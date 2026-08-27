import asyncio
import hashlib
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from navigator.client import Navigator
from navigator.errors import Conflict, CorruptedState, NotFound
from navigator.models import (
    Identity,
    ToolCancellation,
    ToolDefinition,
    ToolEffectClass,
    ToolIdempotencyContract,
    ToolResult,
)


def oid(last: int) -> Identity:
    return Identity(bytes(15) + bytes([last]))


def definition() -> ToolDefinition:
    return ToolDefinition(
        name="document.extract",
        version="v1",
        input_schema={"type": "object", "properties": {"text": {"type": "string"}}},
        output_schema={"type": "object"},
        required_authority="document.read",
        timeout_millis=1_000,
        cancellation=ToolCancellation.COOPERATIVE,
        effect_class=ToolEffectClass.IDEMPOTENT,
        idempotency=ToolIdempotencyContract.INVOCATION_IDENTITY,
    )


def test_tool_definition_canonicalizes_schema_and_rejects_contract_mutants() -> None:
    value = definition()
    assert value.input_schema == b'{"properties":{"text":{"type":"string"}},"type":"object"}'
    assert (
        ToolDefinition(**{**value.model_dump(), "name": "Records.Lookup", "version": "V1"}).name
        == "Records.Lookup"
    )
    with pytest.raises((ValidationError, ValueError)):
        ToolDefinition(**{**value.model_dump(), "input_schema": []})
    with pytest.raises((ValidationError, ValueError)):
        ToolDefinition(**{**value.model_dump(), "name": "Tool:unsafe"})
    with pytest.raises((ValidationError, ValueError)):
        ToolDefinition(**{**value.model_dump(), "input_schema": {"minimum": 1}})
    with pytest.raises((ValidationError, ValueError)):
        ToolDefinition(
            **{
                **value.model_dump(),
                "idempotency": ToolIdempotencyContract.NEVER_REPLAY,
            }
        )


@pytest.mark.asyncio
async def test_register_tool_translates_exact_typed_contract() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def RegisterTool(self, request: object) -> object:
            assert request.tool.input_schema == definition().input_schema
            assert request.tool.timeout_millis == 1_000
            return pb.RegisterToolResponse(
                registration=pb.ToolRegistrationSnapshot(
                    registration_id=bytes(oid(3)),
                    session_id=request.session_id,
                    request_id=request.request_id,
                    tool=request.tool,
                    revision=1,
                    active=True,
                    created_at=pb.Timestamp(unix_seconds=1),
                    updated_at=pb.Timestamp(unix_seconds=2),
                )
            )

    registration = await Navigator(Stub(), pb.RequestMetadata()).tools.register(
        request_id=oid(1), session_id=oid(2), definition=definition()
    )
    assert registration.id == oid(3) and registration.definition == definition()


@pytest.mark.asyncio
async def test_provider_waits_for_durable_started_ack_before_handler() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    handler_called = asyncio.Event()
    terminal_seen = asyncio.Event()

    async def handler(invocation: object) -> ToolResult:
        handler_called.set()
        return ToolResult(output={"ok": True})

    class Stub:
        async def _responses(self, requests: object) -> object:
            iterator = requests.__aiter__()
            connect = await iterator.__anext__()
            yield pb.ToolProviderResponse(
                connected=pb.ToolProviderConnected(
                    session_id=bytes(oid(1)),
                    provider_id=bytes(oid(2)),
                    connection_id=connect.connect.connection_id,
                    accepted_after_server_sequence=0,
                    next_server_sequence=8,
                    high_water_server_sequence=7,
                )
            )
            yield pb.ToolProviderResponse(
                invocation=pb.ToolInvocation(
                    session_id=bytes(oid(1)),
                    registration_id=bytes(oid(3)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    operation_id=bytes(oid(6)),
                    participant_id=bytes(oid(7)),
                    server_sequence=7,
                    tool_name="document.extract",
                    tool_version="v1",
                    input=b'{"text":"x"}',
                    deadline=pb.Timestamp(unix_seconds=4_000_000_000),
                )
            )
            started = await iterator.__anext__()
            assert started.WhichOneof("frame") == "started"
            assert not handler_called.is_set()
            yield pb.ToolProviderResponse(
                acknowledgement=pb.ToolProviderAck(
                    session_id=bytes(oid(1)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    server_sequence=7,
                    kind=pb.TOOL_PROVIDER_ACK_KIND_STARTED,
                )
            )
            terminal = await asyncio.wait_for(iterator.__anext__(), 1)
            assert terminal.WhichOneof("frame") == "result"
            assert terminal.result.output == b'{"ok":true}'
            terminal_seen.set()
            await asyncio.Event().wait()

        def ProvideTools(self, requests: object) -> object:
            return self._responses(requests)

    task = asyncio.create_task(
        Navigator(Stub(), pb.RequestMetadata()).tools.provide(
            session_id=oid(1), provider_id=oid(2), handlers={oid(3): handler}
        )
    )
    await asyncio.wait_for(terminal_seen.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_provider_reconnect_during_handler_does_not_execute_effect_twice() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    release = asyncio.Event()
    terminal_seen = asyncio.Event()
    calls = 0

    def invocation() -> object:
        return pb.ToolInvocation(
            session_id=bytes(oid(1)),
            registration_id=bytes(oid(3)),
            invocation_id=bytes(oid(4)),
            dispatch_id=bytes(oid(5)),
            operation_id=bytes(oid(6)),
            participant_id=bytes(oid(7)),
            server_sequence=7,
            tool_name="document.extract",
            tool_version="v1",
            input=b"{}",
            deadline=pb.Timestamp(unix_seconds=4_000_000_000),
        )

    async def handler(value: object) -> ToolResult:
        nonlocal calls
        calls += 1
        await release.wait()
        return ToolResult(output={"once": calls})

    class Stub:
        connections = 0

        async def _responses(self, requests: object) -> object:
            self.connections += 1
            iterator = requests.__aiter__()
            connect = await iterator.__anext__()
            yield pb.ToolProviderResponse(
                connected=pb.ToolProviderConnected(
                    session_id=bytes(oid(1)),
                    provider_id=bytes(oid(2)),
                    connection_id=connect.connect.connection_id,
                    accepted_after_server_sequence=connect.connect.after_server_sequence,
                    next_server_sequence=8,
                    high_water_server_sequence=7,
                )
            )
            yield pb.ToolProviderResponse(invocation=invocation())
            if self.connections == 1:
                started = await iterator.__anext__()
                assert started.WhichOneof("frame") == "started"
                yield pb.ToolProviderResponse(
                    acknowledgement=pb.ToolProviderAck(
                        session_id=bytes(oid(1)),
                        invocation_id=bytes(oid(4)),
                        dispatch_id=bytes(oid(5)),
                        server_sequence=7,
                        kind=pb.TOOL_PROVIDER_ACK_KIND_STARTED,
                    )
                )
                await asyncio.sleep(0)
                return
            release.set()
            replay_started = await asyncio.wait_for(iterator.__anext__(), 1)
            assert replay_started.WhichOneof("frame") == "started"
            yield pb.ToolProviderResponse(
                acknowledgement=pb.ToolProviderAck(
                    session_id=bytes(oid(1)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    server_sequence=7,
                    kind=pb.TOOL_PROVIDER_ACK_KIND_STARTED,
                    duplicate=True,
                )
            )
            terminal = await asyncio.wait_for(iterator.__anext__(), 1)
            assert terminal.WhichOneof("frame") == "result"
            assert terminal.result.output == b'{"once":1}'
            terminal_seen.set()
            await asyncio.Event().wait()

        def ProvideTools(self, requests: object) -> object:
            return self._responses(requests)

    task = asyncio.create_task(
        Navigator(Stub(), pb.RequestMetadata()).tools.provide(
            session_id=oid(1), provider_id=oid(2), handlers={oid(3): handler}, reconnect_delay=0
        )
    )
    await asyncio.wait_for(terminal_seen.wait(), 1)
    assert calls == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_provider_divergent_duplicate_sequence_fails_closed_before_handler() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    called = False

    async def handler(value: object) -> ToolResult:
        nonlocal called
        called = True
        return ToolResult(output={})

    def frame(content: bytes, sequence: int = 1) -> object:
        return pb.ToolInvocation(
            session_id=bytes(oid(1)),
            registration_id=bytes(oid(3)),
            invocation_id=bytes(oid(4)),
            dispatch_id=bytes(oid(5)),
            operation_id=bytes(oid(6)),
            participant_id=bytes(oid(7)),
            server_sequence=sequence,
            tool_name="document.extract",
            tool_version="v1",
            input=content,
            deadline=pb.Timestamp(unix_seconds=4_000_000_000),
        )

    class Stub:
        async def _responses(self, requests: object) -> object:
            iterator = requests.__aiter__()
            connect = await iterator.__anext__()
            yield pb.ToolProviderResponse(
                connected=pb.ToolProviderConnected(
                    session_id=bytes(oid(1)),
                    provider_id=bytes(oid(2)),
                    connection_id=connect.connect.connection_id,
                    accepted_after_server_sequence=0,
                    next_server_sequence=3,
                    high_water_server_sequence=2,
                )
            )
            yield pb.ToolProviderResponse(invocation=frame(b'{"value":1}'))
            assert (await iterator.__anext__()).WhichOneof("frame") == "started"
            yield pb.ToolProviderResponse(invocation=frame(b'{"value":2}', 2))

        def ProvideTools(self, requests: object) -> object:
            return self._responses(requests)

    with pytest.raises(Conflict):
        await Navigator(Stub(), pb.RequestMetadata()).tools.provide(
            session_id=oid(1), provider_id=oid(2), handlers={oid(3): handler}
        )
    assert not called


@pytest.mark.asyncio
async def test_provider_rejects_cross_session_started_ack_before_handler() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    called = False

    async def handler(value: object) -> ToolResult:
        nonlocal called
        called = True
        return ToolResult(output={})

    class Stub:
        async def _responses(self, requests: object) -> object:
            iterator = requests.__aiter__()
            connect = await iterator.__anext__()
            yield pb.ToolProviderResponse(
                connected=pb.ToolProviderConnected(
                    session_id=bytes(oid(1)),
                    provider_id=bytes(oid(2)),
                    connection_id=connect.connect.connection_id,
                    accepted_after_server_sequence=0,
                    next_server_sequence=2,
                    high_water_server_sequence=1,
                )
            )
            yield pb.ToolProviderResponse(
                invocation=pb.ToolInvocation(
                    session_id=bytes(oid(1)),
                    registration_id=bytes(oid(3)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    operation_id=bytes(oid(6)),
                    participant_id=bytes(oid(7)),
                    server_sequence=1,
                    tool_name="document.extract",
                    tool_version="v1",
                    input=b"{}",
                    deadline=pb.Timestamp(unix_seconds=4_000_000_000),
                )
            )
            await iterator.__anext__()
            yield pb.ToolProviderResponse(
                acknowledgement=pb.ToolProviderAck(
                    session_id=bytes(oid(9)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    server_sequence=1,
                    kind=pb.TOOL_PROVIDER_ACK_KIND_STARTED,
                )
            )

        def ProvideTools(self, requests: object) -> object:
            return self._responses(requests)

    with pytest.raises(Conflict):
        await Navigator(Stub(), pb.RequestMetadata()).tools.provide(
            session_id=oid(1), provider_id=oid(2), handlers={oid(3): handler}
        )
    assert not called


@pytest.mark.asyncio
async def test_provider_rejects_invalid_and_unverifiable_watermarks() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    async def handler(value: object) -> ToolResult:
        return ToolResult(output={})

    with pytest.raises(ValueError):
        await Navigator(object(), pb.RequestMetadata()).tools.provide(
            session_id=oid(1),
            provider_id=oid(2),
            handlers={oid(3): handler},
            after_server_sequence=-1,
        )

    class Stub:
        async def _responses(self, requests: object) -> object:
            iterator = requests.__aiter__()
            connect = await iterator.__anext__()
            yield pb.ToolProviderResponse(
                connected=pb.ToolProviderConnected(
                    session_id=bytes(oid(1)),
                    provider_id=bytes(oid(2)),
                    connection_id=connect.connect.connection_id,
                    accepted_after_server_sequence=5,
                    next_server_sequence=6,
                    high_water_server_sequence=5,
                )
            )
            # The SDK has no exact bytes for sequence 5 in this process. It must not
            # accept an unverifiable replay merely because the numeric watermark matches.
            yield pb.ToolProviderResponse(
                invocation=pb.ToolInvocation(
                    session_id=bytes(oid(1)),
                    registration_id=bytes(oid(3)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    operation_id=bytes(oid(6)),
                    participant_id=bytes(oid(7)),
                    server_sequence=5,
                    tool_name="document.extract",
                    tool_version="v1",
                    input=b"{}",
                    deadline=pb.Timestamp(unix_seconds=4_000_000_000),
                )
            )

        def ProvideTools(self, requests: object) -> object:
            return self._responses(requests)

    with pytest.raises(Conflict):
        await Navigator(Stub(), pb.RequestMetadata()).tools.provide(
            session_id=oid(1),
            provider_id=oid(2),
            handlers={oid(3): handler},
            after_server_sequence=5,
        )

    def invalid_connected_stub(next_sequence: int, high_water: int) -> object:
        class InvalidConnectedStub:
            async def _responses(self, requests: object) -> object:
                iterator = requests.__aiter__()
                connect = await iterator.__anext__()
                yield pb.ToolProviderResponse(
                    connected=pb.ToolProviderConnected(
                        session_id=bytes(oid(1)),
                        provider_id=bytes(oid(2)),
                        connection_id=connect.connect.connection_id,
                        accepted_after_server_sequence=5,
                        next_server_sequence=next_sequence,
                        high_water_server_sequence=high_water,
                    )
                )

            def ProvideTools(self, requests: object) -> object:
                return self._responses(requests)

        return InvalidConnectedStub()

    for next_sequence, high_water in [(5, 5), (7, 5), (6, 4)]:
        with pytest.raises(Conflict):
            await Navigator(
                invalid_connected_stub(next_sequence, high_water), pb.RequestMetadata()
            ).tools.provide(
                session_id=oid(1),
                provider_id=oid(2),
                handlers={oid(3): handler},
                after_server_sequence=5,
            )


@pytest.mark.asyncio
async def test_provider_cooperative_cancel_cancels_handler_and_returns_typed_failure() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    entered = asyncio.Event()
    terminal_seen = asyncio.Event()

    async def handler(value: object) -> ToolResult:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    class Stub:
        async def _responses(self, requests: object) -> object:
            iterator = requests.__aiter__()
            connect = await iterator.__anext__()
            yield pb.ToolProviderResponse(
                connected=pb.ToolProviderConnected(
                    session_id=bytes(oid(1)),
                    provider_id=bytes(oid(2)),
                    connection_id=connect.connect.connection_id,
                    accepted_after_server_sequence=0,
                    next_server_sequence=3,
                    high_water_server_sequence=2,
                )
            )
            yield pb.ToolProviderResponse(
                invocation=pb.ToolInvocation(
                    session_id=bytes(oid(1)),
                    registration_id=bytes(oid(3)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    operation_id=bytes(oid(6)),
                    participant_id=bytes(oid(7)),
                    server_sequence=1,
                    tool_name="document.extract",
                    tool_version="v1",
                    input=b"{}",
                    deadline=pb.Timestamp(unix_seconds=4_000_000_000),
                )
            )
            await iterator.__anext__()
            yield pb.ToolProviderResponse(
                acknowledgement=pb.ToolProviderAck(
                    session_id=bytes(oid(1)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    server_sequence=1,
                    kind=pb.TOOL_PROVIDER_ACK_KIND_STARTED,
                )
            )
            await entered.wait()
            yield pb.ToolProviderResponse(
                cancellation=pb.ToolInvocationCancel(
                    session_id=bytes(oid(1)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    server_sequence=2,
                    cancellation_id=bytes(oid(8)),
                    requested_at=pb.Timestamp(unix_seconds=2),
                )
            )
            terminal = await asyncio.wait_for(iterator.__anext__(), 1)
            assert terminal.WhichOneof("frame") == "failure"
            assert terminal.failure.failure.code == pb.FAILURE_CODE_CANCELLED
            terminal_seen.set()
            await asyncio.Event().wait()

        def ProvideTools(self, requests: object) -> object:
            return self._responses(requests)

    task = asyncio.create_task(
        Navigator(Stub(), pb.RequestMetadata()).tools.provide(
            session_id=oid(1), provider_id=oid(2), handlers={oid(3): handler}
        )
    )
    await asyncio.wait_for(terminal_seen.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_lost_terminal_ack_reconnect_replays_exact_terminal_without_handler_reentry() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    calls = 0
    replayed = asyncio.Event()

    async def handler(value: object) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(output={"receipt": "stable"})

    class Stub:
        connections = 0

        async def _responses(self, requests: object) -> object:
            self.connections += 1
            iterator = requests.__aiter__()
            connect = await iterator.__anext__()
            yield pb.ToolProviderResponse(
                connected=pb.ToolProviderConnected(
                    session_id=bytes(oid(1)),
                    provider_id=bytes(oid(2)),
                    connection_id=connect.connect.connection_id,
                    accepted_after_server_sequence=connect.connect.after_server_sequence,
                    next_server_sequence=2,
                    high_water_server_sequence=1,
                )
            )
            yield pb.ToolProviderResponse(
                invocation=pb.ToolInvocation(
                    session_id=bytes(oid(1)),
                    registration_id=bytes(oid(3)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    operation_id=bytes(oid(6)),
                    participant_id=bytes(oid(7)),
                    server_sequence=1,
                    tool_name="document.extract",
                    tool_version="v1",
                    input=b"{}",
                    deadline=pb.Timestamp(unix_seconds=4_000_000_000),
                )
            )
            if self.connections == 1:
                await iterator.__anext__()
                yield pb.ToolProviderResponse(
                    acknowledgement=pb.ToolProviderAck(
                        session_id=bytes(oid(1)),
                        invocation_id=bytes(oid(4)),
                        dispatch_id=bytes(oid(5)),
                        server_sequence=1,
                        kind=pb.TOOL_PROVIDER_ACK_KIND_STARTED,
                    )
                )
                first_terminal = await asyncio.wait_for(iterator.__anext__(), 1)
                assert first_terminal.result.output == b'{"receipt":"stable"}'
                return  # terminal ACK is deliberately lost
            replay_started = await asyncio.wait_for(iterator.__anext__(), 1)
            assert replay_started.WhichOneof("frame") == "started"
            yield pb.ToolProviderResponse(
                acknowledgement=pb.ToolProviderAck(
                    session_id=bytes(oid(1)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    server_sequence=1,
                    kind=pb.TOOL_PROVIDER_ACK_KIND_STARTED,
                    duplicate=True,
                )
            )
            replay = await asyncio.wait_for(iterator.__anext__(), 1)
            assert replay.result.output == b'{"receipt":"stable"}'
            assert replay.result.connection_id == connect.connect.connection_id
            replayed.set()
            yield pb.ToolProviderResponse(
                acknowledgement=pb.ToolProviderAck(
                    session_id=bytes(oid(1)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    server_sequence=1,
                    kind=pb.TOOL_PROVIDER_ACK_KIND_TERMINAL,
                )
            )
            await asyncio.Event().wait()

        def ProvideTools(self, requests: object) -> object:
            return self._responses(requests)

    task = asyncio.create_task(
        Navigator(Stub(), pb.RequestMetadata()).tools.provide(
            session_id=oid(1), provider_id=oid(2), handlers={oid(3): handler}, reconnect_delay=0
        )
    )
    await asyncio.wait_for(replayed.wait(), 1)
    assert calls == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_cancel_before_started_ack_never_enters_handler_and_divergence_fails_closed() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    called = False

    async def handler(value: object) -> ToolResult:
        nonlocal called
        called = True
        return ToolResult(output={})

    invocation = pb.ToolInvocation(
        session_id=bytes(oid(1)),
        registration_id=bytes(oid(3)),
        invocation_id=bytes(oid(4)),
        dispatch_id=bytes(oid(5)),
        operation_id=bytes(oid(6)),
        participant_id=bytes(oid(7)),
        server_sequence=1,
        tool_name="document.extract",
        tool_version="v1",
        input=b"{}",
        deadline=pb.Timestamp(unix_seconds=4_000_000_000),
    )

    class Stub:
        async def _responses(self, requests: object) -> object:
            iterator = requests.__aiter__()
            connect = await iterator.__anext__()
            yield pb.ToolProviderResponse(
                connected=pb.ToolProviderConnected(
                    session_id=bytes(oid(1)),
                    provider_id=bytes(oid(2)),
                    connection_id=connect.connect.connection_id,
                    accepted_after_server_sequence=0,
                    next_server_sequence=4,
                    high_water_server_sequence=3,
                )
            )
            yield pb.ToolProviderResponse(invocation=invocation)
            assert (await iterator.__anext__()).WhichOneof("frame") == "started"
            cancel = pb.ToolInvocationCancel(
                session_id=bytes(oid(1)),
                invocation_id=bytes(oid(4)),
                dispatch_id=bytes(oid(5)),
                server_sequence=2,
                cancellation_id=bytes(oid(8)),
                requested_at=pb.Timestamp(unix_seconds=2),
            )
            yield pb.ToolProviderResponse(cancellation=cancel)
            terminal = await iterator.__anext__()
            assert terminal.WhichOneof("frame") == "failure"
            yield pb.ToolProviderResponse(
                acknowledgement=pb.ToolProviderAck(
                    session_id=bytes(oid(1)),
                    invocation_id=bytes(oid(4)),
                    dispatch_id=bytes(oid(5)),
                    server_sequence=1,
                    kind=pb.TOOL_PROVIDER_ACK_KIND_STARTED,
                )
            )
            await asyncio.sleep(0)
            divergent = pb.ToolInvocationCancel()
            divergent.CopyFrom(cancel)
            divergent.server_sequence = 3
            divergent.cancellation_id = bytes(oid(9))
            yield pb.ToolProviderResponse(cancellation=divergent)

        def ProvideTools(self, requests: object) -> object:
            return self._responses(requests)

    with pytest.raises(Conflict):
        await Navigator(Stub(), pb.RequestMetadata()).tools.provide(
            session_id=oid(1), provider_id=oid(2), handlers={oid(3): handler}
        )
    assert not called


def artifact_wire(pb: object, content: bytes) -> object:
    return pb.ArtifactSnapshot(
        artifact_id=bytes(oid(2)),
        session_id=bytes(oid(1)),
        media_type="text/plain",
        size=len(content),
        sha256=hashlib.sha256(content).digest(),
        status=pb.ARTIFACT_STATUS_AVAILABLE,
        retain_until=pb.Timestamp(unix_seconds=10),
        created_at=pb.Timestamp(unix_seconds=1),
        updated_at=pb.Timestamp(unix_seconds=1),
        revision=1,
        creator_participant_id=bytes(oid(3)),
        creator_operation_id=bytes(oid(4)),
    )


@pytest.mark.asyncio
async def test_artifact_write_streams_and_read_verifies_integrity() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    content = b"bounded artifact"

    class Stub:
        async def WriteArtifact(self, requests: object) -> object:
            frames = [frame async for frame in requests]
            assert frames[0].WhichOneof("frame") == "begin"
            assert b"".join(frame.chunk.content for frame in frames[1:]) == content
            return pb.WriteArtifactResponse(artifact=artifact_wire(pb, content))

        async def _read(self) -> object:
            yield pb.ReadArtifactResponse(
                header=pb.ArtifactReadHeader(
                    artifact=artifact_wire(pb, content), range_offset=0, range_length=len(content)
                )
            )
            yield pb.ReadArtifactResponse(
                chunk=pb.ArtifactChunk(artifact_id=bytes(oid(2)), offset=0, content=content)
            )

        def ReadArtifact(self, request: object) -> object:
            return self._read()

    artifacts = Navigator(Stub(), pb.RequestMetadata()).artifacts
    snapshot = await artifacts.write(
        request_id=oid(8),
        session_id=oid(1),
        artifact_id=oid(2),
        media_type="text/plain",
        content=content,
        retain_until=datetime.fromtimestamp(10, tz=timezone.utc),
        authority_grant_id=oid(5),
        creator_participant_id=oid(3),
        creator_operation_id=oid(4),
    )
    assert snapshot.sha256 == hashlib.sha256(content).digest()
    assert (
        await artifacts.read(session_id=oid(1), artifact_id=oid(2), authority_grant_id=oid(5))
        == content
    )


@pytest.mark.asyncio
async def test_artifact_partial_bytes_are_discarded_on_terminal_failure_and_corruption() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    content = b"secret partial"

    class FailureStub:
        async def _read(self) -> object:
            yield pb.ReadArtifactResponse(
                header=pb.ArtifactReadHeader(
                    artifact=artifact_wire(pb, content), range_offset=0, range_length=len(content)
                )
            )
            yield pb.ReadArtifactResponse(
                chunk=pb.ArtifactChunk(artifact_id=bytes(oid(2)), offset=0, content=content[:3])
            )
            yield pb.ReadArtifactResponse(
                failure=pb.Failure(
                    code=pb.FAILURE_CODE_NOT_FOUND, message="removed", retry=pb.RETRY_CLASS_NEVER
                )
            )

        def ReadArtifact(self, request: object) -> object:
            return self._read()

    with pytest.raises(NotFound):
        await Navigator(FailureStub(), pb.RequestMetadata()).artifacts.read(
            session_id=oid(1), artifact_id=oid(2), authority_grant_id=oid(5)
        )

    class CorruptStub(FailureStub):
        async def _read(self) -> object:
            yield pb.ReadArtifactResponse(
                header=pb.ArtifactReadHeader(
                    artifact=artifact_wire(pb, content), range_offset=0, range_length=len(content)
                )
            )
            yield pb.ReadArtifactResponse(
                chunk=pb.ArtifactChunk(
                    artifact_id=bytes(oid(2)), offset=0, content=b"x" * len(content)
                )
            )

    with pytest.raises(CorruptedState):
        await Navigator(CorruptStub(), pb.RequestMetadata()).artifacts.read(
            session_id=oid(1), artifact_id=oid(2), authority_grant_id=oid(5)
        )

    oversized = b"x" * (64 * 1024 + 1)

    class OversizedChunkStub(FailureStub):
        async def _read(self) -> object:
            yield pb.ReadArtifactResponse(
                header=pb.ArtifactReadHeader(
                    artifact=artifact_wire(pb, oversized),
                    range_offset=0,
                    range_length=len(oversized),
                )
            )
            yield pb.ReadArtifactResponse(
                chunk=pb.ArtifactChunk(
                    artifact_id=bytes(oid(2)),
                    offset=0,
                    content=oversized,
                )
            )

    with pytest.raises(CorruptedState):
        await Navigator(OversizedChunkStub(), pb.RequestMetadata()).artifacts.read(
            session_id=oid(1), artifact_id=oid(2), authority_grant_id=oid(5)
        )


@pytest.mark.asyncio
async def test_artifact_snapshot_and_delete_preserve_request_authority_and_state() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    content = b"artifact"

    class Stub:
        async def ArtifactSnapshot(self, request: object) -> object:
            assert request.session_id == bytes(oid(1)) and request.artifact_id == bytes(oid(2))
            return pb.ArtifactSnapshotResponse(artifact=artifact_wire(pb, content))

        async def DeleteArtifact(self, request: object) -> object:
            assert request.request_id == bytes(oid(8))
            assert request.authority_grant_id == bytes(oid(5))
            value = artifact_wire(pb, content)
            value.status = pb.ARTIFACT_STATUS_LOGICALLY_DELETED
            value.revision = 2
            return pb.DeleteArtifactResponse(artifact=value)

    artifacts = Navigator(Stub(), pb.RequestMetadata()).artifacts
    snapshot = await artifacts.snapshot(session_id=oid(1), artifact_id=oid(2))
    deleted = await artifacts.delete(
        request_id=oid(8), session_id=oid(1), artifact_id=oid(2), authority_grant_id=oid(5)
    )
    assert snapshot.status.value == pb.ARTIFACT_STATUS_AVAILABLE
    assert deleted.status.value == pb.ARTIFACT_STATUS_LOGICALLY_DELETED
    assert deleted.revision == 2


@pytest.mark.asyncio
async def test_artifact_alien_snapshots_and_contradictory_range_fail_closed() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    content = b"artifact"

    class Stub:
        async def ArtifactSnapshot(self, request: object) -> object:
            value = artifact_wire(pb, content)
            value.artifact_id = bytes(oid(9))
            return pb.ArtifactSnapshotResponse(artifact=value)

        async def DeleteArtifact(self, request: object) -> object:
            return pb.DeleteArtifactResponse(artifact=artifact_wire(pb, content))

        async def _read(self) -> object:
            yield pb.ReadArtifactResponse(
                header=pb.ArtifactReadHeader(
                    artifact=artifact_wire(pb, content), range_offset=0, range_length=1
                )
            )

        def ReadArtifact(self, request: object) -> object:
            return self._read()

    artifacts = Navigator(Stub(), pb.RequestMetadata()).artifacts
    with pytest.raises(CorruptedState):
        await artifacts.snapshot(session_id=oid(1), artifact_id=oid(2))
    with pytest.raises(CorruptedState):
        await artifacts.delete(
            request_id=oid(8), session_id=oid(1), artifact_id=oid(2), authority_grant_id=oid(5)
        )
    with pytest.raises(CorruptedState):
        await artifacts.read(
            session_id=oid(1), artifact_id=oid(2), authority_grant_id=oid(5), length=4
        )
