from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from datetime import datetime, timezone
from typing import Any, cast

import grpc

from .errors import Conflict, NavigatorError, from_failure
from .models import (
    ArtifactRef,
    Identity,
    RetryClass,
    ToolDefinition,
    ToolFailure,
    ToolInvocation,
    ToolRegistration,
    ToolResult,
    timestamp,
)

ToolHandler = Callable[[ToolInvocation], Awaitable[ToolResult]]
_QUEUE_LIMIT = 32
_REPLAY_WINDOW = 64


class ToolProvider:
    """A reconnectable provider whose durable replay state survives stream closure."""

    def __init__(
        self,
        tools: Tools,
        *,
        session_id: Identity,
        provider_id: Identity,
        handlers: Mapping[Identity, ToolHandler],
        after_server_sequence: int,
        reconnect_delay: float,
    ) -> None:
        self._tools = tools
        self._session_id = session_id
        self._provider_id = provider_id
        self._handlers = handlers
        self._after_server_sequence = after_server_sequence
        self._reconnect_delay = reconnect_delay
        self._disconnect = asyncio.Event()
        self._drop_terminal_ack = asyncio.Event()
        self._connected = asyncio.Event()
        self._watermark = after_server_sequence
        self._connection_watermarks: list[int] = []

    async def serve(self) -> None:
        await self._tools._provide(
            session_id=self._session_id,
            provider_id=self._provider_id,
            handlers=self._handlers,
            after_server_sequence=self._after_server_sequence,
            reconnect_delay=self._reconnect_delay,
            disconnect=self._disconnect,
            drop_terminal_ack=self._drop_terminal_ack,
            connected=self._connected,
            observe_watermark=self._observe_watermark,
        )

    def _observe_watermark(self, value: int, *, connected: bool = False) -> None:
        self._watermark = value
        if connected:
            self._connection_watermarks.append(value)

    @property
    def watermark(self) -> int:
        return self._watermark

    @property
    def connection_watermarks(self) -> tuple[int, ...]:
        return tuple(self._connection_watermarks)

    def drop_next_terminal_ack(self) -> None:
        """Arm one deterministic transport cut after sending a terminal frame."""
        self._drop_terminal_ack.set()

    async def disconnect(self, *, timeout: float = 5.0) -> None:
        """Close the current real stream while preserving provider replay state."""
        await asyncio.wait_for(self._connected.wait(), timeout)
        self._disconnect.set()

        async def closed() -> None:
            while self._connected.is_set():
                await asyncio.sleep(0)

        await asyncio.wait_for(closed(), timeout)


def _definition(value: Any) -> ToolDefinition:
    return ToolDefinition(
        name=value.name,
        version=value.version,
        input_schema=bytes(value.input_schema),
        output_schema=bytes(value.output_schema),
        required_authority=value.required_authority,
        timeout_millis=value.timeout_millis,
        cancellation=value.cancellation_behavior,
        effect_class=value.effect_class,
        idempotency=value.idempotency_contract,
    )


def _artifact_proto(value: ArtifactRef) -> Any:
    from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

    return pb.ArtifactReference(
        artifact_id=bytes(value.id),
        session_id=bytes(value.session_id),
        media_type=value.media_type,
        size=value.size,
        sha256=value.sha256,
        creator_participant_id=bytes(value.creator_participant_id),
        creator_operation_id=bytes(value.creator_operation_id),
    )


def _now() -> Any:
    from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

    value = datetime.now(timezone.utc)
    return pb.Timestamp(unix_seconds=int(value.timestamp()), nanoseconds=value.microsecond * 1000)


class Tools:
    def __init__(self, navigator: Any) -> None:
        self._navigator = navigator

    async def register(
        self,
        *,
        request_id: Identity,
        session_id: Identity,
        definition: ToolDefinition,
    ) -> ToolRegistration:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        tool = pb.ToolSpecification(
            name=definition.name,
            version=definition.version,
            input_schema=definition.input_schema,
            output_schema=definition.output_schema,
            required_authority=definition.required_authority,
            timeout_millis=definition.timeout_millis,
            cancellation_behavior=cast(Any, int(definition.cancellation)),
            effect_class=cast(Any, int(definition.effect_class)),
            idempotency_contract=cast(Any, int(definition.idempotency)),
        )
        response = await self._navigator._invoke(
            self._navigator._stub.RegisterTool,
            pb.RegisterToolRequest(
                metadata=self._navigator._metadata,
                request_id=bytes(request_id),
                session_id=bytes(session_id),
                tool=tool,
            ),
        )
        value = self._navigator._outcome(response, "registration")
        return ToolRegistration(
            id=Identity(value.registration_id),
            session_id=Identity(value.session_id),
            request_id=Identity(value.request_id),
            definition=_definition(value.tool),
            revision=value.revision,
            created_at=timestamp(value.created_at.unix_seconds, value.created_at.nanoseconds),
            updated_at=timestamp(value.updated_at.unix_seconds, value.updated_at.nanoseconds),
            active=value.active,
        )

    async def provide(
        self,
        *,
        session_id: Identity,
        provider_id: Identity,
        handlers: Mapping[Identity, ToolHandler],
        after_server_sequence: int = 0,
        reconnect_delay: float = 0.1,
    ) -> None:
        """Serve a closed registration catalog until cancelled.

        Reconnection retains the durable server watermark and exact terminal frames.
        Handler code never starts before Navigator acknowledges HandlerStarted.
        """
        await self._provide(
            session_id=session_id,
            provider_id=provider_id,
            handlers=handlers,
            after_server_sequence=after_server_sequence,
            reconnect_delay=reconnect_delay,
        )

    def provider(
        self,
        *,
        session_id: Identity,
        provider_id: Identity,
        handlers: Mapping[Identity, ToolHandler],
        after_server_sequence: int = 0,
        reconnect_delay: float = 0.1,
    ) -> ToolProvider:
        """Create a stateful provider handle for controlled transport reconnects."""
        if not handlers or len(handlers) > _QUEUE_LIMIT or after_server_sequence < 0:
            raise ValueError("provider catalog or watermark violates bounds")
        return ToolProvider(
            self,
            session_id=session_id,
            provider_id=provider_id,
            handlers=dict(handlers),
            after_server_sequence=after_server_sequence,
            reconnect_delay=reconnect_delay,
        )

    async def _provide(
        self,
        *,
        session_id: Identity,
        provider_id: Identity,
        handlers: Mapping[Identity, ToolHandler],
        after_server_sequence: int,
        reconnect_delay: float,
        disconnect: asyncio.Event | None = None,
        drop_terminal_ack: asyncio.Event | None = None,
        connected: asyncio.Event | None = None,
        observe_watermark: Callable[..., None] | None = None,
    ) -> None:
        if not handlers or len(handlers) > _QUEUE_LIMIT or after_server_sequence < 0:
            raise ValueError("provider catalog or watermark violates bounds")
        watermark = after_server_sequence
        terminals: dict[bytes, tuple[ToolInvocation, ToolResult | ToolFailure]] = {}
        tasks: dict[bytes, asyncio.Task[None]] = {}
        invocations: dict[bytes, ToolInvocation] = {}
        cancellations: dict[bytes, bytes] = {}
        cancelled: set[bytes] = set()
        ackable: set[int] = set()
        seen: OrderedDict[int, bytes] = OrderedDict()
        try:
            while True:
                connection_id = Identity(__import__("os").urandom(16))
                try:
                    watermark = await asyncio.create_task(
                        self._connection(
                            session_id,
                            provider_id,
                            connection_id,
                            handlers,
                            watermark,
                            terminals,
                            tasks,
                            invocations,
                            cancellations,
                            cancelled,
                            ackable,
                            seen,
                            disconnect,
                            drop_terminal_ack,
                            connected,
                            observe_watermark,
                        )
                    )
                    await asyncio.sleep(reconnect_delay)
                except grpc.RpcError:
                    await asyncio.sleep(reconnect_delay)
        finally:
            for task in tasks.values():
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks.values(), return_exceptions=True)

    async def _connection(
        self,
        session_id: Identity,
        provider_id: Identity,
        connection_id: Identity,
        handlers: Mapping[Identity, ToolHandler],
        watermark: int,
        terminals: dict[bytes, tuple[ToolInvocation, ToolResult | ToolFailure]],
        tasks: dict[bytes, asyncio.Task[None]],
        invocations: dict[bytes, ToolInvocation],
        cancellations: dict[bytes, bytes],
        cancelled: set[bytes],
        ackable: set[int],
        seen: OrderedDict[int, bytes],
        disconnect: asyncio.Event | None,
        drop_terminal_ack: asyncio.Event | None,
        connected_event: asyncio.Event | None,
        observe_watermark: Callable[..., None] | None,
    ) -> int:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        outgoing: asyncio.Queue[Any | None] = asyncio.Queue(_QUEUE_LIMIT)
        await outgoing.put(
            pb.ToolProviderRequest(
                connect=pb.ConnectToolProvider(
                    metadata=self._navigator._metadata,
                    session_id=bytes(session_id),
                    provider_id=bytes(provider_id),
                    connection_id=bytes(connection_id),
                    after_server_sequence=watermark,
                    registration_ids=[bytes(value) for value in handlers],
                )
            )
        )

        async def requests() -> AsyncIterator[Any]:
            while True:
                item = await outgoing.get()
                if item is None:
                    return
                yield item
                if (
                    drop_terminal_ack is not None
                    and drop_terminal_ack.is_set()
                    and item.WhichOneof("frame") in {"result", "failure"}
                ):
                    drop_terminal_ack.clear()
                    assert disconnect is not None
                    disconnect.set()

        pending: dict[bytes, ToolInvocation] = {}
        relays: dict[bytes, asyncio.Task[None]] = {}

        def advance_watermark() -> None:
            nonlocal watermark
            while watermark + 1 in ackable:
                watermark += 1
                ackable.remove(watermark)

        def terminal_frame(invocation: ToolInvocation, outcome: ToolResult | ToolFailure) -> Any:
            key = bytes(invocation.dispatch_id)
            common: Any = {
                "session_id": bytes(session_id),
                "provider_id": bytes(provider_id),
                "connection_id": bytes(connection_id),
                "invocation_id": bytes(invocation.id),
                "dispatch_id": key,
                "server_sequence": invocation.server_sequence,
            }
            if isinstance(outcome, ToolResult):
                return pb.ToolProviderRequest(
                    result=pb.ToolHandlerResult(
                        **common,
                        output=outcome.output,
                        artifacts=[_artifact_proto(value) for value in outcome.artifacts],
                    )
                )
            return pb.ToolProviderRequest(
                failure=pb.ToolHandlerFailure(
                    **common,
                    failure=pb.Failure(
                        code=cast(Any, outcome.code),
                        message=outcome.message,
                        retry=cast(Any, int(outcome.retry)),
                    ),
                )
            )

        async def execute(invocation: ToolInvocation) -> None:
            key = bytes(invocation.dispatch_id)
            try:
                result = await handlers[invocation.registration_id](invocation)
                for artifact in result.artifacts:
                    if (
                        artifact.session_id != invocation.session_id
                        or artifact.creator_participant_id != invocation.participant_id
                        or artifact.creator_operation_id != invocation.operation_id
                    ):
                        raise ValueError(
                            "Tool result Artifact belongs to another invocation context"
                        )
                outcome: ToolResult | ToolFailure = result
            except asyncio.CancelledError:
                outcome = ToolFailure(
                    code=13, message="Tool handler cancelled", retry=RetryClass.NEVER
                )
            except Exception:
                outcome = ToolFailure(code=8, message="Tool handler failed", retry=RetryClass.NEVER)
            terminals[key] = (invocation, outcome)
            try:
                outgoing.put_nowait(terminal_frame(invocation, outcome))
            except asyncio.QueueFull:
                # The durable outcome remains cached and is sent on reconnect.
                pass

        async def relay_when_complete(key: bytes, task: asyncio.Task[None]) -> None:
            await asyncio.shield(task)
            stored = terminals.get(key)
            if stored is not None:
                await outgoing.put(terminal_frame(*stored))

        disconnect_watcher: asyncio.Task[None] | None = None
        intentional_disconnect = False
        try:
            stream = self._navigator._stub.ProvideTools(requests())
            if disconnect is not None:

                async def cancel_on_disconnect() -> None:
                    nonlocal intentional_disconnect
                    await disconnect.wait()
                    intentional_disconnect = True
                    disconnect.clear()
                    stream.cancel()

                disconnect_watcher = asyncio.create_task(cancel_on_disconnect())
            connected = False
            async for response in stream:
                kind = response.WhichOneof("frame")
                if kind == "failure":
                    raise from_failure(response.failure)
                if kind == "connected" and not connected:
                    value = response.connected
                    if (
                        bytes(value.session_id) != session_id
                        or bytes(value.provider_id) != provider_id
                        or bytes(value.connection_id) != connection_id
                        or value.accepted_after_server_sequence != watermark
                        or value.next_server_sequence <= value.accepted_after_server_sequence
                        or value.high_water_server_sequence < value.accepted_after_server_sequence
                        or value.high_water_server_sequence + 1 != value.next_server_sequence
                    ):
                        raise Conflict(
                            5, "Provider reconnect acknowledgement conflicted", RetryClass.NEVER
                        )
                    connected = True
                    if observe_watermark is not None:
                        observe_watermark(watermark, connected=True)
                    if connected_event is not None:
                        connected_event.set()
                    continue
                if not connected:
                    raise NavigatorError(8, "Provider frame preceded connection", RetryClass.NEVER)
                if kind == "invocation":
                    value = response.invocation
                    raw = value.SerializeToString(deterministic=True)
                    prior = seen.get(value.server_sequence)
                    if prior is not None and prior != raw:
                        raise Conflict(5, "Server sequence replay conflicted", RetryClass.NEVER)
                    if prior is None and value.server_sequence <= watermark:
                        raise Conflict(
                            5,
                            "Server replay fell outside the bounded exact window",
                            RetryClass.NEVER,
                        )
                    seen[value.server_sequence] = raw
                    seen.move_to_end(value.server_sequence)
                    if len(seen) > _REPLAY_WINDOW:
                        seen.popitem(last=False)
                    if bytes(value.session_id) != session_id:
                        raise Conflict(5, "Invocation session conflicted", RetryClass.NEVER)
                    registration_id = Identity(value.registration_id)
                    if registration_id not in handlers:
                        raise Conflict(
                            5, "Invocation was outside the closed handler catalog", RetryClass.NEVER
                        )
                    invocation = ToolInvocation(
                        id=Identity(value.invocation_id),
                        dispatch_id=Identity(value.dispatch_id),
                        registration_id=registration_id,
                        session_id=Identity(value.session_id),
                        operation_id=Identity(value.operation_id),
                        participant_id=Identity(value.participant_id),
                        server_sequence=value.server_sequence,
                        tool_name=value.tool_name,
                        tool_version=value.tool_version,
                        input=bytes(value.input),
                        deadline=timestamp(value.deadline.unix_seconds, value.deadline.nanoseconds),
                    )
                    key = bytes(invocation.dispatch_id)
                    canonical = invocations.get(key)
                    if canonical is not None and canonical != invocation:
                        raise Conflict(5, "Dispatch replay conflicted", RetryClass.NEVER)
                    if key not in terminals and key not in tasks:
                        if len(set(pending) | set(tasks) | set(terminals)) >= _QUEUE_LIMIT:
                            raise NavigatorError(
                                11, "Provider invocation capacity exceeded", RetryClass.SAFE
                            )
                        prior_invocation = pending.get(key)
                        if prior_invocation is not None and prior_invocation != invocation:
                            raise Conflict(5, "Dispatch replay conflicted", RetryClass.NEVER)
                        invocations[key] = invocation
                    pending[key] = invocation
                    await outgoing.put(
                        pb.ToolProviderRequest(
                            started=pb.ToolHandlerStarted(
                                session_id=bytes(session_id),
                                provider_id=bytes(provider_id),
                                connection_id=bytes(connection_id),
                                invocation_id=bytes(invocation.id),
                                dispatch_id=key,
                                server_sequence=invocation.server_sequence,
                                started_at=_now(),
                            )
                        )
                    )
                elif kind == "acknowledgement":
                    ack = response.acknowledgement
                    key = bytes(ack.dispatch_id)
                    if ack.kind == pb.TOOL_PROVIDER_ACK_KIND_STARTED:
                        pending_invocation = pending.get(key)
                        if (
                            pending_invocation is None
                            or bytes(ack.session_id) != session_id
                            or bytes(ack.invocation_id) != pending_invocation.id
                            or ack.server_sequence != pending_invocation.server_sequence
                        ):
                            raise Conflict(
                                5, "Started acknowledgement conflicted", RetryClass.NEVER
                            )
                        if key in terminals:
                            await outgoing.put(terminal_frame(*terminals[key]))
                        elif key in tasks:
                            if key not in relays:
                                relays[key] = asyncio.create_task(
                                    relay_when_complete(key, tasks[key])
                                )
                        elif key not in cancelled:
                            tasks[key] = asyncio.create_task(execute(pending_invocation))
                    elif ack.kind == pb.TOOL_PROVIDER_ACK_KIND_TERMINAL:
                        terminal = terminals.get(key)
                        if (
                            terminal is None
                            or bytes(ack.session_id) != session_id
                            or bytes(ack.invocation_id) != terminal[0].id
                            or ack.server_sequence != terminal[0].server_sequence
                        ):
                            raise Conflict(
                                5, "Terminal acknowledgement had no terminal", RetryClass.NEVER
                            )
                        terminals.pop(key, None)
                        pending.pop(key, None)
                        tasks.pop(key, None)
                        invocations.pop(key, None)
                        cancelled.discard(key)
                        cancellations.pop(key, None)
                        relay = relays.pop(key, None)
                        if relay is not None and not relay.done():
                            relay.cancel()
                        if ack.server_sequence > watermark:
                            ackable.add(ack.server_sequence)
                        advance_watermark()
                        if observe_watermark is not None:
                            observe_watermark(watermark)
                    else:
                        raise NavigatorError(
                            8, "Unknown provider acknowledgement", RetryClass.NEVER
                        )
                elif kind == "cancellation":
                    cancellation = response.cancellation
                    raw = cancellation.SerializeToString(deterministic=True)
                    key = bytes(cancellation.dispatch_id)
                    canonical_cancellation = cancellations.get(key)
                    if canonical_cancellation is not None and canonical_cancellation != raw:
                        raise Conflict(5, "Cancellation replay conflicted", RetryClass.NEVER)
                    prior = seen.get(cancellation.server_sequence)
                    if prior is not None and prior != raw:
                        raise Conflict(5, "Server sequence replay conflicted", RetryClass.NEVER)
                    if prior is None and cancellation.server_sequence <= watermark:
                        raise Conflict(
                            5,
                            "Server replay fell outside the bounded exact window",
                            RetryClass.NEVER,
                        )
                    seen[cancellation.server_sequence] = raw
                    seen.move_to_end(cancellation.server_sequence)
                    if len(seen) > _REPLAY_WINDOW:
                        seen.popitem(last=False)
                    known = pending.get(key)
                    if known is None and key in terminals:
                        known = terminals[key][0]
                    if (
                        known is None
                        or bytes(cancellation.session_id) != session_id
                        or bytes(cancellation.invocation_id) != known.id
                    ):
                        raise Conflict(5, "Cancellation correlation conflicted", RetryClass.NEVER)
                    cancellations[key] = raw
                    cancelled.add(key)
                    if known.server_sequence > watermark:
                        ackable.add(known.server_sequence)
                    if cancellation.server_sequence > watermark:
                        ackable.add(cancellation.server_sequence)
                    advance_watermark()
                    if observe_watermark is not None:
                        observe_watermark(watermark)
                    task = tasks.get(key)
                    if task is not None:
                        task.cancel()
                    elif key not in terminals:
                        outcome = ToolFailure(
                            code=13, message="Tool handler cancelled", retry=RetryClass.NEVER
                        )
                        terminals[key] = (known, outcome)
                        await outgoing.put(terminal_frame(known, outcome))
                else:
                    raise NavigatorError(8, "Malformed provider frame", RetryClass.NEVER)
        except asyncio.CancelledError:
            if not intentional_disconnect:
                raise
            current = asyncio.current_task()
            if current is not None:
                current.uncancel()
        finally:
            if disconnect_watcher is not None and not disconnect_watcher.done():
                disconnect_watcher.cancel()
            if disconnect_watcher is not None:
                await asyncio.gather(disconnect_watcher, return_exceptions=True)
            if connected_event is not None:
                connected_event.clear()
            await outgoing.put(None)
            for relay in relays.values():
                if not relay.done():
                    relay.cancel()
            if relays:
                await asyncio.gather(*relays.values(), return_exceptions=True)
        return watermark
