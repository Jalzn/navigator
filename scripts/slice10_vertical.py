"""Authoritative installed-wheel Slice 10 vertical demonstration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import grpc
from navigator import (
    AuthorityProfile,
    AuthorityRule,
    CapabilityRequirement,
    CorruptedState,
    Identity,
    Navigator,
    NotFound,
    ToolCancellation,
    ToolDefinition,
    ToolEffectClass,
    ToolIdempotencyContract,
    ToolInvocation,
    ToolResult,
    managed_template,
)


def identity(hex_value: str) -> Identity:
    return Identity(bytes.fromhex(hex_value))


def derived(domain: bytes, *parts: bytes) -> Identity:
    digest = hashlib.sha256()
    digest.update(domain)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    value = bytearray(digest.digest()[:16])
    value[6] = (value[6] & 0x0F) | 0x40
    value[8] = (value[8] & 0x3F) | 0x80
    return Identity(bytes(value))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def eventually(predicate: object, *, attempts: int = 1_000) -> None:
    for _ in range(attempts):
        if callable(predicate) and predicate():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError("vertical condition was not observed")


async def main(root: Path, work: Path) -> None:
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    session_id = identity("10" * 16)
    template_id = identity("11" * 16)
    start_request_id = identity("12" * 16)
    driver_id = identity("01" * 16)
    provider_id = identity("13" * 16)
    artifact_id = identity("14" * 16)
    corrupt_id = identity("15" * 16)
    tool_name, tool_version = "artifact.vertical", "v1"
    registration_id = derived(
        b"navigator.tool.registration.v1",
        bytes(session_id),
        tool_name.encode(),
        tool_version.encode(),
    )
    participant_id = derived(
        b"navigator.root-participant.v1", bytes(session_id), bytes(template_id)
    )
    operation_id = derived(b"navigator.operation.v1", bytes(session_id), bytes(start_request_id))
    content = b"authoritative Slice 10 artifact\n"
    content_hash = hashlib.sha256(content).digest()
    expected_reference = {
        "artifactId": artifact_id.hex(),
        "sessionId": session_id.hex(),
        "creatorParticipantId": participant_id.hex(),
        "creatorOperationId": operation_id.hex(),
        "mediaType": "application/octet-stream",
        "size": str(len(content)),
        "sha256": content_hash.hex(),
    }

    package = root / "packages/navigator-driver-pi"
    entrypoint = package / "dist/main.js"
    node = Path(shutil.which("node") or "").resolve()
    if not node.is_file() or not entrypoint.is_file():
        raise RuntimeError("Pi build or Node executable is missing")
    provider_module = work / "provider.mjs"
    pi_ai = package / "node_modules/@earendil-works/pi-ai/dist/index.js"
    registered_name = f"navigator_registered_tool_{registration_id.hex()}"
    provider_module.write_text(
        "import{fauxAssistantMessage,fauxProvider,fauxToolCall}from"
        + json.dumps("file://" + os.fspath(pi_ai))
        + ";export function register(runtime){const p=fauxProvider({tokensPerSecond:1000});"
        + "p.setResponses(["
        + f"fauxAssistantMessage(fauxToolCall({json.dumps(registered_name)},{{value:'vertical'}}),{{stopReason:'toolUse'}}),"
        + f"(context)=>{{const result=[...context.messages].reverse().find((m)=>m.role==='toolResult'&&m.toolName==={json.dumps(registered_name)});"
        + "if(!result||result.isError||!result.details||!Array.isArray(result.details.artifacts)||result.details.artifacts.length!==1)throw new Error('missing observable Tool Artifact');"
        + "return fauxAssistantMessage(fauxToolCall('navigator_report',{kind:'succeeded',payload:JSON.stringify(result.details.artifacts[0])}),{stopReason:'toolUse'});},"
        + "fauxAssistantMessage('settled')]);"
        + "runtime.registerNativeProvider(p.provider);}\n",
        encoding="utf-8",
    )
    auth = work / "auth.json"
    auth.write_text("{}\n", encoding="ascii")
    driver = work / "pi-driver"
    driver.write_text(
        f"#!/bin/sh\nexec '{node}' --preserve-symlinks '{entrypoint}' 2>>'{work / 'pi.stderr'}'\n",
        encoding="utf-8",
    )
    driver.chmod(0o700)
    catalog = work / "drivers.json"
    catalog.write_text(
        json.dumps(
            {
                "entries": {
                    "pi": {
                        "driver_id": str(uuid.UUID(bytes=bytes(driver_id))),
                        "executable": os.fspath(driver),
                        "executable_sha256": sha256(driver),
                        "arguments": [],
                        "working_directory": os.fspath(package),
                        "protocol_version": 1,
                        "ownership_channel": "dedicated_fd",
                        "capabilities": [{"name": "durable.acceptance", "version": 1}],
                        "bootstrap_configuration": {
                            "provider": "faux",
                            "model": "faux-1",
                            "authPath": os.fspath(auth),
                            "providerModule": os.fspath(provider_module),
                            "cwd": os.fspath(work),
                            "tools": [],
                        },
                        "trusted_artifacts": [
                            {"path": os.fspath(node), "sha256": sha256(node)},
                            {"path": os.fspath(driver), "sha256": sha256(driver)},
                            {"path": os.fspath(entrypoint), "sha256": sha256(entrypoint)},
                            {"path": os.fspath(provider_module), "sha256": sha256(provider_module)},
                        ],
                    }
                }
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
        encoding="ascii",
    )
    data = work / "data"
    data.mkdir(mode=0o700)
    definition = ToolDefinition(
        name=tool_name,
        version=tool_version,
        input_schema={
            "additionalProperties": False,
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "type": "object",
        },
        output_schema={
            "additionalProperties": False,
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "type": "object",
        },
        required_authority="durable.acceptance",
        timeout_millis=30_000,
        cancellation=ToolCancellation.COOPERATIVE,
        effect_class=ToolEffectClass.IDEMPOTENT,
        idempotency=ToolIdempotencyContract.INVOCATION_IDENTITY,
    )
    effects = work / "effects.log"
    handler_entered = asyncio.Event()
    release_handler = asyncio.Event()
    terminal_ready = asyncio.Event()
    reference = None
    before_tmp = {path for path in Path("/tmp").glob("navigator-*") if path.is_dir()}
    local_options: dict[str, object] = {}
    if override := os.environ.get("NAVIGATORD_TEST_BINARY"):
        binary = Path(override).resolve()
        local_options.update(binary=binary, binary_sha256=sha256(binary))
    context = Navigator.local(
        data_dir=data,
        driver_catalog=catalog,
        driver_catalog_sha256=sha256(catalog),
        driver_profiles=("pi",),
        **local_options,
    )

    def terminal_persisted() -> bool:
        with sqlite3.connect(data / "navigator.sqlite") as database:
            row = database.execute(
                "SELECT terminal_digest IS NOT NULL FROM tool_invocations LIMIT 1"
            ).fetchone()
        return row == (1,)

    async with context as navigator:
        requested_slice10 = ("artifacts.v1", "consumer.tools.v1")
        runtime = context._runtime
        assert runtime is not None
        credential = (runtime / "bootstrap.credential").read_text(encoding="ascii")
        template = managed_template(
            "Invoke the registered artifact Tool, then report success with its exact reference.",
            required_capabilities=(
                CapabilityRequirement(capability="durable.acceptance", minimum_version=1),
            ),
        ).model_copy(update={"id": template_id, "driver_id": driver_id})
        template = template.model_copy(
            update={
                "authority": AuthorityProfile(
                    active=(rule := AuthorityRule(
                        capability="durable.acceptance",
                        resource="operation",
                        resource_id=operation_id,
                    ),),
                    delegable=(rule,),
                )
            }
        )
        session = await navigator.open(
            identity("16" * 16), session_id, "slice10-vertical", b"", template
        )
        registration = await navigator.tools.register(
            request_id=identity("17" * 16), session_id=session_id, definition=definition
        )
        replay = await navigator.tools.register(
            request_id=identity("17" * 16), session_id=session_id, definition=definition
        )
        assert registration == replay and registration.id == registration_id

        async def handler(invocation: ToolInvocation) -> ToolResult:
            nonlocal reference
            assert invocation.input_json() == {"value": "vertical"}
            with effects.open("a", encoding="ascii") as stream:
                stream.write(invocation.id.hex() + "\n")
            reference = await navigator.artifacts.write(
                request_id=identity("18" * 16),
                session_id=session_id,
                artifact_id=artifact_id,
                media_type="application/octet-stream",
                content=content,
                retain_until=datetime.now(timezone.utc) + timedelta(hours=1),
                creator_participant_id=invocation.participant_id,
                creator_operation_id=invocation.operation_id,
            )
            handler_entered.set()
            await release_handler.wait()
            terminal_ready.set()
            return ToolResult(
                output={"ok": True},
                artifacts=(
                    ()
                    if os.environ.get("SLICE10_DROP_TOOL_ARTIFACT") == "1"
                    else (reference,)
                ),
            )

        provider = navigator.tools.provider(
            session_id=session_id,
            provider_id=provider_id,
            handlers={registration.id: handler},
            reconnect_delay=0.01,
        )
        provider_task = asyncio.create_task(provider.serve())
        operation = await navigator.start(
            start_request_id,
            session_id,
            session.root_id,
            json.dumps({"task": "produce the vertical artifact"}).encode(),
        )
        await asyncio.wait_for(handler_entered.wait(), 30)
        exercise_disconnect = os.environ.get("SLICE10_NO_DISCONNECT") != "1"
        if exercise_disconnect:
            await provider.disconnect()
        assert len(effects.read_text(encoding="ascii").splitlines()) == 1
        if exercise_disconnect:
            provider.drop_next_terminal_ack()
        release_handler.set()
        await asyncio.wait_for(terminal_ready.wait(), 5)
        await eventually(terminal_persisted)
        if exercise_disconnect:
            await eventually(lambda: provider.watermark == 1)
            await provider.disconnect()
            await eventually(lambda: len(provider.connection_watermarks) >= 4)
            assert provider.connection_watermarks[:4] == (0, 0, 0, 1)
        for _ in range(3_000):
            operation = await navigator.operation(session_id, operation.id)
            if operation.status.value in {7, 8, 9, 10}:
                break
            await asyncio.sleep(0.01)
        assert operation.status.value == 7, operation.terminal_failure
        assert json.loads((operation.result or b"").decode()) == expected_reference
        database = sqlite3.connect(data / "navigator.sqlite")
        invocation_row = database.execute(
            "SELECT terminal_digest, CAST(snapshot AS TEXT) FROM tool_invocations"
        ).fetchone()
        provider_row = database.execute(
            "SELECT generation, acknowledged_server_sequence FROM tool_provider_connections"
        ).fetchone()
        connected_events = database.execute(
            "SELECT COUNT(*) FROM events WHERE event_type = 'tool.provider_connected'"
        ).fetchone()
        database.close()
        assert invocation_row is not None and invocation_row[0] is not None
        invocation_snapshot = json.loads(invocation_row[1])
        assert invocation_snapshot["phase"] == "completed"
        assert invocation_snapshot["terminal"] is not None
        assert provider_row is not None and provider_row[1] == 1
        assert provider_row[0] == 4
        assert connected_events is not None and connected_events[0] == 4
        assert reference is not None
        assert (
            await navigator.artifacts.read(session_id=session_id, artifact_id=artifact_id)
            == content
        )
        assert reference.id == artifact_id
        assert reference.session_id == session_id
        assert reference.creator_participant_id == participant_id
        assert reference.creator_operation_id == operation_id
        assert reference.media_type == "application/octet-stream"
        assert reference.size == len(content)
        assert reference.sha256 == content_hash
        assert len(effects.read_text(encoding="ascii").splitlines()) == 1

        removed = await navigator.artifacts.delete(
            request_id=identity("19" * 16), session_id=session_id, artifact_id=artifact_id
        )
        assert removed.id == artifact_id
        try:
            await navigator.artifacts.read(session_id=session_id, artifact_id=artifact_id)
        except NotFound:
            pass
        else:
            raise AssertionError("removed Artifact returned bytes")

        corrupt = await navigator.artifacts.write(
            request_id=identity("1a" * 16),
            session_id=session_id,
            artifact_id=corrupt_id,
            media_type="application/octet-stream",
            content=b"corrupt me",
            retain_until=datetime.now(timezone.utc) + timedelta(hours=1),
            creator_participant_id=participant_id,
            creator_operation_id=operation_id,
        )
        locator = (
            data
            / "navigator.artifacts"
            / str(uuid.UUID(bytes=bytes(session_id)))
            / f"{uuid.UUID(bytes=bytes(corrupt.id))}.blob"
        )
        locator.write_bytes(b"tampered!!")
        try:
            await navigator.artifacts.read(session_id=session_id, artifact_id=corrupt.id)
        except CorruptedState:
            pass
        else:
            raise AssertionError("corrupted Artifact returned bytes")
        provider_task.cancel()
        try:
            await provider_task
        except asyncio.CancelledError:
            pass
        from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb
        from navigator._transport.navigator.consumer.v1 import consumer_pb2_grpc

        channel = grpc.aio.insecure_channel(
            f"unix://{runtime / 'navigator.sock'}",
            options=(("grpc.default_authority", "localhost"),),
        )
        raw = consumer_pb2_grpc.NavigatorConsumerStub(channel)
        selected = await raw.Negotiate(
            pb.NegotiateRequest(
                minimum_version=pb.ProtocolVersion(major=1, minor=0),
                maximum_version=pb.ProtocolVersion(major=1, minor=1),
                capabilities=requested_slice10,
            ),
            metadata=(("x-navigator-bootstrap", credential),),
        )
        assert tuple(selected.negotiated.capabilities) == requested_slice10
        legacy = await raw.Negotiate(
            pb.NegotiateRequest(
                minimum_version=pb.ProtocolVersion(major=1, minor=0),
                maximum_version=pb.ProtocolVersion(major=1, minor=0),
                capabilities=requested_slice10,
            ),
            metadata=(("x-navigator-bootstrap", credential),),
        )
        assert tuple(legacy.negotiated.capabilities) == ()
        await channel.close()
    after_tmp = {path for path in Path("/tmp").glob("navigator-*") if path.is_dir()}
    assert after_tmp == before_tmp, f"managed runtime leaked: {sorted(after_tmp - before_tmp)}"
    print(
        json.dumps(
            {
                "status": "ok",
                "reference": expected_reference,
                "effects": 1,
                "connectionWatermarks": provider.connection_watermarks,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()))
