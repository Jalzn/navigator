from __future__ import annotations

import hashlib
from collections.abc import AsyncIterable, AsyncIterator
from datetime import datetime
from typing import Any

from .errors import CorruptedState, InvalidRequest, NavigatorError, from_failure
from .models import (
    MAX_ARTIFACT_BYTES,
    ArtifactRef,
    ArtifactSnapshot,
    ArtifactStatus,
    Identity,
    RetryClass,
    timestamp,
)

_CHUNK_BYTES = 64 * 1024


def _proto_timestamp(value: datetime) -> Any:
    from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

    seconds = int(value.timestamp())
    return pb.Timestamp(unix_seconds=seconds, nanoseconds=value.microsecond * 1000)


def _artifact_ref(value: Any) -> ArtifactRef:
    return ArtifactRef(
        id=Identity(value.artifact_id),
        session_id=Identity(value.session_id),
        creator_participant_id=Identity(value.creator_participant_id),
        creator_operation_id=Identity(value.creator_operation_id),
        media_type=value.media_type,
        size=value.size,
        sha256=bytes(value.sha256),
    )


def artifact_snapshot(value: Any) -> ArtifactSnapshot:
    return ArtifactSnapshot(
        **_artifact_ref(value).model_dump(),
        status=ArtifactStatus(value.status),
        retain_until=timestamp(value.retain_until.unix_seconds, value.retain_until.nanoseconds),
        created_at=timestamp(value.created_at.unix_seconds, value.created_at.nanoseconds),
        updated_at=timestamp(value.updated_at.unix_seconds, value.updated_at.nanoseconds),
        revision=value.revision,
    )


class Artifacts:
    """Bounded Artifact transport. Bytes are exposed only after terminal validation."""

    def __init__(self, navigator: Any) -> None:
        self._navigator = navigator

    @staticmethod
    def _bind(snapshot: ArtifactSnapshot, session_id: Identity, artifact_id: Identity) -> None:
        if snapshot.id != artifact_id or snapshot.session_id != session_id:
            raise CorruptedState(16, "Artifact response identity mismatch", RetryClass.NEVER)

    async def write(
        self,
        *,
        request_id: Identity,
        session_id: Identity,
        artifact_id: Identity,
        media_type: str,
        content: bytes | AsyncIterable[bytes],
        retain_until: datetime,
        authority_grant_id: Identity | None = None,
        creator_participant_id: Identity,
        creator_operation_id: Identity,
        declared_size: int | None = None,
        declared_sha256: bytes | None = None,
    ) -> ArtifactSnapshot:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        if isinstance(content, bytes):
            declared_size = len(content)
            declared_sha256 = hashlib.sha256(content).digest()

            async def source() -> AsyncIterator[bytes]:
                for offset in range(0, len(content), _CHUNK_BYTES):
                    yield content[offset : offset + _CHUNK_BYTES]

            chunks: AsyncIterable[bytes] = source()
        else:
            if declared_size is None or declared_sha256 is None:
                raise ValueError("streaming writes require declared_size and declared_sha256")
            chunks = content
        if declared_size is None or not 0 <= declared_size <= MAX_ARTIFACT_BYTES:
            raise ValueError("artifact size violates protocol bounds")
        if declared_sha256 is None or len(declared_sha256) != 32:
            raise ValueError("artifact SHA-256 must be 32 bytes")

        async def requests() -> AsyncIterator[Any]:
            yield pb.WriteArtifactRequest(
                begin=pb.BeginArtifactWrite(
                    metadata=self._navigator._metadata,
                    request_id=bytes(request_id),
                    session_id=bytes(session_id),
                    artifact_id=bytes(artifact_id),
                    media_type=media_type,
                    declared_size=declared_size,
                    declared_sha256=declared_sha256,
                    retain_until=_proto_timestamp(retain_until),
                    authority_grant_id=(
                        bytes(authority_grant_id) if authority_grant_id is not None else b""
                    ),
                    creator_participant_id=bytes(creator_participant_id),
                    creator_operation_id=bytes(creator_operation_id),
                )
            )
            offset = 0
            digest = hashlib.sha256()
            async for chunk in chunks:
                if not chunk or len(chunk) > _CHUNK_BYTES or offset + len(chunk) > declared_size:
                    raise InvalidRequest(
                        1, "Artifact chunk violates protocol bounds", RetryClass.NEVER
                    )
                digest.update(chunk)
                yield pb.WriteArtifactRequest(
                    chunk=pb.ArtifactChunk(
                        artifact_id=bytes(artifact_id), offset=offset, content=chunk
                    )
                )
                offset += len(chunk)
            if offset != declared_size or digest.digest() != declared_sha256:
                raise CorruptedState(
                    16, "Artifact stream did not match its declaration", RetryClass.NEVER
                )

        response = await self._navigator._invoke(self._navigator._stub.WriteArtifact, requests())
        snapshot = artifact_snapshot(self._navigator._outcome(response, "artifact"))
        self._bind(snapshot, session_id, artifact_id)
        if (
            snapshot.creator_participant_id != creator_participant_id
            or snapshot.creator_operation_id != creator_operation_id
            or snapshot.media_type != media_type
            or snapshot.size != declared_size
            or snapshot.sha256 != declared_sha256
            or snapshot.status is not ArtifactStatus.AVAILABLE
        ):
            raise CorruptedState(16, "Artifact write response conflicted", RetryClass.NEVER)
        return snapshot

    async def read(
        self,
        *,
        session_id: Identity,
        artifact_id: Identity,
        authority_grant_id: Identity | None = None,
        offset: int = 0,
        length: int | None = None,
    ) -> bytes:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        if offset < 0 or length is not None and length < 0:
            raise ValueError("artifact range cannot be negative")
        request = pb.ReadArtifactRequest(
            metadata=self._navigator._metadata,
            session_id=bytes(session_id),
            artifact_id=bytes(artifact_id),
            offset=offset,
            authority_grant_id=(
                bytes(authority_grant_id) if authority_grant_id is not None else b""
            ),
            **({"length": length} if length is not None else {}),
        )
        header: Any = None
        output = bytearray()
        expected_offset = offset
        async for response in self._navigator._stub.ReadArtifact(request):
            selected = response.WhichOneof("outcome")
            if selected == "failure":
                output.clear()
                raise from_failure(response.failure)
            if selected == "header" and header is None and not output:
                header = response.header
                snapshot = artifact_snapshot(header.artifact)
                self._bind(snapshot, session_id, artifact_id)
                expected_length = max(0, snapshot.size - offset)
                if length is not None:
                    expected_length = min(expected_length, length)
                if (
                    offset > snapshot.size
                    or header.range_offset != offset
                    or header.range_length != expected_length
                    or header.range_length > MAX_ARTIFACT_BYTES
                ):
                    raise CorruptedState(16, "Malformed Artifact read header", RetryClass.NEVER)
            elif selected == "chunk" and header is not None:
                chunk = response.chunk
                if (
                    bytes(chunk.artifact_id) != bytes(artifact_id)
                    or chunk.offset != expected_offset
                    or not chunk.content
                    or len(chunk.content) > _CHUNK_BYTES
                ):
                    output.clear()
                    raise CorruptedState(
                        16, "Artifact chunk ordering was corrupted", RetryClass.NEVER
                    )
                output.extend(chunk.content)
                expected_offset += len(chunk.content)
                if len(output) > header.range_length:
                    output.clear()
                    raise CorruptedState(
                        16, "Artifact read exceeded declared range", RetryClass.NEVER
                    )
            else:
                output.clear()
                raise NavigatorError(8, "Malformed Navigator response", RetryClass.NEVER)
        if header is None or len(output) != header.range_length:
            output.clear()
            raise CorruptedState(
                16, "Artifact read ended before its declared range", RetryClass.NEVER
            )
        snapshot = artifact_snapshot(header.artifact)
        if (
            offset == 0
            and len(output) == snapshot.size
            and hashlib.sha256(output).digest() != snapshot.sha256
        ):
            output.clear()
            raise CorruptedState(16, "Artifact content digest mismatch", RetryClass.NEVER)
        return bytes(output)

    async def snapshot(self, *, session_id: Identity, artifact_id: Identity) -> ArtifactSnapshot:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._navigator._invoke(
            self._navigator._stub.ArtifactSnapshot,
            pb.ArtifactSnapshotRequest(
                metadata=self._navigator._metadata,
                session_id=bytes(session_id),
                artifact_id=bytes(artifact_id),
            ),
        )
        snapshot = artifact_snapshot(self._navigator._outcome(response, "artifact"))
        self._bind(snapshot, session_id, artifact_id)
        return snapshot

    async def delete(
        self,
        *,
        request_id: Identity,
        session_id: Identity,
        artifact_id: Identity,
        authority_grant_id: Identity | None = None,
    ) -> ArtifactSnapshot:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._navigator._invoke(
            self._navigator._stub.DeleteArtifact,
            pb.DeleteArtifactRequest(
                metadata=self._navigator._metadata,
                request_id=bytes(request_id),
                session_id=bytes(session_id),
                artifact_id=bytes(artifact_id),
                authority_grant_id=(
                    bytes(authority_grant_id) if authority_grant_id is not None else b""
                ),
            ),
        )
        snapshot = artifact_snapshot(self._navigator._outcome(response, "artifact"))
        self._bind(snapshot, session_id, artifact_id)
        if snapshot.status is not ArtifactStatus.LOGICALLY_DELETED:
            raise CorruptedState(16, "Artifact delete response conflicted", RetryClass.NEVER)
        return snapshot
