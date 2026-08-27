from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from navigator import Navigator
from navigator.errors import CorruptedState
from navigator.models import ApprovalRequest, ApprovalStatus, Identity


def oid(last: int) -> Identity:
    return Identity(bytes(15) + bytes([last]))


def approval_wire(pb: Any, *, status: int, grant: bool = False, revoked: bool = False) -> Any:
    request = pb.ApprovalRequestSnapshot(
        approval_id=bytes(oid(2)),
        session_id=bytes(oid(1)),
        requester_participant_id=bytes(oid(3)),
        operation_id=bytes(oid(4)),
        capability="repository.publish",
        resource=b'{"branch":"main"}',
        summary="publish exact revision",
        status=status,
        expires_at=pb.Timestamp(unix_seconds=100),
        created_at=pb.Timestamp(unix_seconds=1),
        revision=1 if status == pb.APPROVAL_STATUS_PENDING else 2,
    )
    grant_value = None
    if grant:
        request.grant_id = bytes(oid(6))
        request.decision_source = pb.APPROVAL_DECISION_SOURCE_TRUSTED_CONSUMER
        request.decided_at.CopyFrom(pb.Timestamp(unix_seconds=2))
        grant_value = pb.ApprovalGrantSnapshot(
            grant_id=bytes(oid(6)),
            approval_id=bytes(oid(2)),
            session_id=bytes(oid(1)),
            subject_participant_id=bytes(oid(3)),
            operation_id=bytes(oid(4)),
            capability="repository.publish",
            resource_hash=bytes(32),
            issued_by=pb.APPROVAL_DECISION_SOURCE_TRUSTED_CONSUMER,
            max_uses=1,
            expires_at=pb.Timestamp(unix_seconds=90),
            created_at=pb.Timestamp(unix_seconds=2),
            revision=2 if revoked else 1,
        )
        if revoked:
            grant_value.revoked_at.CopyFrom(pb.Timestamp(unix_seconds=3))
    elif status == pb.APPROVAL_STATUS_DENIED:
        request.decision_source = pb.APPROVAL_DECISION_SOURCE_TRUSTED_CONSUMER
        request.decided_at.CopyFrom(pb.Timestamp(unix_seconds=2))
    result = pb.ApprovalSnapshot(request=request)
    if grant_value is not None:
        result.grant.CopyFrom(grant_value)
    return result


def test_approval_resource_is_canonical_bounded_and_models_are_frozen() -> None:
    base = {
        "id": oid(1),
        "session_id": oid(2),
        "requester_participant_id": oid(3),
        "operation_id": oid(4),
        "capability": "repository.publish",
        "resource": b'{"z":1,"a":2}',
        "summary": "publish",
        "status": ApprovalStatus.PENDING,
        "expires_at": datetime.fromtimestamp(10, tz=timezone.utc),
        "created_at": datetime.fromtimestamp(1, tz=timezone.utc),
        "revision": 1,
    }
    value = ApprovalRequest(**base)
    assert value.resource == b'{"a":2,"z":1}'
    with pytest.raises(ValidationError):
        value.summary = "changed"
    for resource in (b'{"a":1,"a":2}', b'{"a":1.5}', b"[]", b'{"n":-0}'):
        with pytest.raises((ValidationError, ValueError, TypeError)):
            ApprovalRequest(**{**base, "resource": resource})


@pytest.mark.asyncio
async def test_approval_group_maps_get_approve_deny_and_revoke_exactly() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def ApprovalSnapshot(self, request: Any) -> Any:
            assert request.session_id == bytes(oid(1)) and request.approval_id == bytes(oid(2))
            return pb.ApprovalSnapshotResponse(
                approval=approval_wire(pb, status=pb.APPROVAL_STATUS_PENDING)
            )

        async def ApproveApproval(self, request: Any) -> Any:
            assert request.grant_id == bytes(oid(6))
            assert request.expected_revision == 1 and request.max_uses == 1
            return pb.ApproveApprovalResponse(
                approval=approval_wire(pb, status=pb.APPROVAL_STATUS_GRANTED, grant=True)
            )

        async def DenyApproval(self, request: Any) -> Any:
            return pb.DenyApprovalResponse(
                approval=approval_wire(pb, status=pb.APPROVAL_STATUS_DENIED)
            )

        async def RevokeApprovalGrant(self, request: Any) -> Any:
            assert request.grant_id == bytes(oid(6))
            return pb.RevokeApprovalGrantResponse(
                approval=approval_wire(
                    pb, status=pb.APPROVAL_STATUS_REVOKED, grant=True, revoked=True
                )
            )

    approvals = Navigator(Stub(), pb.RequestMetadata()).approvals
    assert (
        await approvals.get(session_id=oid(1), approval_id=oid(2))
    ).request.status is ApprovalStatus.PENDING
    granted = await approvals.approve(
        request_id=oid(5),
        grant_id=oid(6),
        session_id=oid(1),
        approval_id=oid(2),
        expected_revision=1,
        expires_at=datetime.fromtimestamp(90, tz=timezone.utc),
    )
    assert granted.grant is not None and granted.grant.id == oid(6)
    denied = await approvals.deny(
        request_id=oid(7), session_id=oid(1), approval_id=oid(2), expected_revision=1
    )
    assert denied.request.status is ApprovalStatus.DENIED
    revoked = await approvals.revoke(
        request_id=oid(8), session_id=oid(1), grant_id=oid(6), expected_revision=1
    )
    assert revoked.grant is not None and revoked.grant.revoked_at is not None


@pytest.mark.asyncio
async def test_approval_group_rejects_broadened_or_cross_bound_server_response() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def ApproveApproval(self, request: Any) -> Any:
            value = approval_wire(pb, status=pb.APPROVAL_STATUS_GRANTED, grant=True)
            value.grant.capability = "repository.delete"
            return pb.ApproveApprovalResponse(approval=value)

    with pytest.raises(CorruptedState):
        await Navigator(Stub(), pb.RequestMetadata()).approvals.approve(
            request_id=oid(5),
            grant_id=oid(6),
            session_id=oid(1),
            approval_id=oid(2),
            expected_revision=1,
            expires_at=datetime.fromtimestamp(90, tz=timezone.utc),
        )


@pytest.mark.asyncio
async def test_packaged_daemon_negotiates_approvals_v1(tmp_path: Path) -> None:
    async with Navigator.local(data_dir=tmp_path / "approval-package") as client:
        negotiated = await client.negotiate(capabilities=("approvals.v1",))
        assert negotiated.capabilities == ("approvals.v1",)
        assert negotiated.protocol.minor >= 2
