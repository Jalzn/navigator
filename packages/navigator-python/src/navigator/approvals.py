from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from .errors import CorruptedState
from .models import (
    MAX_APPROVAL_USES,
    Approval,
    ApprovalDecisionSource,
    ApprovalGrant,
    ApprovalRequest,
    ApprovalStatus,
    Identity,
    RetryClass,
    timestamp,
)


def _proto_timestamp(value: datetime) -> Any:
    from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Approval expiry must be timezone-aware")
    seconds = int(value.timestamp())
    return pb.Timestamp(unix_seconds=seconds, nanoseconds=value.microsecond * 1000)


def _approval_snapshot(value: Any) -> Approval:
    try:
        if not value.HasField("request"):
            raise ValueError("Approval response omitted its request")
        request = value.request
        decision_source = (
            ApprovalDecisionSource(request.decision_source) if request.decision_source else None
        )
        parsed_request = ApprovalRequest(
            id=Identity(request.approval_id),
            session_id=Identity(request.session_id),
            requester_participant_id=Identity(request.requester_participant_id),
            operation_id=Identity(request.operation_id),
            capability=request.capability,
            resource=bytes(request.resource),
            summary=request.summary,
            status=ApprovalStatus(request.status),
            expires_at=timestamp(request.expires_at.unix_seconds, request.expires_at.nanoseconds),
            grant_id=Identity(request.grant_id) if request.HasField("grant_id") else None,
            decision_source=decision_source,
            created_at=timestamp(request.created_at.unix_seconds, request.created_at.nanoseconds),
            decided_at=(
                timestamp(request.decided_at.unix_seconds, request.decided_at.nanoseconds)
                if request.HasField("decided_at")
                else None
            ),
            revision=request.revision,
        )
        parsed_grant = None
        if value.HasField("grant"):
            grant = value.grant
            parsed_grant = ApprovalGrant(
                id=Identity(grant.grant_id),
                approval_id=Identity(grant.approval_id),
                session_id=Identity(grant.session_id),
                subject_participant_id=Identity(grant.subject_participant_id),
                operation_id=Identity(grant.operation_id),
                capability=grant.capability,
                resource_hash=bytes(grant.resource_hash),
                issued_by=ApprovalDecisionSource(grant.issued_by),
                max_uses=grant.max_uses,
                used_count=grant.used_count,
                expires_at=timestamp(grant.expires_at.unix_seconds, grant.expires_at.nanoseconds),
                revoked_at=(
                    timestamp(grant.revoked_at.unix_seconds, grant.revoked_at.nanoseconds)
                    if grant.HasField("revoked_at")
                    else None
                ),
                created_at=timestamp(grant.created_at.unix_seconds, grant.created_at.nanoseconds),
                revision=grant.revision,
            )
        return Approval(request=parsed_request, grant=parsed_grant)
    except (ValueError, ValidationError) as error:
        raise CorruptedState(16, "Malformed Approval response", RetryClass.NEVER) from error


class Approvals:
    """Trusted, Session-bound Approval decisions and immutable snapshots."""

    def __init__(self, navigator: Any) -> None:
        self._navigator = navigator

    @staticmethod
    def _bind(value: Approval, session_id: Identity, approval_id: Identity) -> None:
        if value.request.session_id != session_id or value.request.id != approval_id:
            raise CorruptedState(16, "Approval response identity mismatch", RetryClass.NEVER)

    async def get(self, *, session_id: Identity, approval_id: Identity) -> Approval:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._navigator._invoke(
            self._navigator._stub.ApprovalSnapshot,
            pb.ApprovalSnapshotRequest(
                metadata=self._navigator._metadata,
                session_id=bytes(session_id),
                approval_id=bytes(approval_id),
            ),
        )
        result = _approval_snapshot(self._navigator._outcome(response, "approval"))
        self._bind(result, session_id, approval_id)
        return result

    async def approve(
        self,
        *,
        session_id: Identity,
        approval_id: Identity,
        expected_revision: int,
        expires_at: datetime,
        max_uses: int = 1,
        request_id: Identity | None = None,
        grant_id: Identity | None = None,
    ) -> Approval:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        if expected_revision <= 0 or not 1 <= max_uses <= MAX_APPROVAL_USES:
            raise ValueError("Approval revision or use count violates protocol bounds")
        request_id = request_id or Identity(os.urandom(16))
        grant_id = grant_id or Identity(os.urandom(16))
        response = await self._navigator._invoke(
            self._navigator._stub.ApproveApproval,
            pb.ApproveApprovalRequest(
                metadata=self._navigator._metadata,
                request_id=bytes(request_id),
                session_id=bytes(session_id),
                approval_id=bytes(approval_id),
                expected_revision=expected_revision,
                grant_id=bytes(grant_id),
                grant_expires_at=_proto_timestamp(expires_at),
                max_uses=max_uses,
            ),
        )
        result = _approval_snapshot(self._navigator._outcome(response, "approval"))
        self._bind(result, session_id, approval_id)
        if (
            result.request.status is not ApprovalStatus.GRANTED
            or result.grant is None
            or result.grant.id != grant_id
            or result.grant.max_uses != max_uses
        ):
            raise CorruptedState(16, "Approval decision response conflicted", RetryClass.NEVER)
        return result

    async def deny(
        self,
        *,
        session_id: Identity,
        approval_id: Identity,
        expected_revision: int,
        request_id: Identity | None = None,
    ) -> Approval:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        if expected_revision <= 0:
            raise ValueError("Approval revision violates protocol bounds")
        response = await self._navigator._invoke(
            self._navigator._stub.DenyApproval,
            pb.DenyApprovalRequest(
                metadata=self._navigator._metadata,
                request_id=bytes(request_id or Identity(os.urandom(16))),
                session_id=bytes(session_id),
                approval_id=bytes(approval_id),
                expected_revision=expected_revision,
            ),
        )
        result = _approval_snapshot(self._navigator._outcome(response, "approval"))
        self._bind(result, session_id, approval_id)
        if result.request.status is not ApprovalStatus.DENIED or result.grant is not None:
            raise CorruptedState(16, "Approval denial response conflicted", RetryClass.NEVER)
        return result

    async def revoke(
        self,
        *,
        session_id: Identity,
        grant_id: Identity,
        expected_revision: int,
        request_id: Identity | None = None,
    ) -> Approval:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        if expected_revision <= 0:
            raise ValueError("Grant revision violates protocol bounds")
        response = await self._navigator._invoke(
            self._navigator._stub.RevokeApprovalGrant,
            pb.RevokeApprovalGrantRequest(
                metadata=self._navigator._metadata,
                request_id=bytes(request_id or Identity(os.urandom(16))),
                session_id=bytes(session_id),
                grant_id=bytes(grant_id),
                expected_revision=expected_revision,
            ),
        )
        result = _approval_snapshot(self._navigator._outcome(response, "approval"))
        if (
            result.request.session_id != session_id
            or result.request.status is not ApprovalStatus.REVOKED
            or result.grant is None
            or result.grant.id != grant_id
            or result.grant.revoked_at is None
        ):
            raise CorruptedState(16, "Grant revocation response conflicted", RetryClass.NEVER)
        return result
