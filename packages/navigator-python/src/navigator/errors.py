from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import Identity, RetryClass


class NavigatorError(Exception):
    def __init__(
        self,
        code: int,
        message: str,
        retry: RetryClass | int,
        related_id: bytes | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code, self.retry = code, RetryClass(retry)
        self.related_id = Identity(related_id) if related_id else None
        self.details = dict(details or {})

    def __repr__(self) -> str:
        return f"NavigatorError(code={self.code}, retry={self.retry}, message=<redacted>)"


class TransportUnavailable(NavigatorError):
    pass


class InvalidRequest(NavigatorError):
    pass


class Unsupported(NavigatorError):
    pass


class UnsupportedVersion(Unsupported):
    pass


class UnsupportedCapability(Unsupported):
    pass


class IncompatibleProtocol(NavigatorError):
    pass


class NotFound(NavigatorError):
    pass


class Conflict(NavigatorError):
    pass


class StaleOwnership(NavigatorError):
    pass


class AuthenticationError(NavigatorError):
    pass


class AuthorizationError(NavigatorError):
    pass


class CapacityExceeded(NavigatorError):
    pass


class NavigatorTimeout(NavigatorError):
    pass


class OperationCancelled(NavigatorError):
    pass


class UncertainEffect(NavigatorError):
    pass


class CleanupRequired(NavigatorError):
    pass


class CorruptedState(NavigatorError):
    pass


class InternalError(NavigatorError):
    pass


_ERRORS = {
    1: InvalidRequest,
    2: UnsupportedVersion,
    3: UnsupportedCapability,
    4: NotFound,
    5: Conflict,
    6: StaleOwnership,
    7: TransportUnavailable,
    8: InternalError,
    9: AuthenticationError,
    10: AuthorizationError,
    11: CapacityExceeded,
    12: NavigatorTimeout,
    13: OperationCancelled,
    14: UncertainEffect,
    15: CleanupRequired,
    16: CorruptedState,
    17: Unsupported,
    18: IncompatibleProtocol,
}


def from_failure(value: Any) -> NavigatorError:
    # Details are intentionally opaque: protobuf bytes can contain credentials.
    error_type = _ERRORS.get(int(value.code), NavigatorError)
    try:
        retry = RetryClass(int(value.retry))
    except (TypeError, ValueError):
        return InternalError(8, "Malformed Navigator failure", RetryClass.NEVER)
    return error_type(
        int(value.code),
        str(value.message),
        retry,
        bytes(value.related_id) if value.HasField("related_id") else None,
    )
