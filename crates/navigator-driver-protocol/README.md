# Navigator Driver protocol

`navigator.driver.v1.Envelope` is transported as a protobuf varint-length-delimited frame. A frame, including its length prefix, must not exceed 256 KiB. Implementations must reject the declared length before allocating or decoding the body.

Every request has an independent request ID and every response names it in `in_reply_to`. Mutable request IDs are idempotency keys. Instance identity includes the Session ownership epoch; a stale epoch cannot authorize work.

Every response uses a `oneof` containing either a semantic success result or a typed `Failure`. Transport, authentication, and command failures therefore cannot be confused with acceptance unknown, uncertain start, or uncertain/cleanup-required stop outcomes.

Authentication uses HMAC-SHA-256. `request_digest` is SHA-256 over the canonical encoded request body with `Authentication.authenticator` and `Authentication.request_digest` cleared. The tag input is length-delimited and binds the protocol domain, envelope ID, request ID, key ID, nonce, digest, Participant scope, launch-attempt scope, protocol version, and expiry. A receiver also rejects expired credentials and previously consumed nonces. Nonce storage and key revocation belong to the authenticated transport implementation.

Capability requirements are checked before mutable effects. Unknown optional protobuf fields are accepted and ignored; an unknown required capability is a typed negotiation failure.
