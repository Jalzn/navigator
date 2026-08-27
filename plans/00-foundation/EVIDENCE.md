# Foundation semantic evidence

Status: verified by the fourth independent adversarial gate.

| Invariant | Canonical source | Subject or boundary | Evidence | Mutant rejected |
|---|---|---|---|---|
| NAV-OP-005 idle is not success | docs/principles.md / Acceptance is not completion | OperationSubject | nav_op_005_idle_never_implies_success | IdleMeansSuccess |
| NAV-OP-TERM-001 terminal is immutable | docs/domain-model.md / Operation | Operation aggregate | terminal_state_never_changes | property: all eleven post-terminal actions are rejected |
| NAV-OP-MODEL-001 actions match public state model | docs/execution.md / Operation lifecycle | OperationSubject | generated_operation_traces_match_reference_model | Resume from Starting counterexample |
| NAV-AUTH-001 authority decreases | docs/principles.md / Authority only decreases | AuthoritySubject | nav_authority_001_effective_authority_is_intersection | UnionAuthority |
| NAV-LEASE-001 stale owner cannot write | docs/principles.md / Ownership is exclusive and fenced | FencedWriteSubject | nav_lease_001_stale_epoch_cannot_authorize_write | IgnoresFence |
| NAV-RECOVERY-001 started unsafe effect is uncertain | docs/principles.md / Uncertainty is first-class | recovery classifier | nav_recovery_001_started_non_idempotent_effect_is_uncertain | none yet; executor mutant belongs to recovery slice |
| NAV-PROTO-BOUND-001 input is bounded before decode | docs/communication.md / Backpressure | bounded decoder | raw_frame_is_bounded_before_decode | boundary property; decoder instrumentation |
| NAV-PROTO-NEG-001 protocol selects mutual version | docs/compatibility.md / Protocol negotiation | protocol kernel | negotiation examples and generated laws | property evidence, not mutation claim |
| NAV-VALIDATE-001 invariants survive decode | docs/testing.md / Assertions | domain codecs | validation_cannot_be_bypassed_by_deserialization | boundary property, not mutation claim |
| NAV-ERROR-001 diagnostics redact public message | docs/policy-security.md / Secrets | ErrorInfo and NavigatorError | public_error_debug_and_display_do_not_repeat_message | boundary property, not mutation claim |

The Store, Mailbox, Driver, delivery ACK, and recovery-executor rows are added by
their owning slices. Their absence is not represented as passing evidence.
