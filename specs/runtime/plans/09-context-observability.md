# Vertical 09 — Context management and observability

## Outcome

Long-running hierarchies remain understandable, bounded, and diagnosable while
Pi and Runtime retain distinct sources of truth.

## End-to-end proof

A Campaign executes enough Worker turns to trigger context management. The
owning parent produces a semantic checkpoint, Runtime builds a bounded mechanical
view, and the user can trace the full operation through logs/events without
polluting the Coordinator TUI.

## Scope

- context checkpoint table and parent-owned semantic summaries;
- mechanical selection of relevant messages, results, and artifact references;
- Pi transcript/session identity linkage without transcript mirroring;
- structured logging with Session/Agent/operation/message/request correlation;
- bounded Rich event view only in a terminal mode proven not to conflict with
  Coordinator TUI;
- progress batching, important-event wake-up, diagnostics, and export;
- retention/quotas for events and checkpoints;
- secrets and control-sequence redaction.

## Invariants

- Pi owns transcript and compaction; Runtime owns operational graph/history;
- summaries are Agent-produced claims, not authoritative lifecycle state;
- terminal events are never dropped or hidden by batching;
- renderer failure cannot alter Runtime state;
- logs never contain credentials or unrestricted tool payloads;
- context selection is deterministic from persisted inputs.

## Acceptance

- context boundary just below/at/above limits;
- checkpoint creation, replacement, stale revision, and restart;
- progress flood retains bounded memory and terminal visibility;
- renderer disabled/headless mode has identical behavior;
- TUI plus logging does not corrupt terminal output;
- correlation reconstructs one request across parent/child/tool/process events;
- malicious ANSI/control text is neutralized.

## Adversarial review

- compare checkpoint claims against authoritative state;
- force renderer/log sink failure and disk full;
- attempt prompt injection through old summaries and artifact metadata;
- inspect duplicated storage between Pi and Runtime;
- remove metrics or views that have no concrete operational question.

## Excluded from this slice

Central log services, distributed tracing backends, dashboards, semantic vector
search, and automated evaluation of summary quality.

