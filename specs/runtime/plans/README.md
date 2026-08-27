# Runtime vertical delivery plans

Status: implementation roadmap. These plans refine `delivery-plan.md` into
reviewable end-to-end slices. They preserve the complete target architecture;
later placement is sequencing, not removal from scope.

## Working rule

Only one vertical slice is active at a time. A slice must produce observable
behavior through its real boundaries, not only disconnected classes. After its
acceptance tests pass, perform the recorded adversarial review and update the
specifications with anything learned before starting the next slice.

Every review asks:

1. Does the behavior match the normative specs?
2. Can a crash or timeout leave permanent active state?
3. Can authority, tools, paths, or credentials escape their policy ceiling?
4. Are external effects classified before retry or resume?
5. Did we introduce a layer or dependency without a demonstrated need?
6. Are errors and logs sufficient to diagnose the failure from one run?
7. Can the slice be exercised without a paid model call?

Copy [REVIEW-TEMPLATE.md](REVIEW-TEMPLATE.md) for the review record of each
implemented slice. Review evidence belongs beside the implementation history,
while this folder remains the planned contract.

## Sequence

| ID | Vertical slice | User-visible proof |
|---|---|---|
| 00 | [Foundation](00-foundation.md) | Independent package installs and contracts run |
| 01 | [Pi host](01-pi-host.md) | Coordinator and headless Agent run through the production adapter |
| 02 | [Durable session](02-durable-session.md) | Session opens, closes, and is inspectable in SQLite |
| 03 | [Coordinator](03-coordinator.md) | User converses with the persistent Coordinator |
| 04 | [Campaign and Worker](04-campaign-worker.md) | Coordinator delegates through Campaign to Worker and receives a report |
| 05 | [Messaging](05-messaging.md) | Durable mailbox handles prompt, steering, follow-up, feedback, and deduplication |
| 06 | [Recovery](06-recovery.md) | Killed/timed-out workers reconcile without permanent active state |
| 07 | [Policy and tools](07-policy-tools.md) | Role-scoped delegation and non-escalation are enforced |
| 08 | [Approvals and artifacts](08-approvals-artifacts.md) | Approved effect and bounded artifact complete with audit history |
| 09 | [Context and observability](09-context-observability.md) | Long campaign remains understandable and within context limits |
| 10 | [Runtime hardening](10-runtime-hardening.md) | Neutral full-stack scenario and macOS release gate pass |

## Gate states

Each slice moves through:

```text
planned → implementing → acceptance → adversarial_review → accepted
                                      ↘ corrections ↗
```

Do not mark a slice accepted with skipped blocking tests. Record optional tests
separately. A discovered requirement is added to the earliest slice that can
prove it without rewriting already accepted contracts.

## Definition of done for every slice

- implementation and public behavior agree;
- deterministic tests cover success, failure, cancellation, and timeout where
  applicable;
- no test requires a real provider credential unless explicitly a manual smoke;
- `git diff --check`, focused tests, and dependency audit pass;
- operational failures expose stable error information and correlation IDs;
- specs and this plan reflect discoveries made during implementation;
- the adversarial checklist has a written result;
- the next slice does not begin until corrections are accepted.

Consumer migrations are intentionally outside this folder. Each consumer owns
its integration plan; Runtime completion is proved with a neutral example and
cannot depend on product-specific behavior.
