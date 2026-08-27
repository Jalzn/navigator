# Arara Runtime specifications

Status: design in progress. These documents record decisions made before
implementation. They describe the intended contract, not existing behavior.

The latest adversarial findings and proposed MVP reduction are recorded in
[adversarial-review.md](adversarial-review.md). They are not yet folded into all
normative documents.

The walking skeleton is an implementation sequence, not a deletion of the
planned architecture. Store parity, artifacts, approvals, checkpoints,
observability, recovery, and the complete orchestration surface remain intended
capabilities and may be added in tested slices after the first vertical path.

The proposed replacement of the custom Pi extension with a small Node host built
on the coding-agent SDK is recorded in
[pi-sdk-integration.md](pi-sdk-integration.md). It remains conditional on a
blocking spike.

`arara-runtime` will be an independent workspace package in `runtime/`, imported
as `arara_runtime`. It provides reusable infrastructure for hierarchical Pi
agents connected directly to a foreground Runtime Host. It must remain independent from Factory,
Laboratory, models, targets, gates, experiments, Git, and publication.

## Documents

- [architecture.md](architecture.md): boundaries, node hierarchy, and public API.
- [public-api.md](public-api.md): minimal consumer-facing models and methods.
- [lifecycle.md](lifecycle.md): async execution, states, concurrency, and recovery.
- [messaging.md](messaging.md): hierarchical mailboxes and delivery guarantees.
- [protocol.md](protocol.md): Pi extension WebSocket frames and connection contract.
- [pi-extension.md](pi-extension.md): Pi hooks, message injection, and result contract.
- [pi-sdk-integration.md](pi-sdk-integration.md): evaluation and spike for Pi's
  coding-agent, agent-core, and AI layers.
- [storage.md](storage.md): Store contract, SQLite schema, and artifacts.
- [store-contract.md](store-contract.md): transactional Store operations and invariants.
- [errors.md](errors.md): stable typed failures and boundary translation.
- [security.md](security.md): capabilities, authority, isolation, and invariants.
- [pi-tools.md](pi-tools.md): role-scoped orchestration tools exposed to agents.
- [approvals.md](approvals.md): trusted user approvals and scoped grants.
- [observability.md](observability.md): foreground Runtime Host and live event view.
- [dependencies.md](dependencies.md): library decisions and rejected alternatives.
- [delivery-plan.md](delivery-plan.md): implementation and migration sequence.
- [plans/](plans/README.md): detailed vertical delivery and review gates.

## Decisions already closed

- Independent `runtime/` workspace package named `arara-runtime`.
- Python import package named `arara_runtime`.
- Async-first core built on AnyIO; no parallel synchronous API initially.
- Cross-platform core and storage from the first release.
- Pi processes are launched directly; Herdr is not a runtime dependency.
- Agent lifecycle and agent communication are separate interfaces.
- The first `AgentLauncher` is `PiProcessLauncher`.
- The first `AgentChannel` is a local authenticated WebSocket connection between
  the Pi runtime extension and the Runtime Host.
- The Python endpoint uses the focused `websockets` library; the Runtime has no
  general HTTP application or API in version 1.
- The Runtime deliberately provides three semantic roles: Coordinator, Campaign,
  and Worker. This opinionated hierarchy is part of its product model, not a
  Factory-specific implementation detail.
- The user communicates with one Coordinator agent.
- The Coordinator plans and dispatches Campaign agents.
- Campaigns coordinate Worker agents. A Worker may create child Workers when its
  trusted template and Runtime policy permit it.
- Every Campaign is agent-led in the first version; there is no external
  deterministic campaign-controller variant.
- Communication is hierarchical and mediated by the parent node: Coordinator ↔
  Campaign ↔ Worker. A child Worker communicates through its parent Worker.
- Coordinator, Campaign, and eligible Worker agents may autonomously create only
  the child roles allowed by their trusted template, through policy-enforced
  Runtime tools.
- One active operation per Agent, with a persistent FIFO mailbox.
- Delivery is at-least-once with acknowledgement and deduplication.
- The Pi extension reconstructs accepted delivery IDs from the native persisted
  custom messages it injected; it does not maintain a second marker, JavaScript
  database, or state file.
- Pi `agent_settled` means idle only. Campaign and Worker success, failure,
  blocking, and questions must be reported explicitly through runtime tools.
- Multiple Campaigns and Workers can run concurrently under conservative limits.
- Queued work is not resumed automatically after process or machine restart.
- Recovery is explicit through reconciliation and user/consumer authorization.
- `Store`, `AgentLauncher`, and `AgentChannel` are the only public infrastructure
  interfaces initially. Local dispatch is an internal Runtime mechanism.
- `SQLiteStore` is the default durable store; `MemoryStore` exists for tests.
- SQLite uses ten focused tables, a single Runtime writer, bounded expiring
  Session ownership leases, and no WAL until tests demonstrate a need.
- Large artifacts live outside SQLite and are referenced by validated metadata.
- Important child events proactively wake an idle parent; progress is batched.
- Context windows are assembled mechanically; semantic summaries are produced by
  the owning parent Agent and persisted as checkpoints.
- Durable history is retained conservatively and deleted only with explicit user
  authorization; temporary unreferenced artifacts may expire automatically.
- Runtime-owned process trees use graceful cancellation followed by bounded
  psutil termination after identity and ownership validation.
- The Runtime owns and monitors only Pi process trees it launched itself.
- WebSocket delivery uses a small versioned JSON protocol with handshake,
  request/response, delivery acknowledgement, lifecycle events, and native
  ping/pong keepalive.
- Pi orchestration uses six generic, policy-filtered tools: spawn, send,
  children, status, cancel, and resume.
- Agents may request approval through a seventh conditional tool; only the
  trusted user channel can issue a scoped, expiring grant.
- Every child is created from an immutable, consumer-provided AgentTemplate;
  models cannot construct prompts, tools, or executables freely. Arbitrary
  consumer Pi extensions are outside version 1.
- Version 1 requires persisted Sessions to be reset when consumer templates,
  prompts, tools, extensions, or policies change.
- Each interactive Session owns a foreground `Runtime` process that stops with
  the Coordinator; it is not a daemon and never auto-resumes after restart.
- Consumer CLIs expose one default start command plus only `--resume` and
  `--reset` lifecycle flags initially; no administrative subcommand tree.
- `--reset` creates a clean Session and makes the previous one inactive without
  physically deleting its durable audit history.
- The foreground Runtime Host renders a bounded structured event feed with Rich;
  the Coordinator conversation remains clean.
- Herdr may be reconsidered later as an optional developer-facing launcher or
  inspector, but no Herdr abstraction or adapter is implemented in version 1.
- No scheduler service, broker, daemon, event bus, ORM, or workflow DSL initially.
- Public failures use one `RuntimeFailure` carrying a closed `ErrorInfo`; native
  async cancellation and programmer bugs are never disguised as domain errors.

## Important naming issue

The repository root distribution is `arara-models` and continues to import as
`arara`. The independent workspace member reserves distribution name
`arara-runtime` and imports as `arara_runtime`.
