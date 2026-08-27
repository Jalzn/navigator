# Public API

## Principles

The public surface optimizes for a short consumer entrypoint and stable data
contracts. Factory, Laboratory, and future consumers provide trusted templates
and configuration; they do not orchestrate internal mailbox or Agent mechanics.

Version 1 exposes:

- one convenience function, `run_session()`;
- one advanced async context manager, `Runtime`;
- immutable Pydantic inputs and snapshots;
- one public `RuntimeFailure` exception carrying immutable `ErrorInfo`;
- `Store`, `AgentLauncher`, and `AgentChannel` protocols;
- the initial concrete local implementations.

There is no separate `RuntimeHost` class, public `Dispatcher`, builder, service
locator, plugin registry, mutable remote handle, or parallel synchronous API.

## Simple consumer entrypoint

```python
from arara_runtime import OpenMode, RuntimeLimits, SessionSpec, run_session

await run_session(
    SessionSpec(
        name="factory",
        coordinator_template="factory-coordinator",
        templates=factory_templates,
        limits=RuntimeLimits(),
    ),
    data_dir=".factory/runtime",
    mode=OpenMode.OPEN,
    environment=trusted_environment,
)
```

`run_session()` constructs `SQLiteStore`, `PiProcessLauncher`,
`WebSocketAgentChannel`, private local dispatch, and `RichRuntimeRenderer`. It
opens Runtime, runs the interactive Coordinator until shutdown, performs bounded
cleanup, and returns a final immutable `SessionSnapshot`.

`environment` is an optional trusted in-memory mapping supplied by the consumer.
Only keys allowlisted by the selected AgentPolicy are delegated to a process.
Values are never placed in `SessionSpec`, persisted, logged, or exposed to model
arguments. The default is an empty mapping rather than ambient environment
inheritance. Advanced consumers configure `PiProcessLauncher` directly when the
Pi executable or launch behavior differs.

The function is async. A consumer CLI or `mise` task calls it through
`anyio.run()`. The Runtime package does not add synchronous wrappers.

## Advanced construction

Tests and consumers with a real adapter need may inject the three public seams:

```python
async with Runtime(
    store=MemoryStore(),
    launcher=launcher,
    channel=channel,
    renderer=None,
) as runtime:
    session = await runtime.open_session(spec, mode=OpenMode.OPEN)
    final = await runtime.run(session.id)
```

Constructor defaults are not hidden globals. `run_session()` is the convenience
composition root; direct `Runtime` construction is explicit and testable.

## Input models

### OpenMode

```python
class OpenMode(StrEnum):
    OPEN = "open"
    RESUME = "resume"
    RESET = "reset"
```

`OPEN` opens an idle compatible Session or creates one, but never resumes an
interrupted operation. `RESUME` explicitly reconciles and resumes recoverable
work. `RESET` logically closes the prior Session and creates a clean identity.

### AgentRole

```python
class AgentRole(StrEnum):
    COORDINATOR = "coordinator"
    CAMPAIGN = "campaign"
    WORKER = "worker"
```

Roles affect universal topology rules only. Consumers attach no domain meaning
to the enum inside Runtime.

### SessionSpec

```python
class SessionSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    coordinator_template: str
    templates: tuple[AgentTemplate, ...]
    limits: RuntimeLimits = RuntimeLimits()
```

`name` is a bounded display/stable consumer key, not a filesystem path. Template
IDs are unique and the Coordinator template must exist with role `coordinator`.
The tuple is converted to a validated immutable internal TemplateCatalog.

### AgentTemplate

```python
class AgentTemplate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    role: AgentRole
    system_prompt: str
    allowed_children: frozenset[str] = frozenset()
    tools: frozenset[str] = frozenset()
    delegated_tools: frozenset[str] = frozenset()
    policy: AgentPolicy
    task_schema: dict[str, object]
```

The model may select only an `allowed_children` template ID and supply task data
validated against `task_schema`. It cannot provide prompts, tool names,
executables, environment values, or extension paths. The Runtime's Pi extension
is fixed infrastructure and is not a template field.

`tools` is the active trusted tool ceiling for that template, including selected
Pi and Runtime tools. `delegated_tools` is the separate ceiling from which a
direct child's active tools must be selected; it does not activate those tools
on the parent. This avoids granting a coordinating parent every coding tool it
may delegate.

### AgentPolicy

```python
class AgentPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    capabilities: frozenset[str] = frozenset()
    launch_cwd: Path
    environment_keys: frozenset[str] = frozenset()
    max_children: int = 0
    max_depth: int = 0
```

Environment values come from trusted consumer configuration at the composition
root; models see neither those values nor a way to add keys. `launch_cwd` is an
absolute initial workspace path, not a sandbox guarantee. Runtime resolves it
and performs filesystem/containment checks immediately before process creation.
Resource authority may be reduced for a child but never increased beyond
template, parent, and Session ceilings.

### RuntimeLimits

```python
class RuntimeLimits(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_campaigns: int = 3
    max_agents: int = 10
    max_children_per_agent: int = 3
    max_depth: int = 3
    max_concurrent_operations: int = 4
    max_message_bytes: int = 256 * 1024
    max_pending_rpcs: int = 32
    startup_timeout: float = 10.0
    rpc_timeout: float = 30.0
```

These are provisional ergonomic defaults, validated as positive and capped by
hard safety bounds. Depth counts parent/child edges from the Coordinator; the
default permits Coordinator → Campaign → Worker → child Worker. Runtime limits
are global ceilings. `AgentPolicy.max_children` and `max_depth` may only reduce
them for a specific subtree. More timeout fields are added only when
implementation tests show that one value cannot represent materially different
operations.

## Immutable snapshots

Public reads and method results return frozen snapshots rather than stateful
handles:

```python
class SessionSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    name: str
    status: SessionStatus
    coordinator_id: str


class AgentSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    session_id: str
    parent_id: str | None
    role: AgentRole
    status: AgentStatus
```

Snapshots never perform I/O and may become stale immediately. Callers request a
new snapshot rather than mutating a local proxy.

## Runtime methods

The stable consumer-facing methods are initially:

```python
await runtime.open_session(spec, mode) -> SessionSnapshot
await runtime.run(session_id) -> SessionSnapshot
await runtime.status(session_id) -> SessionSnapshot
await runtime.close_session(session_id) -> SessionSnapshot
```

`open_session()` prepares/reconciles state and starts the Coordinator according
to `OpenMode`. `run()` owns the foreground interactive lifetime. `status()` is a
bounded snapshot for consumer integration and tests. `close_session()` performs
the normal child-before-parent close and is idempotent.

Agent spawn, send, wait resolution, cancellation, and recovery exist as private
Runtime services invoked by authenticated runtime-tool handlers. They are not
promised as consumer API in version 1. Tests exercise them through internal
modules and tool/channel contracts rather than expanding the supported surface.

## Infrastructure protocols

The three public protocols are behavioral seams, not plugin discovery systems:

```python
class Store(Protocol):
    # Transactional persistence operations defined by storage contract tests.
    ...


class AgentLauncher(Protocol):
    async def start(self, spec: AgentProcessSpec) -> AgentProcessSnapshot: ...
    async def inspect(self, process_id: str) -> ProcessStatus: ...
    async def stop(self, process_id: str) -> None: ...


class AgentChannel(Protocol):
    async def start(self) -> ChannelEndpoint: ...
    async def send(self, agent_id: str, frame: OutboundFrame) -> None: ...
    async def close_agent(self, agent_id: str) -> None: ...
    async def close(self) -> None: ...
```

Exact Store methods are derived from transactional use cases and shared contract
tests rather than one oversized repository interface. Channel inbound frames are
delivered through a Runtime-owned callback/receive stream configured at startup;
the model cannot install handlers. Concrete initial classes are `SQLiteStore`,
`MemoryStore`, `PiProcessLauncher`, and `WebSocketAgentChannel`.

## Compatibility boundary

Only symbols re-exported from `arara_runtime` are public. Internal modules may
change without compatibility guarantees. Version 1 requires Session reset when
trusted templates, prompts, tools, or policies change; no catalog hash/version,
snapshot migration, or hot reload mechanism is added yet.

Public async methods raise `RuntimeFailure` for expected operational failures.
They do not translate native task cancellation, `KeyboardInterrupt`,
`SystemExit`, assertion failures, or unexpected programming defects. See
`errors.md`.
