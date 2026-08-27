# Dependency decisions

Every transversal mechanism must begin with a comparison of the standard
library and maintained libraries. Adoption considers semantic fit, maintenance,
portability, operational services, transitive surface, and exit cost—not only
lines of code saved.

## Adopt: AnyIO 4

Purpose:

- structured task groups;
- cancellation scopes and shielded cleanup;
- timeouts;
- async subprocess and synchronization primitives;
- capacity limiters;
- async test support.

Runtime version 1 uses the asyncio backend. AnyIO avoids baking raw event-loop
management throughout public code. It does not imply support for every backend.

## Adopt: Pydantic 2

Purpose:

- strict validation at persistence, launcher, and channel boundaries;
- versioned public models;
- bounded/forbidden extra fields;
- reliable JSON parsing and serialization.

Internal ephemeral values may use frozen dataclasses. Pydantic is not an ORM and
does not define domain transitions.

## Adopt: aiosqlite

Purpose:

- async access to SQLite;
- transactional Store operations without blocking the event loop;
- cross-platform durable mailbox/state implementation.

No connection pool or ORM is planned initially. Transactions remain explicit.

## Adopt: psutil

Purpose:

- inspect runtime-owned process descendants across platforms;
- defend against PID reuse using process identity and creation time;
- implement bounded terminate/wait/kill for owned process trees;
- avoid separate fragile Windows and POSIX tree-walking implementations.

AnyIO remains responsible for async subprocess I/O and cancellation scopes.
Potentially blocking psutil operations run through AnyIO's thread boundary.
Only Runtime-launched Pi process trees are within psutil ownership.

## Adopt: Rich

Purpose:

- render the foreground Runtime event feed;
- format structured standard-library logging events;
- provide safe live updates without corrupting Coordinator terminal output.

Rich is a renderer only. Store events remain authoritative. Textual is not
adopted because version 1 needs a feed rather than a full TUI. structlog remains
unnecessary because events are already structured records.

## Do not adopt initially: filelock

It was considered for a JSON `FileStore`. `SQLiteStore` removes the main need for
cross-process document locks. Artifact writes use atomic filesystem primitives
and database-coordinated metadata.

## Do not adopt initially: scheduler libraries

AnyIO task groups and capacity limiters cover local concurrency and waiting.
APScheduler targets calendar/interval scheduling; its v4 line was still marked
pre-release during this design. Version 1 has no cron or timed job requirements.

## Adopt: websockets 17

Purpose:

- host the loopback WebSocket AgentChannel in the foreground Runtime Host;
- provide focused asyncio WebSocket lifecycle and framing;
- provide bounded messages and receive queues, ping/pong keepalive, timeouts,
  backpressure, and graceful shutdown;
- avoid carrying a general HTTP application stack when no HTTP API exists.

The Runtime uses the modern `websockets.asyncio` API, not the deprecated legacy
implementation. AnyIO runs on its asyncio backend in version 1. The server binds
to loopback on an ephemeral port and accepts only the small authenticated runtime
protocol. The Pi extension should use the WebSocket client available in the
supported Node.js runtime when verified, avoiding a second JavaScript networking
dependency.

`aiohttp` is not adopted because version 1 has no routes, middleware, REST API,
or HTTP client requirement. Reconsider only if a real HTTP surface appears.

## Do not adopt initially: distributed queues

Dramatiq and Taskiq provide brokers, workers, retries, acknowledgements, and
dead-letter behavior. They introduce Redis/RabbitMQ or another broker plus a
second worker lifecycle alongside Pi. Reconsider when Agents must execute
across machines or independent services.

## Do not adopt initially: durable workflow platforms

Hatchet/Temporal-style systems provide valuable durable execution and replay but
require service infrastructure and deterministic workflow semantics. Reconsider
when automatic recovery, long waits without a resident process, distribution,
or operational dashboards become requirements.

## Do not adopt initially

- Tenacity: retry authority/idempotency must stay explicit.
- structlog: Store events plus standard logging are enough initially.
- state-machine packages: transitions are small and invariant-specific.
- SQLAlchemy/ORM: direct small SQL schema is easier to audit initially.
- agent frameworks: Pi already provides the agent execution substrate.
- event brokers: the mailbox is internal and SQLite-backed.

## Provisional dependencies

```toml
dependencies = [
  "anyio>=4,<5",
  "aiosqlite>=0.20,<1",
  "pydantic>=2,<3",
  "psutil>=7,<8",
  "rich>=14,<15",
  "websockets>=17,<18",
]
```

Exact minimum versions must be selected from APIs actually used and locked by
the workspace. Broad version bumps are not part of runtime implementation.
