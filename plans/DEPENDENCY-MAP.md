# Rust dependency map

Status: proposed implementation choice.

This file maps the intended Rust ecosystem. It is not a canonical product
contract. Versions are pinned in the workspace manifest and updated only with
compatibility and behavior checks.

## Runtime foundation

| Concern | Preferred crate | Why | Replacement seam |
|---|---|---|---|
| Async runtime | tokio | Mature process, socket, timer, signal, and task support | Internal runtime services |
| Structured concurrency | tokio-util CancellationToken plus JoinSet | Explicit cancellation and bounded task ownership | Runtime task supervisor |
| Error definitions | thiserror | Stable typed internal errors without opaque context | Error module |
| Application diagnostics | anyhow | Context at binary boundaries only | CLI and process entrypoints |
| Data models | serde and serde_json | Stable serialization ecosystem and JSON diagnostics | Protocol codec |
| Identifiers | uuid | Opaque sortable-independent identities | Identity newtypes |
| Time | time | Explicit UTC values and formatting | Clock trait |
| Async traits | trait-variant where needed | Native async traits where possible, object-safe boundary only where required | Public internal traits |

## Persistence

| Concern | Preferred crate | Why | Replacement seam |
|---|---|---|---|
| SQL access and migrations | sqlx with SQLite | Compile-aware queries, explicit transactions, async integration | Store traits |
| Temporary local databases | tempfile | Isolated contract and crash tests | Test support only |
| Content hashing | sha2 | Artifact integrity and semantic digests | Digest service |

SQLite is the first Store implementation, not part of the public domain model.
SQLx queries remain inside the store crate. Domain crates never import SQLx.

## Protocol and transport

| Concern | Preferred crate | Why | Replacement seam |
|---|---|---|---|
| Schema | prost and prost-types | Language-neutral Protobuf contracts | Protocol package |
| RPC | tonic | Generated Rust and Python-compatible gRPC | Consumer and Driver transports |
| Local Unix transport | tonic native Unix-domain endpoint | Local process boundary without public TCP or a second connector stack | Transport factory |
| Streaming utilities | tokio-stream and futures | Bounded event streams and adapters | Transport internals |
| Framing for subprocess Driver | tokio-util codec | Bounded length-delimited frames | Driver transport |
| Private Driver control | standard UnixStream | Small synchronous bounded adapter with OS timeouts and no additional runtime coupling | `navigator-driver-client` |

`navigator-supervisor` depends directly on `navigator-driver-client` only at the
bootstrap boundary: the supervisor retains the opaque launch credential, opens
the authenticated channel, verifies the MAC-protected Start response and exact
Instance binding, and commits Ready before releasing the client handle to the
operation executor. `navigator-local` composes that attested handle; it never
receives or duplicates the bootstrap secret.

The fake Driver uses the local service, Consumer protocol, core, Store, and
supervisor only as development dependencies for the black-box vertical
contract. Its production boundary remains the generic Driver protocol.

The first supported platform is Unix-like. No Windows named-pipe design is part
of the initial plan.

## Process and system integration

| Concern | Preferred crate | Why | Replacement seam |
|---|---|---|---|
| Process launch | tokio process | Async child ownership and streams | Process supervisor |
| Unix signals | nix | Process groups, signals, and identity inspection | Platform supervisor |
| Unix child fd mapping | command-fds 0.3.3 | Audited fixed-fd mapping for dedicated ownership channels without workspace unsafe code | Platform supervisor |
| System inspection | sysinfo only if native APIs are insufficient | Portable observation, never sole strong identity proof | Platform inspection |
| Secret comparison | subtle | Constant-time comparison of authentication material | Auth module |
| Secret containers | secrecy and zeroize | Reduce accidental formatting and lingering memory | Credential types |

## Policy and validation

| Concern | Preferred crate | Why | Replacement seam |
|---|---|---|---|
| JSON Schema | jsonschema | Validate untrusted task and Tool input | Schema validator |
| URL and path parsing | url and camino | Typed normalized inputs | Boundary validation |
| Capability sets | typed newtypes plus standard collections | Avoid a policy DSL before needed | Policy engine |

No general-purpose policy engine is planned initially. Policy remains explicit
Rust logic with table-driven tests.

## Observability

| Concern | Preferred crate | Why | Replacement seam |
|---|---|---|---|
| Structured instrumentation | tracing | Spans and events across async boundaries | Telemetry facade |
| Subscriber configuration | tracing-subscriber | JSON or human-readable local output | Binary composition |
| Metrics | metrics facade | Backend-neutral counters and histograms | Optional exporter |

Durable Navigator Events remain separate from diagnostic tracing.

## CLI and configuration

| Concern | Preferred crate | Why | Replacement seam |
|---|---|---|---|
| CLI | clap | Typed, documented local lifecycle commands | Binary only |
| Config files | figment | Layered trusted configuration without ambient magic | Composition root |
| Secure file permissions | rustix | Explicit Unix file and socket permissions | Platform module |

## Testing

| Concern | Preferred crate | Why |
|---|---|---|
| Assertions | pretty_assertions | Readable contract diffs |
| Property tests | proptest | Transition and message invariant exploration |
| Snapshot tests | insta | Stable protocol and event projections |
| Async fault control | turmoil where applicable, otherwise injected fakes | Deterministic network and timing faults |
| Test parameterization | rstest | Store and Driver contract suites |
| Coverage | cargo-llvm-cov | Workspace coverage evidence |
| Lints | clippy and rustfmt | Repeatable quality gate |
| Dependency policy | cargo-deny | Licenses, duplicate versions, advisories, sources |
| Unused dependencies | cargo-machete | Keep crate boundaries lean |

## Python SDK

The Python SDK uses generated gRPC and Protobuf clients beneath an idiomatic
async wrapper. Preferred Python dependencies are grpcio, protobuf, anyio, and
pydantic. The SDK does not embed Rust through native Python bindings.

## TypeScript Driver protocol bindings

| Dependency | Exact version | Why |
|---|---:|---|
| `@bufbuild/protobuf` | 2.10.2 | Protobuf runtime used by generated TypeScript bindings |
| `@bufbuild/protoc-gen-es` | 2.10.2 | Deterministic generation from the canonical Driver schema |
| `typescript` | 5.9.3 | Strict compatibility check for bindings and fixtures |
| `tsx` | 4.20.6 | Executes golden round-trips without emitted build artifacts |

The TypeScript dependencies remain isolated under the Driver protocol package.
Verification uses `npm ci --ignore-scripts` in a temporary directory.

## Pi Driver

Pi is implemented in its native TypeScript and Node ecosystem behind the Driver
protocol. Its dependencies are isolated from Rust workspace crates. The Driver
pins an exact validated Pi SDK version and contains no Navigator domain state.

## Rejected as defaults

- PyO3 as the primary Consumer boundary: couples lifetime and failure domains.
- WebSocket as the universal protocol: transport choice would leak into domain.
- an ORM: obscures explicit transactions and invariants.
- an event broker: unnecessary before distributed deployment.
- a workflow DSL: policy requirements are not yet general enough.
- dynamic plugin loading in the core: expands trust and compatibility surface.
