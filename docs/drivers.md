# Driver contract

## Purpose

A Driver adapts one Executor technology to Navigator. Drivers may be implemented
in any language and connected through any conforming transport.

The contract is capability-based. Navigator asks what a Driver can prove and
uses only supported behavior.

## Required operations

Every Driver provides semantic equivalents of:

- describe: identify Driver version, protocol range, and capabilities;
- start: establish an Instance from trusted configuration;
- inspect: report verifiable Instance and connection state;
- deliver: accept one Message with stable identity;
- cancel: request cancellation of one Operation;
- stop: stop one verified Instance;
- events: emit lifecycle, acceptance, and Operation reports.

Names and wire shapes may differ by SDK. Semantics do not.

## Capabilities

Capabilities are versioned identifiers. Examples include:

- durable acceptance;
- streaming output;
- delivery during active execution;
- persistent native Session;
- pause and resume;
- interactive terminal;
- tool invocation;
- graceful cancellation;
- verifiable process identity;
- artifact transfer.

A capability may include parameters or limits. Capability absence is normal and
`[NAV-ADAPTER-001]` MUST NOT be simulated with a weaker guarantee.

Navigator validates required capabilities before creating external effects.

## Identity and authentication

Navigator assigns Participant and launch-attempt identity. The Driver binds them
to an Instance through a trusted bootstrap channel.

An Executor cannot select or override its Navigator identity through untrusted
task data. Authentication credentials are scoped, revocable, bounded in
lifetime, and excluded from logs and public Events.

## Trusted and untrusted configuration

Trusted configuration may include executable identity, base instructions,
allowed tools, environment-key allowlists, workspace, and resource limits.

Untrusted task input is separately schema-validated. It cannot introduce
executables, extensions, credentials, trusted prompts, new tools, or authority.

## Acceptance

The Driver acknowledges a Message only after reaching the advertised durability
boundary for that exact Message identity. Receipt by a socket handler or return
from a non-awaitable native method is insufficient.

After reconnect, the Driver can determine whether an uncommitted delivery
identity was previously accepted, or it reports unknown.

## Lifecycle signals

Native signals are translated conservatively:

- ready means the bound Instance may accept supported work;
- idle means no native activity is currently observed;
- disconnected means communication was lost;
- stopped means the verified Instance ended;
- report means the Participant explicitly declared an Operation outcome.

Idle or settled never implies success.

## Ownership loss

A managed Driver stops accepting work after bounded loss of the owning
Navigator connection or lease. Where possible it causes managed Executors to
self-terminate. Failure to prove termination becomes cleanup required or
uncertain, never silent success.

## Driver isolation

Drivers cannot access Navigator storage directly. They receive only scoped
Commands and publish bounded Events. A Driver failure is isolated from the
control plane process where the deployment supports it.

## Conformance

A Driver is conforming only if it passes contract tests for identity,
capability negotiation, delivery deduplication, disconnect windows, bounded
input, cancellation, lifecycle translation, and ownership loss.

Adapter-specific tests additionally prove the native Executor behavior on every
platform the Driver claims to support.
