# Consumer API

## Purpose

Consumer SDKs make Navigator natural to use from an application while retaining
language-neutral semantics. An SDK may manage a local Navigator process or
connect to an existing instance.

The API is asynchronous by default. Synchronous wrappers, when provided, are
thin boundaries and do not define separate behavior.

## Resource groups

A complete SDK exposes semantic groups for:

- Sessions;
- Participants;
- Operations;
- Messages;
- Artifacts;
- Events;
- approvals and Grants;
- consumer-provided Tools.

SDKs return immutable snapshots. They do not expose mutable remote objects whose
local fields pretend to be authoritative.

## Opening a Session

A Consumer supplies a Session specification containing a stable consumer key,
root Template, immutable Template catalog, policy, and limits.

Open modes have these meanings:

- open: open an idle compatible Session or create one; never resume interrupted
  work implicitly;
- resume: reconcile, then continue only work classified as safe;
- reset: logically close the previous Session and create a clean identity.

Reset does not physically erase audit history.

## Starting work

Starting an Operation requires Participant identity, bounded input, and a stable
request or idempotency identity. The result is an immutable Operation snapshot
plus an Event subscription or query path.

Repeated equivalent requests return the committed result or current Operation.
Repeated identity with different semantic input fails with conflict.

## Observing work

Consumers can query snapshots and subscribe to Events from a known position.
Disconnect and replay are normal. SDKs expose typed Event variants and preserve
unknown optional fields for compatible evolution where practical.
Bounded `ReadEvents` polling remains available after ownership release (subject
to authenticated negotiation/consumer binding); live `SubscribeEvents` stays
ownership-bound and fails with stale ownership after release.

## Cancellation and resolution

Cancellation returns the committed cancellation request state, not a false
promise of immediate termination.

An uncertain Operation exposes its classification and allowed resolution
actions. Resolving uncertainty is explicit, authorized, audited, and
effect-specific.

## Consumer-provided Tools

A Consumer may register a Tool handler with:

- stable name and version;
- input and output schema;
- required authority;
- timeout and cancellation behavior;
- effect classification;
- idempotency contract.

Navigator persists Tool invocation identity before calling the handler. Handler
availability is transient; pending work survives Consumer disconnection.

Effect classes are:

- read only: no externally visible mutation;
- idempotent: repeated invocation with the same identity is safe;
- transactional: external system provides commit or idempotency proof;
- non-idempotent: repetition may create another effect;
- unknown: no safe assumption is possible.

## Failures

Public failures have a stable machine code, human message, retry classification,
related identity where safe, and redacted structured details.

Programmer errors and native cancellation are not disguised as domain failures.
SDKs map transport-specific errors into stable Navigator failures only when the
mapping is unambiguous.

## Illustrative Python shape

    async with Navigator.local(data_dir=path) as navigator:
        session = await navigator.sessions.open(spec, mode=\"open\")
        operation = await navigator.operations.start(
            participant_id=session.root_id,
            input={\"task\": \"investigate\"},
            request_id=\"consumer:job-42:v1\",
        )

        async for event in navigator.events.subscribe(
            session_id=session.id,
            after=last_position,
        ):
            handle(event)

This example defines ergonomics, not a required package or method spelling.

## Local and remote equivalence

Changing from a managed local instance to a remote Navigator changes connection
configuration only. Resource semantics, identities, errors, and lifecycle do
not change.
