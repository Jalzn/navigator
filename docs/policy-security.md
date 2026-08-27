# Policy and security

## Trust boundaries

Trusted:

- Consumer configuration entering through an authenticated administrative
  boundary;
- immutable Templates and policy;
- Navigator control-plane identity;
- explicit decisions from an authenticated approval authority.

Untrusted:

- model output;
- Executor messages and tool arguments;
- task input;
- Driver network input before authentication;
- artifact paths and metadata supplied externally;
- process identifiers without corroborating identity evidence.

## Authority model

Authority is capability-based and scoped to Session, subject, action, resource,
and time where applicable.

Effective authority is the intersection of all applicable ceilings. A child may
receive less authority than its parent but never more. Delegable authority is
distinct from authority the parent may exercise directly.

Every privileged action is checked at effect time, not only when planned.

## Templates

Templates form the trusted ceiling for Executor behavior. Untrusted input cannot
select an unregistered Template, alter trusted instructions, add tools, expand
environment access, or bypass topology constraints.

Templates are immutable within a compatible Session.

## Authentication

Every Consumer, Driver, and Instance connection is bound to an authenticated
identity. Authentication material is scoped to its purpose and never accepted
from model-controlled arguments.

Replay, expired credentials, identity mismatch, and protocol downgrade fail
closed.

## Approvals

Executors may request approval but cannot approve themselves. Approval decisions
enter through a trusted Consumer or user channel.

Grants are narrow, expiring, revocable, and auditable. Approval of one request
does not create a permanent general capability.

## Process ownership

Navigator supervises only Instances it launched or safely adopted. Termination
requires corroborated identity such as launch attempt, process creation
evidence, executable identity, parentage, or a platform-native ownership handle.

An ambiguous live process is not killed merely because its numeric identifier
matches an old record.

## Filesystem and execution

A launch workspace is an initial location, not confinement. Tool allowlists
limit exposed interfaces but do not sandbox unrestricted code. Strong isolation
requires an actual platform boundary such as a container, virtual machine,
sandbox, separate operating-system identity, or mediated tool service.

Navigator reports the enforcement level that exists.

## Secrets

Secrets remain in trusted memory or dedicated secret systems and are delegated
only to authorized Instances. They are excluded from Session specifications,
Messages, Events, snapshots, errors, logs, and Artifacts.

Environment delegation uses named allowlists with values supplied through a
trusted boundary. Ambient environment inheritance is not assumed.

## Artifacts

Artifact access is scoped and all locations are resolved beneath an owned root.
Implementations validate size, media type where relevant, hash, traversal,
symlink behavior, and atomic publication.

## Denial-of-service controls

Navigator enforces bounds on participants, depth, concurrent work, message and
artifact size, pending requests, subscriptions, retry attempts, timeouts, and
retained history. Limit failures are explicit and do not partially expand
authority.

## Audit

Security-relevant decisions emit redacted durable Events, including denied
actions, grants, policy changes at Session boundaries, ownership changes,
forced termination, uncertainty resolution, and deletion authorization.

Audit history is not deleted implicitly.
