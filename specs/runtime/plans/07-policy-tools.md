# Vertical 07 — Policy, tools, and authority

## Outcome

All planned orchestration tools are available according to role and immutable
template policy, with auditable non-escalation across descendants.

## End-to-end proof

Coordinator manages Campaigns, Campaign manages Workers, and an eligible Worker
creates a child Worker. Each sees only its allowed Runtime and coding tools. An
attempt to exceed path, environment, template, or capability authority fails
before an external effect.

## Scope

- complete generic tools: spawn, send, children, status, cancel, and resume;
- conditional approval-request tool integration point;
- per-role and per-template tool allowlists;
- capability intersection across Session, template, parent, and request;
- bounded trusted environment-key delegation;
- launch workspace validation and post-effect change inspection hooks;
- immutable tool schemas and safe result projection;
- audit events around tool intent, decision, execution, and result.

## Invariants

- child authority is never greater than every applicable ceiling;
- caller Agent identity comes from its authenticated channel, never arguments;
- models cannot select arbitrary executable, prompt, extension, or environment;
- Bash cwd is not represented as a security sandbox;
- policy failure occurs before process/filesystem/network effects where possible;
- a tool result cannot forge Runtime lifecycle events.

## Acceptance

- role/tool matrix for Coordinator, Campaign, Worker, and child Worker;
- every capability-escalation combination is rejected;
- environment allowlist does not leak values into messages or logs;
- unsafe workspace/path traversal and symlink cases fail;
- post-effect diff hook catches out-of-scope changes;
- forged caller IDs and result/report IDs fail;
- tool schema fuzzing cannot add unknown authority fields.

## Adversarial review

- give a Worker the most powerful planned tool set and enumerate escape paths;
- inspect Bash, subprocess environment, symlinks, and same-user process access;
- challenge whether each capability is preventive or only detective;
- ensure consumer-specific validation gates remain outside Runtime;
- review approval boundary before enabling approval-request tool.

## Excluded from this slice

Strong OS sandboxing, remote secrets, domain-specific tools, and publication
policy.
