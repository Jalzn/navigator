# Vertical 03 — Interactive Coordinator

## Outcome

The user opens one foreground Runtime command and converses with a Coordinator
whose identity and Pi transcript persist according to the Session policy.

## End-to-end proof

A minimal example consumer starts Runtime, opens the Coordinator TUI, exchanges
a faux-provider message, requests Runtime status, and exits. Runtime closes all
owned resources and records the final Session state.

## Scope

- `run_session()` composition root;
- open/create, explicit `--resume`, and logical `--reset` modes;
- Coordinator template validation and process registration;
- foreground signal handling and terminal ownership;
- Coordinator status tool and safe operational summaries;
- persistent Pi Session identity for Coordinator;
- structured file logging without competing with the TUI;
- ordered child-before-parent shutdown, even though no child is created yet.

## Invariants

- exactly one Coordinator per Session;
- only Coordinator communicates directly with the user;
- default open never resumes an interrupted operation;
- Pi new/fork/switch cannot silently replace Runtime Agent identity;
- Coordinator exit closes the foreground Runtime;
- reset preserves prior audit history while creating clean operational identity.

## Acceptance

- fresh open, reopen idle, explicit resume refusal when unsafe, and reset;
- `SIGINT`, double `Ctrl-C`, EOF, and Coordinator process exit;
- startup failure at Store, channel, spawn, and handshake boundaries;
- no orphan process after each failure;
- status is available through the conversation without an admin command tree;
- log records correlate Session, Agent, process, and operation IDs.

## Adversarial review

- attempt a second Coordinator and Session switching from inside Pi;
- change template/tool policy and verify reset is required;
- inspect terminal corruption under logs and errors;
- ensure consumer environment values never enter specs or logs;
- challenge whether Coordinator transcript persistence duplicates Runtime state.

## Excluded from this slice

Campaign creation, Worker tools, mailbox concurrency, approvals, and publication.

