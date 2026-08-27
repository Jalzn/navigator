---
status: verified
slice: 01-durable-session
depends_on:
  - plans/00-foundation/00-slice.md
specs:
  - docs/domain-model.md
  - docs/execution.md
---

# Slice: Durable Session

## Outcome

A local Consumer can open, inspect, close, and reopen a Session. Two Navigator
hosts cannot mutate it concurrently.

## Demonstration

Start one host, create a Session, start a competing host, observe a fenced
ownership failure, stop the first host, advance time, and safely acquire a new
epoch without losing history.

## Exit gate

Session lifecycle, SQLite transactions, ownership renewal, lease loss, schema
validation, and crash tests are verified.
