# Slice 01 implementation decisions

These decisions resolve implementation ambiguity without changing the canonical
specifications.

- Reopening means opening the durable Session for inspection after a process
  restart. A logically closed Session remains closed and cannot accept work.
- Creating a Session commits revision 1 and Event position 1. Revision and Event
  position remain distinct counters after creation.
- Repeating an equivalent mutable request returns its committed result without a
  new revision or Event. Reusing its identity with different semantics conflicts.
- Closing an already closed Session returns its committed closed snapshot when
  the request is equivalent; a new close request reports `AlreadyClosed`.
- A lease is expired when observed wall time is equal to or later than its
  deadline. A persisted time floor prevents clock regression from resurrecting
  authority.
- Logical close releases ownership atomically while preserving the epoch high
  water mark.
- Ownership acquisition and release are observable Events and advance revision;
  renewal is internal and changes neither.
- Reading Events after a position beyond the current head returns an empty page.
