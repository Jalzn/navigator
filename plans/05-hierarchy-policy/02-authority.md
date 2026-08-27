---
status: verified
slice: 05-hierarchy-policy
depends_on:
  - plans/05-hierarchy-policy/01-topology.md
specs:
  - docs/policy-security.md
---

# Task: Enforce non-escalating authority

## Outcome

Compute effective capabilities from Session, parent delegation, Template,
relationship policy, and Grants.

## Implementation

- Use typed capabilities and resource scopes.
- Separate active tools from delegable tools.
- Check authority at child creation and again at effect time.
- Record redacted denial Events.
- Make model-controlled fields incapable of naming new authority.

## Verification

- Table-driven lattice tests prove every intersection.
- Child cannot delegate a capability it cannot delegate.
- Parent need not actively possess every tool it may delegate.
- Expiry and revocation take effect before the next privileged action.

## Done

Every delegated capability has an explainable trusted origin.
