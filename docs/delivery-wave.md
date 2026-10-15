# Current Delivery Wave

This record is the sole positive work-authorization authority. Authorization changes
only when merged into `main-v2`. Issues and pull requests coordinate work; proposed
records do not authorize their own execution. Preparing and reviewing an explicitly
owner-authorized Wave amendment does not perform the work it proposes to add.

## Authorized Advancements

### Lightweight Pre-Commit Hook

**Outcome:** Resolve [Issue #464](https://github.com/hcoona/microsoft-authentication-cli/issues/464)
so that the local pre-commit hook runs lightweight checks for ordinary commits.

**Delegated work:** Scope the slow `public-build-runner-conformance` pre-commit step
to its own inputs through hk configuration, with the applicable control and record
reviews. Keep every existing check and its CI execution unchanged; do not change a
control's invariant.

**External effects:** None beyond repository changes and ordinary CI.

**Completion:** Remove this entry through a reviewed Wave change once the fix merges
or the owner ends it.
