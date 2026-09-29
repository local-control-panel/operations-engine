# Implementation plan index

This directory contains historical execution plans. It is not the active
backlog; current priority and remaining work live in
[`../../../PLAN.md`](../../../PLAN.md).

Unchecked boxes inside an archived plan preserve the sequence originally given
to implementers. They do not mean that the delivered feature is incomplete.
Use the status in this index and at the top of each plan.

| Plan | Repository status | Notes |
| --- | --- | --- |
| [`2026-09-03-engine-install-rollback.md`](2026-09-03-engine-install-rollback.md) | Completed; archived | Engine implementation, tests, workflow, and docs delivered. Production-key rotation, first release, external integration, and rollout remain in the active roadmap. |
| [`2026-09-03-ingress-config-activation-pilot.md`](2026-09-03-ingress-config-activation-pilot.md) | Completed; archived | General engine primitive and the scoped pilot shipped. Further callers require separate milestones. |
| [`2026-09-05-ops-engine-maintenance-mode.md`](2026-09-05-ops-engine-maintenance-mode.md) | Completed for `operations-engine`; archived | Engine-side target selection and park/unpark shipped. Check the control-panel repository for its own integration state. |

When adding a plan:

1. add it here with status `proposed`, `active`, `completed`, or `superseded`;
2. state its repository scope explicitly;
3. update the status at the top of the plan and in this index together;
4. move durable outcomes to the active roadmap or an architectural decision;
5. archive the plan when its in-repository scope is complete.
