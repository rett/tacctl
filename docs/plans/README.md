# Plans

The plans, handoffs and lab results of work that is current. A plan of a
released version is removed when the release is done; its decisions
(`D<n>`), work packages and lab findings are in git, and the code and tests
cite them by number and file name.

## Current

| File | What it is |
|---|---|
| `backlog.md` | The roadmap (section 0) and the open items |
| `0.2.12-handoff.md` | State, candidates and working rules for 0.2.12 |
| `0.2.11-plan.md` | The apply lock (D152-D158) |
| `0.2.11-lab.md` | NETCONF limits and a competing commit: run sheets |
| `0.2.10-plan.md` | NETCONF service setting and apply over NETCONF (D145-D151) |
| `0.2.10-lab.md` | Junos NETCONF lab results the code cites |
| `0.2.9-rollout-plan.md` | Apply and onboard over the Junos CLI (D128-D144) |
| `0.2.9-lab.md` | Junos apply lab results the code cites |
| `0.2.9-conversion.md` | Map from the helper script to the 0.2.9 verbs |
| `0.2.9-execution.md` | Work packages of 0.2.9 |
| `apply-deferred.md` | NETCONF apply and rollback, deferred (D77-D93) |
| `asa-deferred.md` | Cisco ASA, deferred |
| `0.2.3-baseline-design.md` | The command-rule baseline the open lab items test |
| `0.2.4-spike.md` | Device spike results the active plans rest on |
| `0.2.5-lab.md` | Junos apply and plan lab results the active plans rest on |
| `wti-interface.md` | The WTI units' menus and levels |

## Removed plans

Every earlier plan is in the `0.2.7` tag. Read one with, for example:

```
git show 0.2.7:docs/plans/0.2.5-plan.md
```

`0.2.2-plan.md` (D1-D28), `0.2.3-plan.md` (D29-D59), `0.2.4-plan.md`
(D60-D76), `0.2.5-plan.md` (D94-D127), `0.2.5-operator-audit.md` (the
operator's command audit), `0.2.7-blocks-plan.md`, `0.2.4-handoff.md`
(working rules, gates), the `go-rewrite*.md` set, `operator-console*.md` and
`pluggable-backends.md`.
