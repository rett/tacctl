# Plans

What is not done yet. A plan, handoff, lab sheet or spike of work that is
implemented is removed in the release that ships it; its decisions (`D<n>`),
work packages and lab findings stay in git, and the code and tests cite them
by number and file name.

| File | What it is |
|---|---|
| `0.2.23-plan.md` | The 0.2.23 release in progress (D296-D311) |
| `backlog.md` | The roadmap (section 0) and the open items |
| `apply-deferred.md` | NETCONF apply and rollback, deferred (D77-D93) |
| `asa-deferred.md` | Cisco ASA, deferred |
| `wti-interface.md` | The WTI units' menus and levels (a reference) |

## Removed plans

Every removed plan is in the `0.2.18` tag. Read one with, for example:

```
git show 0.2.18:docs/plans/0.2.17-plan.md
```

The release plans `0.2.3` to `0.2.18` (`D29` to `D277`), their handoffs, lab
sheets and spikes, `0.2.3-baseline-design.md`, `0.2.9-conversion.md`,
`0.2.9-execution.md`, `0.2.16-options.md`, `enroll-workflow.md` and
`vendor-detection.md` are there. The earlier ones (`0.2.2-plan.md`, the
`go-rewrite*.md` set, `operator-console*.md`, `pluggable-backends.md`) are in
the `0.2.7` tag.
