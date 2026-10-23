# Enrolling and remediating with one attended command (0.2.18 candidate)

Filed 2026-10-23. Status: direction only, nothing designed or built.

## Goal

Today a new or changed device takes a chain of commands that each person
must remember and run in the same order: `device discover`, `device scan`,
the host-key question, `device add`, `device config pull`, `diff`, `plan`,
`apply`. With several people using tacctl and devices changing often, the
chain drifts. The goal is one command per job that runs the whole chain
for the addresses or devices named, asks the few questions that need a
person, and ends at a sign-off.

## Boundary

Every run is started by a person at a terminal and every device login is
that person's own, with the password asked once and never kept. Nothing is
scheduled, nothing runs unattended and no credential is stored. The
sign-offs stay: the host keys are shown and accepted by a person, and a
change is committed only after the review is answered. A command that
cannot reach its sign-off without a terminal refuses, as `device onboard`
and `device apply` do today.

## Scope: Junos first

Junos is the only vendor with a write path (`device config apply`,
`device onboard`, `device collect`). IOS, IOS-XE and WTI keep paste-ready
plans, so for them the chain ends at the plan. Vendor detection
(`vendor-detection.md`, D260 in the 0.2.17 plan) is the step that lets a
chain choose the path from the device.

## What exists

- `device collect --discovered [--register]`: reads unregistered
  addresses, shows their host keys for one question, registers them
  pinned and keeps the read as the first pull record.
- `device onboard`: a blank device reached with a local account, first
  configuration committed and proven by the operator's own login.
- `device config apply <names>|--all|--scope|--vendor|--stale`: the
  review grouped by shape, one question, a commit under `commit
  confirmed` per device with a fresh-login proof, a canary per shape and
  `--max`. Mass remediation of Junos devices is therefore built; what
  is missing is the selection ("the devices that differ") and the chain
  in front of it.

## Decisions (2026-10-23)

- The verb is `device enroll`. It asks at the end: after the plan it
  offers the apply review (Junos), and answering no leaves the device
  registered and pulled with the plan printed.
- The selectors of the config verbs grow. `device config
  pull|diff|plan|apply` take, besides names, `--all`, `--scope`,
  `--vendor` and `--stale`: `--differs` (the devices whose last pull
  record differs from today's rendering, as `device config list
  --differs` computes it, with no login), `--name <text>` and `--ip
  <addr|cidr|text>` (as `device list` takes them, comma lists included).
  All of the filters combine; names and `--all` still stand alone. The
  apply re-checks every selected device on the device itself, so a stale
  record can only select too many, never apply a change nobody reviewed.
  `device config list` takes the same filters.
- `--differs` with `--pull` pulls the selected devices first, so the
  selection is made on fresh records. The chain that pulls, selects the
  devices that differ and hands them to the apply review is these flags
  on `device config apply`, with every filter above; there is no verb of
  its own.

## Candidates

1. **`device enroll`** (working name): addresses from the arguments or
   from `device discover`; scan, one host-key question for all, vendor
   and name from the device (D260) with a question for what cannot be
   read, register, pull, and print the plan (Junos: and offer the apply
   review). Replaces the remembered chain for the common case.
2. **A remediation selection** for the config verbs: `--differs`,
   `--name` and `--ip` beside the existing selectors (see Decisions),
   and `--pull` on `apply`, which pulls the selected devices first and
   hands those that differ to the apply review. The apply's own review,
   canary and proof stay as they are.
3. **Consistency for several operators:** the same prompts and defaults
   for every person; the audit lines of the 0.2.17 release record who
   ran the chain (`sid=` ties the steps together).

## Open

- Which questions a run asks once for many addresses (host keys) and
  which it asks per device.
