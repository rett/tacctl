package cli

// 'device config shapes' (docs/plans/0.2.9-rollout-plan.md D135): the
// shapes of the changes 'device config apply' has seen, which of them a
// verified apply confirmed, and 'seed', a person's word that a device's shape
// was applied and verified by other means. Nothing here contacts a device;
// the store is /var/lib/tacctl/device-apply/shapes.json.

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devapply"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/ui"
)

// shapeState is the word of a shape's standing.
func shapeState(e devapply.ShapeEntry) string {
	seeded, proven := 0, 0
	for _, c := range e.Confirmed {
		if c.Seeded {
			seeded++
		} else {
			proven++
		}
	}
	switch {
	case proven > 0:
		return "confirmed"
	case seeded > 0:
		return "seeded"
	}
	return "new"
}

// shapeDevices are the devices that confirmed a shape, once each, in the
// order of their first confirmation.
func shapeDevices(e devapply.ShapeEntry) []string {
	var out []string
	for _, c := range e.Confirmed {
		if !slices.Contains(out, c.Device) {
			out = append(out, c.Device)
		}
	}
	return out
}

// nearestShape names the confirmed shape whose lines differ least from a new
// one's (the symmetric difference of the line sets), "" when none is
// confirmed.
func nearestShape(m map[string]devapply.ShapeEntry, hash string) (string, int) {
	mine := map[string]bool{}
	for _, l := range m[hash].Lines {
		mine[l] = true
	}
	best, bestN := "", -1
	for h, e := range m {
		if h == hash || len(e.Confirmed) == 0 {
			continue
		}
		theirs := map[string]bool{}
		for _, l := range e.Lines {
			theirs[l] = true
		}
		n := 0
		for l := range mine {
			if !theirs[l] {
				n++
			}
		}
		for l := range theirs {
			if !mine[l] {
				n++
			}
		}
		if bestN < 0 || n < bestN || (n == bestN && h < best) {
			best, bestN = h, n
		}
	}
	return best, bestN
}

// shapeJSON is one shape in --json.
type shapeJSON struct {
	Shape     string          `json:"shape"`
	State     string          `json:"state"`
	Devices   []string        `json:"devices"`
	Confirmed []shapeConfJSON `json:"confirmed"`
	Lines     []string        `json:"lines,omitempty"`
	Count     int             `json:"line_count"`
	Nearest   string          `json:"nearest,omitempty"`
	Differing int             `json:"nearest_differs,omitempty"`
}

type shapeConfJSON struct {
	Device string `json:"device"`
	At     string `json:"at"`
	By     string `json:"by"`
	ID     string `json:"id,omitempty"`
	Seeded bool   `json:"seeded,omitempty"`
}

// deviceConfigShapes is 'device config shapes [list|seed]'.
func (inv *invocation) deviceConfigShapes(args []string) error {
	p, err := inv.deviceConfigParse("shapes", args)
	if err != nil {
		return err
	}
	if err := inv.deviceConfigAllowed("shapes"); err != nil {
		return err
	}
	usage := "Usage: tacctl device config " + deviceConfigUse("shapes")
	sub, rest := "list", p.Args
	if len(rest) > 0 && (rest[0] == "list" || rest[0] == "seed") {
		sub, rest = rest[0], rest[1:]
	}
	switch {
	case sub == "list" && len(rest) > 0:
		return inv.argErr("'shapes list' takes no name: '"+rest[0]+"'. Seed a device with: tacctl device config shapes seed <name>", usage)
	case sub == "list" && p.Has("-y"):
		return inv.argErr("-y answers the question of 'shapes seed'; 'shapes list' asks none.", usage)
	case sub == "seed" && (p.Has("--show") || p.Has("--json")):
		return inv.argErr("--show and --json are for 'shapes list'.", usage)
	}
	if sub == "seed" {
		return inv.deviceConfigSeed(p, rest)
	}
	return inv.deviceConfigShapesList(p)
}

// deviceConfigShapesList is 'shapes list'.
func (inv *invocation) deviceConfigShapesList(p Parsed) error {
	st := devapply.OpenShapes(inv.app.Paths.ApplyDir)
	m, err := st.Load()
	if err != nil {
		return err
	}
	// where each device stands now, from its record (no device is contacted)
	recs, _ := inv.configStore().Load()
	at := map[string][]string{}
	for _, n := range recs.Names() {
		if r, ok := recs.Of(n); ok && r.Applied != nil && r.Applied.Shape != "" {
			switch r.Applied.Result {
			case devconf.AppliedChecked, devconf.AppliedApplied:
				at[r.Applied.Shape] = append(at[r.Applied.Shape], n)
			}
		}
	}
	hashes := make([]string, 0, len(m))
	for h := range m {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	objs := func(hs []string, withLines bool) []shapeJSON {
		out := []shapeJSON{}
		for _, h := range hs {
			e := m[h]
			j := shapeJSON{Shape: h, State: shapeState(e), Devices: append([]string{}, at[h]...), Confirmed: []shapeConfJSON{}, Count: len(e.Lines)}
			if withLines {
				j.Lines = e.Lines
			}
			for _, c := range e.Confirmed {
				j.Confirmed = append(j.Confirmed, shapeConfJSON{Device: c.Device, At: c.At.UTC().Format(time.RFC3339), By: c.By, ID: c.ID, Seeded: c.Seeded})
			}
			if j.State == "new" {
				j.Nearest, j.Differing = nearestShape(m, h)
				if j.Nearest == "" {
					j.Differing = 0
				}
			}
			out = append(out, j)
		}
		return out
	}
	if p.Has("--show") {
		want := strings.ToLower(strings.TrimSpace(p.Value("--show")))
		var match []string
		for _, h := range hashes {
			if h == want || (want != "" && strings.HasPrefix(h, want)) {
				match = append(match, h)
			}
		}
		switch {
		case len(match) == 0:
			return inv.usageErr("No shape '" + p.Value("--show") + "'. List them with: tacctl device config shapes")
		case len(match) > 1:
			return inv.usageErr("'" + p.Value("--show") + "' names several shapes: " + strings.Join(match, ", "))
		}
		if p.Has("--json") {
			return inv.printJSON(objs(match, true)[0])
		}
		h := match[0]
		e := m[h]
		inv.echo("")
		inv.echoE(ui.Bold + "Shape " + h + ui.NC + "  (" + shapeState(e) + ")")
		for _, l := range e.Lines {
			if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
				inv.echo("  " + l)
			} else {
				inv.echo("    " + cleanLine(l))
			}
		}
		for _, c := range e.Confirmed {
			how := "applied and verified"
			if c.Seeded {
				how = "seeded by"
			}
			inv.echo(fmt.Sprintf("  confirmed on %s: %s %s %s", c.Device, how, c.By, seenTime(c.At)))
		}
		if d := at[h]; len(d) > 0 {
			inv.echo("  at this shape now (last check or apply): " + strings.Join(d, ", "))
		}
		inv.echo("")
		return nil
	}
	if p.Has("--json") {
		return inv.printJSON(objs(hashes, false))
	}
	head := fmt.Sprintf("Shapes (%d)", len(hashes))
	if len(hashes) == 0 {
		inv.echo("")
		inv.echoE(ui.Bold + head + ui.NC)
		inv.echo(ui.Rule(head))
		inv.echo("  None. A check or an apply of a device that needs a change files its shape: tacctl device config apply <name> --check")
		inv.echo("")
		return nil
	}
	tb := ui.NewTable(head, ui.Left("SHAPE"), ui.Left("STATE"), ui.Left("CONFIRMED"), ui.Left("DEVICES NOW"), ui.Left("LINES"), ui.Left("NOTE"))
	for _, j := range objs(hashes, false) {
		conf := "-"
		if n := len(shapeDevices(m[j.Shape])); n > 0 {
			conf = howMany(n, "device")
		}
		note := "-"
		if j.Nearest != "" {
			note = fmt.Sprintf("nearest confirmed %s, %d lines differ", j.Nearest, j.Differing)
		}
		now := "-"
		if len(j.Devices) > 0 {
			now = strings.Join(j.Devices, ",")
		}
		tb.Add(j.Shape, j.State, conf, now, fmt.Sprint(j.Count), note)
	}
	inv.write(tb.String())
	inv.echo("")
	return nil
}

// deviceConfigSeed is 'shapes seed <name>[,<name>...] [-y]': the shape of
// each device's last check or apply is filed as confirmed by the person's
// word (D135). The lines are the ones the check saw: nothing is re-planned,
// and no device is contacted.
func (inv *invocation) deviceConfigSeed(p Parsed, rest []string) error {
	usage := "Usage: tacctl device config " + deviceConfigUse("shapes")
	var names []string
	for _, a := range rest {
		for _, n := range strings.Split(a, ",") {
			if n = strings.TrimSpace(n); n != "" && !slices.ContainsFunc(names, func(x string) bool { return strings.EqualFold(x, n) }) {
				names = append(names, n)
			}
		}
	}
	if len(names) == 0 {
		return inv.argErr("Name the devices whose shape was applied and verified by other means.", usage)
	}
	user := inv.sudoUser()
	if user == "" || user == "root" {
		return inv.usageErr("device config shapes seed records whose word it is: run it from your own account, not as root")
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	st := devapply.OpenShapes(inv.app.Paths.ApplyDir)
	known, err := st.Load()
	if err != nil {
		return err
	}
	recs, _ := inv.configStore().Load()
	type seedItem struct {
		e     devreg.Entry
		shape string
		lines []string
		done  bool
	}
	var items []*seedItem
	for _, n := range names {
		e, err := inv.deviceFind(res, n)
		if err != nil {
			return err
		}
		if e.Source != devreg.SourceDevice || e.Vendor != "juniper" {
			return inv.usageErr("'" + e.Name + "' is not a Junos device: shapes are the changes of 'device config apply', which writes to Junos devices.")
		}
		rec, _ := recs.Of(e.Name)
		a := (*devconf.Applied)(nil)
		if rec != nil {
			a = rec.Applied
		}
		switch {
		case a == nil || a.Shape == "":
			return inv.usageErr("'"+e.Name+"' has no check or apply on record that found a change; there is no shape to seed.",
				"Check it first: tacctl device config apply "+e.Name+" --check")
		case a.Result != devconf.AppliedChecked && a.Result != devconf.AppliedApplied:
			return inv.usageErr("The last run on '"+e.Name+"' was "+a.Result+", not a check or an apply that went through; there is no shape to seed.",
				"Check it first: tacctl device config apply "+e.Name+" --check")
		}
		ent, ok := known[a.Shape]
		if !ok || len(ent.Lines) == 0 {
			return inv.usageErr("The lines of shape " + a.Shape + " are not in the store; check '" + e.Name + "' again: tacctl device config apply " + e.Name + " --check")
		}
		it := &seedItem{e: e, shape: a.Shape, lines: ent.Lines}
		for _, c := range ent.Confirmed {
			if strings.EqualFold(c.Device, e.Name) {
				it.done = true
			}
		}
		items = append(items, it)
	}
	// What is asked: each shape once, with its lines and its devices.
	var order []string
	byShape := map[string][]*seedItem{}
	for _, it := range items {
		if _, ok := byShape[it.shape]; !ok {
			order = append(order, it.shape)
		}
		byShape[it.shape] = append(byShape[it.shape], it)
	}
	inv.echo("")
	pending := 0
	for _, h := range order {
		var devs []string
		for _, it := range byShape[h] {
			if it.done {
				devs = append(devs, it.e.Name+" (already confirmed)")
			} else {
				devs = append(devs, it.e.Name)
				pending++
			}
		}
		inv.echo("Shape " + h + ": " + strings.Join(devs, ", "))
		for _, l := range byShape[h][0].lines {
			if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
				inv.echo("  " + l)
			} else {
				inv.echo("    " + cleanLine(l))
			}
		}
		inv.echo("")
	}
	if pending == 0 {
		inv.app.Out.Info("Every shape is confirmed on those devices already. Nothing was changed.")
		return nil
	}
	inv.echo("  This is your word that each shape above was applied to the device and verified there")
	inv.echo("  by other means: 'device config apply --confirmed' will then apply it to other devices")
	inv.echo("  with no review of their own.")
	if !p.Has("-y") && !inv.app.Prompter().Confirm("  Mark them confirmed? [y/N]: ") {
		inv.app.Out.Info("Nothing was changed.")
		return nil
	}
	now := inv.app.Knobs.Now()
	for _, h := range order {
		for _, it := range byShape[h] {
			if it.done {
				continue
			}
			if err := st.Confirm(h, it.lines, devapply.Confirmation{Device: it.e.Name, At: now, By: user, Seeded: true}); err != nil {
				return err
			}
			inv.app.Audit().Raw("auth.notice", "device config shapes seed user="+user+" device="+it.e.Name+" shape="+h)
			inv.app.Out.Info("Shape " + h + " is confirmed on " + it.e.Name + ".")
		}
	}
	return nil
}

// shapeNames are the hashes of the shapes in the store, for completion of
// 'device config shapes --show'. The shapes are the superuser's: a caller
// whose scopes are restricted gets none.
func (inv *invocation) shapeNames([]string) []string {
	if inv.callerScopes().restricted {
		return nil
	}
	m, err := devapply.OpenShapes(inv.app.Paths.ApplyDir).Load()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for h := range m {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
