package lifecycle

// The rollback to 0.2.8 (docs/plans/0.2.9-rollout-plan.md D143): the part of
// PlanRollback that runs when RollbackInput.Target is RollbackTarget028. The
// file header of rollback.go has the table of what it does and why; ApplyRollback
// is shared (tacctl.yaml's keys and the sudoers drop-ins are all it converts).

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/tier"
)

// planRollback028 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback028(p *RollbackPlan) (*RollbackPlan, error) {
	in := p.in
	p.keys = in.Conf.RollbackKeys028()
	p.sudoers = p.planSudoers028()
	p.Steps = append(p.Steps, p.confStep028(), p.sudoersStep028(), p.recordsStep028(), p.otherStep028())
	if in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget028 + ": 0.2.9 changed nothing on the hosts; no host is synced"}})
	}
	p.Warnings = p.warnings028()
	p.Notes = p.notes028()
	return p, nil
}

func (p *RollbackPlan) confStep028() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.Overrides + ": remove the keys " + RollbackTarget028 + " does not know", Todo: len(p.keys) > 0}
	if len(p.keys) == 0 {
		s.Lines = []string{"nothing to remove (device.apply.confirm_timeout and device.apply.pause are not set)"}
		return s
	}
	for _, k := range p.keys {
		s.Lines = append(s.Lines, "remove "+k)
	}
	s.Lines = append(s.Lines, "("+RollbackTarget028+"'s schema refuses them: its 'config validate' reports them and its 'backup restore' refuses a snapshot that has them; every other key is one it has and stays)")
	return s
}

// planSudoers028 reads the two drop-ins: this release's text is rewritten
// with 0.2.8's, 0.2.8's is done, anything else is left.
func (p *RollbackPlan) planSudoers028() []sudoersPlan {
	var out []sudoersPlan
	pt := p.in.Paths

	tiers := sudoersPlan{label: "the per-tier drop-in", file: pt.TierSudoersFile, state: "absent"}
	if b, err := os.ReadFile(pt.TierSudoersFile); err == nil {
		switch got := string(b); {
		case got == tier.Sudoers028():
			tiers.state = "done"
		case got == tier.Sudoers():
			tiers.state, tiers.body = "rewrite", tier.Sudoers028()
		default:
			tiers.state = "left"
		}
	}
	out = append(out, tiers)

	group := sudoersPlan{label: "the group drop-in", file: pt.SudoersFile, state: "absent"}
	if b, err := os.ReadFile(pt.SudoersFile); err == nil {
		name, kind := tier.ClassifyGroupSudoers(string(b))
		switch {
		case kind == tier.GroupCurrent:
			group.label = "the drop-in of group " + name
			group.state, group.body = "rewrite", tier.GroupSudoers028(name)
		case kind == tier.GroupOlder && string(b) == tier.GroupSudoers028(name):
			group.label = "the drop-in of group " + name
			group.state = "done"
		default:
			group.state = "left"
		}
	}
	out = append(out, group)
	return out
}

func (p *RollbackPlan) sudoersStep028() RollbackStep {
	s := RollbackStep{Title: "put back the sudoers drop-ins " + RollbackTarget028 + " writes", Todo: len(p.todoSudoers()) > 0}
	any := false
	for _, d := range p.sudoers {
		switch d.state {
		case "rewrite":
			any = true
			line := "rewrite " + d.file + " (" + d.label + ": " + RollbackTarget028 + "'s text, after 'visudo -cf'; the password cache's alias loses the lines of 'device config apply', 'device onboard' and 'device collect')"
			if p.in.InstallSudoers == nil {
				line += " [not rewritten: no installer]"
			}
			s.Lines = append(s.Lines, line)
		case "done":
			any = true
			s.Lines = append(s.Lines, d.file+" ("+d.label+") is already the text "+RollbackTarget028+" writes")
		case "left":
			any = true
			s.Lines = append(s.Lines, "leaves "+d.file+": it is not the text this release writes (edited, or another release's); sudo accepts it, and "+RollbackTarget028+" ignores the lines it does not use")
		}
	}
	if !any {
		s.Lines = []string{"no tacctl sudoers drop-in is installed (" + p.in.Paths.TierSudoersFile + ", " + p.in.Paths.SudoersFile + ")"}
	}
	return s
}

// recordsStep028 lists what 0.2.9 left on disk that 0.2.8 ignores. Nothing
// is deleted.
func (p *RollbackPlan) recordsStep028() RollbackStep {
	pt := p.in.Paths
	s := RollbackStep{Title: "leave what 0.2.9 wrote in " + pt.VarLib + " (listed, not deleted)"}

	var applied, extra, total int
	if recs, err := (devconf.Store{Records: pt.ConfigRecords, Dir: pt.ConfigDir}).Load(); err == nil {
		for _, name := range recs.Names() {
			r, _ := recs.Of(name)
			if r == nil {
				continue
			}
			total++
			if r.Applied != nil {
				applied++
			}
			if r.Login != "" || r.UserPulled || r.Hostname != "" {
				extra++
			}
		}
	}
	if fi, err := os.Stat(pt.ConfigRecords); err == nil && fi.Mode().IsRegular() {
		s.Lines = append(s.Lines, "leaves "+pt.ConfigRecords+" ("+strconv.Itoa(total)+" "+pluralWord(total, "record", "records")+", version 1 as "+RollbackTarget028+" reads it):")
		if applied > 0 {
			s.Lines = append(s.Lines, "  "+strconv.Itoa(applied)+" "+pluralWord(applied, "record has", "records have")+" an 'applied' part of 'device config apply' (id, kind, result, reason, until, shape, sections, counts, commit, pre); none is pending")
		} else {
			s.Lines = append(s.Lines, "  no record has an 'applied' part")
		}
		if extra > 0 {
			s.Lines = append(s.Lines, "  "+strconv.Itoa(extra)+" "+pluralWord(extra, "record has", "records have")+" the 'login', 'user_pulled' or 'hostname' fields of --login pulls, 'device onboard' and 'device collect'")
		}
		s.Lines = append(s.Lines, "  "+RollbackTarget028+" ignores the fields it does not know (unknown JSON fields are not an error) and writes none of them back; the next pull of the device rewrites its record, and 'tacctl device config forget --all' of "+RollbackTarget028+" deletes them")
	}
	if ents, err := os.ReadDir(pt.ApplyDir); err == nil {
		var files []string
		locks := 0
		for _, e := range ents {
			switch {
			case e.IsDir() && e.Name() == "locks":
				if l, err := os.ReadDir(filepath.Join(pt.ApplyDir, e.Name())); err == nil {
					locks = len(l)
				}
			case e.Type().IsRegular():
				files = append(files, e.Name())
			}
		}
		sort.Strings(files)
		line := "leaves " + pt.ApplyDir + " (the state of 'device config apply'"
		if len(files) > 0 {
			line += ": " + strings.Join(files, ", ")
		}
		if locks > 0 {
			line += fmt.Sprintf("; %d device %s in locks/", locks, pluralWord(locks, "lock", "locks"))
		}
		s.Lines = append(s.Lines, line+")",
			"  "+RollbackTarget028+" never opens it; 0.2.9 finds the shapes again (the first device of a shape is applied alone only until a shape is confirmed). Delete the directory by hand to forget them")
	}
	if len(s.Lines) == 0 {
		s.Lines = []string{"no record of a configuration pull or of an apply"}
		return s
	}
	s.Lines = append(s.Lines, "(derived from the devices and the pulls and applies made: never in a snapshot, and nothing here is needed to run "+RollbackTarget028+")")
	return s
}

func (p *RollbackPlan) otherStep028() RollbackStep {
	pt := p.in.Paths
	return RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.ConsoleFile + ", " + pt.DevicesFile + ", " + pt.StoreFile + ", the SNMP credentials, the blocks and the rendered backend files are in formats " + RollbackTarget028 + " reads (0.2.9 changed none of them);",
			"nothing is re-rendered or restarted, and no device is contacted"}}
}

func (p *RollbackPlan) warnings028() []RollbackWarning {
	var out []RollbackWarning
	in := p.in
	var ro []string
	for _, k := range p.keys {
		v, _ := in.Conf.Get(k, "")
		ro = append(ro, k+"="+v)
	}
	if len(ro) > 0 {
		lines := []string{"The settings of 'device config apply' (" + strings.Join(ro, ", ") + ") are removed from tacctl.yaml; " + RollbackTarget028 + " has no such verb, and 0.2.9 uses its defaults (10 minutes, 60 seconds) until they are set again.",
			"What is removed from tacctl.yaml stays in the snapshot --apply takes first (tacctl backup list); 'tacctl backup restore' of it, with 0.2.9, brings it back."}
		out = append(out, RollbackWarning{Title: "Settings " + RollbackTarget028 + " cannot use are dropped", Lines: lines})
	}
	if !in.HasStore && p.PendingFiles() {
		out = append(out, RollbackWarning{
			Title: "No snapshot can be taken",
			Lines: []string{"This install has no store (legacy read-only mode) and snapshots are taken of the store, so --apply cannot back up the files it converts.",
				"Copy " + in.Paths.Overrides + " yourself before you go on."}})
	}
	return out
}

func (p *RollbackPlan) notes028() []string {
	var out []string
	if p.PendingFiles() {
		out = append(out, "The snapshot --apply takes holds the 0.2.9 form of tacctl.yaml: restore it with 0.2.9 ('tacctl backup restore'), not with "+RollbackTarget028+", whose restore refuses a key it does not know.")
	}
	return out
}
