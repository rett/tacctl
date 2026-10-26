package lifecycle

// The rollback to 0.2.9 (docs/plans/0.2.10-plan.md): the part of
// PlanRollback that runs when RollbackInput.Target is RollbackTarget029. The
// file header of rollback.go has the table of what it does and why;
// ApplyRollback is shared (tacctl.yaml's keys, the NETCONF setting of the
// devices and the key of their configuration syntax setting, config_syntax
// in 0.2.9, are all it converts for this target; there is no drop-in step: the
// tiers file is left, and 0.2.9's upgrade rewrites it).

import (
	"strconv"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
)

// planRollback029 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback029(p *RollbackPlan) (*RollbackPlan, error) {
	in := p.in
	p.keys = in.Conf.RollbackKeys029()
	reg, err := devreg.Load(in.Paths.DevicesFile)
	if err != nil {
		return nil, err
	}
	for _, d := range reg.Devices {
		if !d.Netconf.Empty() {
			p.netconfDev = append(p.netconfDev, devNetconf{d.Name, describeNetconf(d.Netconf)})
		}
	}
	if err := p.planSyntaxKey(); err != nil {
		return nil, err
	}
	p.Steps = append(p.Steps, p.confStep029(), p.devicesStep029(), p.syntaxKeyStep(), p.recordsStep029(), p.otherStep029())
	if in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget029 + ": 0.2.10 changed nothing on the hosts; no host is synced"}})
	}
	p.Warnings = append(p.warnings029(), p.blocksWarning(RollbackTarget029)...)
	p.Notes = p.notes029()
	return p, nil
}

func (p *RollbackPlan) confStep029() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.Overrides + ": remove the keys " + RollbackTarget029 + " does not know", Todo: len(p.keys) > 0}
	if len(p.keys) == 0 {
		s.Lines = []string{"nothing to remove (device.apply.transport, the netconf_scope settings, audit.strict and the lockdown record are not set)"}
		return s
	}
	for _, k := range p.keys {
		s.Lines = append(s.Lines, "remove "+k)
	}
	s.Lines = append(s.Lines, "("+RollbackTarget029+"'s schema refuses them: its 'config validate' reports them and its 'backup restore' refuses a snapshot that has them; every other key is one it has and stays)")
	return s
}

func (p *RollbackPlan) devicesStep029() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.DevicesFile + ": remove the per-device NETCONF service setting", Todo: len(p.netconfDev) > 0}
	if len(p.netconfDev) == 0 {
		s.Lines = []string{"no device has a NETCONF service setting of its own"}
		return s
	}
	for _, d := range p.netconfDev {
		s.Lines = append(s.Lines, "remove the netconf map of "+d.name+" ("+d.what+")")
	}
	s.Lines = append(s.Lines, "("+RollbackTarget029+"'s parser refuses a device with a key it does not know: \"unknown key 'netconf'\")")
	return s
}

// recordsStep029 lists what 0.2.10 left on disk that 0.2.9 ignores. Nothing
// is deleted.
func (p *RollbackPlan) recordsStep029() RollbackStep {
	pt := p.in.Paths
	s := RollbackStep{Title: "leave what 0.2.10 wrote in " + pt.VarLib + " (listed, not deleted)"}

	var via, total int
	if recs, err := (devconf.Store{Records: pt.ConfigRecords, Dir: pt.ConfigDir}).Load(); err == nil {
		for _, name := range recs.Names() {
			r, _ := recs.Of(name)
			if r == nil {
				continue
			}
			total++
			if r.Applied != nil && r.Applied.Via != "" {
				via++
			}
		}
	}
	if total == 0 {
		s.Lines = []string{"no record of a configuration pull or of an apply"}
		return s
	}
	s.Lines = append(s.Lines, "leaves "+pt.ConfigRecords+" ("+strconv.Itoa(total)+" "+pluralWord(total, "record", "records")+", version 1 as "+RollbackTarget029+" reads it):")
	if via > 0 {
		s.Lines = append(s.Lines, "  "+strconv.Itoa(via)+" "+pluralWord(via, "record has", "records have")+" the 'via' field of its 'applied' part (the transport the apply wrote through)")
	} else {
		s.Lines = append(s.Lines, "  no record has a field "+RollbackTarget029+" does not know")
	}
	s.Lines = append(s.Lines, "  "+RollbackTarget029+" ignores the fields it does not know (unknown JSON fields are not an error) and writes none of them back; the next apply or pull of the device rewrites its record")
	s.Lines = append(s.Lines, "(derived from the devices and the pulls and applies made: never in a snapshot, and nothing here is needed to run "+RollbackTarget029+")")
	return s
}

func (p *RollbackPlan) otherStep029() RollbackStep {
	pt := p.in.Paths
	return RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.ConsoleFile + ", " + pt.StoreFile + ", the SNMP credentials, the blocks, the apply state directory and the rendered backend files are in formats " + RollbackTarget029 + " reads (0.2.10 changed none of them, and 0.2.19 none but the blocks: see the warning, if any);",
			"the sudoers drop-ins are left: sudo accepts them, the tiers file is left, and " + RollbackTarget029 + "'s upgrade rewrites it;",
			"nothing is re-rendered or restarted, and no device is contacted"}}
}

func (p *RollbackPlan) warnings029() []RollbackWarning {
	var out []RollbackWarning
	in := p.in
	var tr, nc []string
	for _, k := range p.keys {
		if conf.Added0217Key(k) || conf.Added0219Key(k) {
			continue
		}
		v, _ := in.Conf.Get(k, "")
		if k == "device.apply.transport" {
			tr = append(tr, k+"="+v)
			continue
		}
		nc = append(nc, k+"="+v)
	}
	var lines []string
	if len(tr) > 0 {
		lines = append(lines, "The transport setting of 'device config apply' ("+tr[0]+") is removed from tacctl.yaml; "+RollbackTarget029+" applies over the command line only.")
	}
	if len(nc) > 0 || len(p.netconfDev) > 0 {
		lines = append(lines, "The NETCONF service setting (scope netconf, device netconf) is removed: "+RollbackTarget029+" neither plans nor compares the service again, and a service a device runs, or has had deleted, stays as it is:")
		for _, k := range nc {
			lines = append(lines, "  "+k)
		}
		for _, d := range p.netconfDev {
			lines = append(lines, "  "+d.name+": "+d.what)
		}
	}
	if len(lines) > 0 {
		lines = append(lines, "What is removed from tacctl.yaml and devices.yaml stays in the snapshot --apply takes first (tacctl backup list); 'tacctl backup restore' of it, with 0.2.10, brings it back.")
		out = append(out, RollbackWarning{Title: "Settings " + RollbackTarget029 + " cannot use are dropped", Lines: lines})
	}
	out = append(out, p.auditStrictWarning(RollbackTarget029)...)
	if !in.HasStore && p.PendingFiles() {
		out = append(out, RollbackWarning{
			Title: "No snapshot can be taken",
			Lines: []string{"This install has no store (legacy read-only mode) and snapshots are taken of the store, so --apply cannot back up the files it converts.",
				"Copy " + in.Paths.Overrides + " and " + in.Paths.DevicesFile + " yourself before you go on."}})
	}
	return out
}

func (p *RollbackPlan) notes029() []string {
	var out []string
	if p.PendingFiles() {
		out = append(out, "The snapshot --apply takes holds the 0.2.10 form of tacctl.yaml and devices.yaml: restore it with 0.2.10 ('tacctl backup restore'), not with "+RollbackTarget029+", whose restore and parsers refuse a key they do not know.")
	}
	return out
}
