package lifecycle

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/mgmtacl"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/ui"
)

// The plain management ACL entries of 0.2.7: an entry with no ':service' is
// every protocol and port from its source. On a WTI unit that is a change of
// what its IP Tables list renders: a plain entry was ssh (tcp/22) and ICMP
// before, and the next plan from this release renders
// 'iptables -A INPUT -s <net> -j ACCEPT'. The decision is kept; the upgrade
// tells an operator once where it applies, before a plan is pasted.

// WTIPlainNoticeDone reports whether the upgrade has said it (the marker
// p.WTIPlainNoticeMarker). An empty path is always done: nothing records it.
func WTIPlainNoticeDone(p paths.Paths) bool {
	if p.WTIPlainNoticeMarker == "" {
		return true
	}
	_, err := os.Stat(p.WTIPlainNoticeMarker)
	return err == nil
}

// MarkWTIPlainNotice records that it was said (the marker, 0600, in VarLib).
// A fresh install writes it too: no unit was ever given a list that rendered
// a plain entry as ssh.
func MarkWTIPlainNotice(p paths.Paths) error {
	if p.WTIPlainNoticeMarker == "" {
		return nil
	}
	if err := paths.MkVarLib(filepath.Dir(p.WTIPlainNoticeMarker)); err != nil {
		return err
	}
	return os.WriteFile(p.WTIPlainNoticeMarker, []byte("tacctl 0.2.7 told once, at an upgrade, which scopes have plain management ACL entries that permit every protocol and port on WTI units. Delete this file only to be told again.\n"), 0o600)
}

// ScopeACL is the management permit list that applies to a scope (its own
// list, else the global one: Global says which).
type ScopeACL struct {
	Scope   string
	Global  bool
	Permits []string
}

// WTIUnit is a registered WTI device and the scope that answers its address
// ("" when none does).
type WTIUnit struct {
	Name, Scope string
}

// maxNoticeUnits is how many unit names a scope's line lists.
const maxNoticeUnits = 5

// WTIPlainNotice is the lines of the notice (nil: nothing to say): for every
// scope that has at least one registered WTI unit and a list with at least
// one plain IPv4 entry, the entries and the units. The WTI list is IPv4 only,
// so a plain IPv6 entry is not named. Scopes are in name order, units in name
// order, and a scope's entries as its list has them (each once).
func WTIPlainNotice(lists []ScopeACL, units []WTIUnit) []string {
	byScope := map[string][]string{}
	for _, u := range units {
		if u.Scope != "" {
			byScope[u.Scope] = append(byScope[u.Scope], u.Name)
		}
	}
	var out []string
	sorted := slices.Clone(lists)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Scope < sorted[j].Scope })
	for _, l := range sorted {
		names := byScope[l.Scope]
		if len(names) == 0 {
			continue
		}
		var plain []string
		for _, raw := range l.Permits {
			e, err := mgmtacl.ParseEntry(strings.TrimSpace(raw))
			if err != nil || !e.Plain() || e.IPv6() || slices.Contains(plain, e.Net) {
				continue
			}
			plain = append(plain, e.Net)
		}
		if len(plain) == 0 {
			continue
		}
		slices.Sort(names)
		names = slices.Compact(names)
		shown := names
		if len(shown) > maxNoticeUnits {
			shown = shown[:maxNoticeUnits]
		}
		list := strings.Join(shown, ", ")
		if more := len(names) - len(shown); more > 0 {
			list += fmt.Sprintf(" and %d more", more)
		}
		unit := "WTI device"
		if len(names) != 1 {
			unit = "WTI devices"
		}
		src := ""
		if l.Global {
			src = "; the global list"
		}
		out = append(out, fmt.Sprintf("scope %s: %s  (%d %s: %s%s)", l.Scope, strings.Join(plain, ", "), len(names), unit, list, src))
	}
	if len(out) == 0 {
		return nil
	}
	head := "Management ACL: plain entries now permit every protocol and port on WTI units."
	tail := []string{
		"A WTI plan from this release renders them as 'iptables -A INPUT -s <cidr> -j ACCEPT'",
		"(0.2.6 rendered ssh and ICMP). To keep ssh only, rewrite an entry as <cidr>:tcp/22",
		"(tacctl scope mgmt-acl <scope> remove <cidr>, then add <cidr>:tcp/22; tacctl config mgmt-acl for the global list).",
	}
	lines := []string{head}
	for _, l := range out {
		lines = append(lines, "  "+l)
	}
	for _, l := range tail {
		lines = append(lines, "  "+l)
	}
	return lines
}

// wtiPlainNotice is the upgrade's say about it: once, on the first upgrade
// onto this release, and only when a scope with registered WTI units has a
// plain entry. The marker is written whether or not there was anything to
// say (an entry added later is added knowing what it means, and the plan
// warns of it); nothing is written when the registry or the store could not
// be read, so the next upgrade tries again. An upgrade never creates VarLib.
func (h *Host) wtiPlainNotice() {
	if WTIPlainNoticeDone(h.Paths) {
		return
	}
	lines, ok := h.wtiPlainLines()
	if !ok {
		return
	}
	for _, l := range lines {
		h.echo(ui.Red + "  " + l + ui.NC)
	}
	if len(lines) > 0 {
		h.echo("")
	}
	if _, err := os.Stat(filepath.Dir(h.Paths.WTIPlainNoticeMarker)); err == nil {
		if err := MarkWTIPlainNotice(h.Paths); err != nil {
			h.Out.Warn("Could not record that this notice was shown in " + h.Paths.WTIPlainNoticeMarker + ": " + strings.TrimSpace(err.Error()))
		}
	}
}

// wtiPlainLines reads the registry, the store and the lists and builds the
// notice; ok is false when something could not be read.
func (h *Host) wtiPlainLines() (lines []string, ok bool) {
	reg, err := devreg.Load(h.Paths.DevicesFile)
	if err != nil {
		return nil, false
	}
	var wti []*devreg.Device
	for _, d := range reg.Devices {
		if d.Vendor == "wti" {
			wti = append(wti, d)
		}
	}
	if len(wti) == 0 {
		return nil, true
	}
	p := h.Paths
	_, m, _, err := model.Load(model.Paths{
		Store: p.StoreFile, Config: p.Config, DatesDir: p.PWDatesDir,
		DisabledDir: filepath.Join(p.BackupDir, "disabled"),
	})
	if err != nil || m == nil {
		return nil, false
	}
	var units []WTIUnit
	var lists []ScopeACL
	seen := map[string]bool{}
	for _, d := range wti {
		info, found := m.LookupAddr(d.Address)
		if !found {
			continue
		}
		units = append(units, WTIUnit{Name: d.Name, Scope: info.Scope})
		if seen[info.Scope] {
			continue
		}
		seen[info.Scope] = true
		list, own := h.Conf.MgmtACLList(info.Scope)
		lists = append(lists, ScopeACL{Scope: info.Scope, Global: !own, Permits: list})
	}
	return WTIPlainNotice(lists, units), true
}
