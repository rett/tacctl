package cli

// 'tacctl status' (lib/service.sh cmd_status at 0.1.16), native since
// WP2.4d. With one enabled backend its lines sit where this report always
// had them; with more, each backend gets a section of its own (after the
// backup count) with all of its lines, and what is not any backend's stays
// up front. The users line, the backup count, the security posture and the
// password-age warnings are the report's own.

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/ui"
)

func statusCmd(inv *invocation) *cobra.Command {
	return withRun(verb("status", "Show service health, stats, and recent errors (per backend)"),
		inv.native(withPreflight, inv.status))
}

// statusView is the 'status' model view (Model.Status) as cmd_status reads
// it: key=value lines, 'orphan=' and 'pwdate=' repeating.
type statusView struct {
	kv              map[string]string
	orphans, pwdate []string
}

func readStatusView(lines []string) statusView {
	v := statusView{kv: map[string]string{
		"user_count": "0", "scope_count": "0", "prefix_count": "0", "prefix_unrestricted": "0",
		"prefix_has_v6": "0", "allow_has_v6": "0", "total_refs": "0",
	}}
	for _, l := range lines {
		k, val, _ := strings.Cut(l, "=")
		switch k {
		case "":
		case "orphan":
			v.orphans = append(v.orphans, val)
		case "pwdate":
			v.pwdate = append(v.pwdate, val)
		default:
			v.kv[k] = val
		}
	}
	return v
}

// status is cmd_status. A model that cannot be read is reported once
// (docs/plans/go-rewrite.md 3.9 item 17) and the report goes on with
// nothing counted, as 0.1.16's did.
func (inv *invocation) status([]string) error {
	a := inv.app
	B, G, R, Y, NC := ui.Bold, ui.Green, ui.Red, ui.Yellow, ui.NC
	inv.echo("")
	inv.echoE(B + "Service Status" + NC)
	inv.echo("--------------------------------------------")

	enabled, err := inv.enabledOrFail()
	if err != nil {
		return err
	}
	set := a.Backends()
	multi := len(enabled) > 1
	// part is backends_run status <part>: every enabled backend's part, in
	// order; a failing one ends the command (errexit).
	part := func(id string, p backend.StatusPart) error {
		b, err := set.Get(id)
		if err != nil {
			return err
		}
		return b.Status(inv.ctx, p, inv.stdout())
	}
	all := func(p backend.StatusPart) error {
		for _, id := range enabled {
			if err := part(id, p); err != nil {
				return err
			}
		}
		return nil
	}

	if !multi {
		if err := all(backend.StatusService); err != nil {
			return err
		}
	}

	t := a.Tunables()
	var view statusView
	var scopeNames []string
	m, merr := inv.model()
	if merr == nil {
		view = readStatusView(m.Status(t.SecretMinLength))
		scopeNames = m.ScopeNames()
	} else {
		inv.reportModelError(merr)
		view = readStatusView(nil)
	}
	st := view.kv
	inv.echoE("  " + B + "Users:" + NC + "                " + st["user_count"])

	if !multi {
		if err := all(backend.StatusConfig); err != nil {
			return err
		}
	}
	storeMode := model.Mode(a.Paths.StoreFile) == "store"
	if !storeMode {
		inv.echoE("  " + Y + "Store:                not initialised — read-only until 'tacctl store import' (see 'tacctl store import --check')" + NC)
	}
	// Drift: a backend's own artifacts are reported in its section.
	if multi {
		inv.write(strings.Join(set.DriftLines(backend.DriftUnowned), ""))
	} else {
		inv.write(strings.Join(set.DriftLines(backend.DriftAll), ""))
	}
	if !multi {
		if err := all(backend.StatusAccounting); err != nil {
			return err
		}
	}

	// Backup count: snapshots, plus the old-style files an upgrade leaves
	// behind; without a store the old-style files are the backups.
	snaps, old := len(inv.snapshotIDs()), len(inv.legacyBackups())
	count := strconv.Itoa(snaps + old)
	if storeMode {
		count = strconv.Itoa(snaps)
		if old > 0 {
			count += " (+" + strconv.Itoa(old) + " old-style)"
		}
	}
	inv.echoE("  " + B + "Config backups:" + NC + "       " + count)

	// Each backend's section, or the one backend's activity.
	if multi {
		for _, id := range enabled {
			b, err := set.Get(id)
			if err != nil {
				return err
			}
			inv.write(backend.Heading(b))
			for _, p := range []backend.StatusPart{backend.StatusService, backend.StatusConfig, backend.StatusAccounting} {
				if err := part(id, p); err != nil {
					return err
				}
			}
			inv.write(strings.Join(set.DriftLines(backend.DriftOf(id)), ""))
			if err := part(id, backend.StatusActivity); err != nil {
				return err
			}
		}
	} else if err := all(backend.StatusActivity); err != nil {
		return err
	}

	// Security posture: every scope's prefixes and secret, IPv6/IPv4 ACL
	// parity, the management ACL, the scopes and the default scope.
	inv.echo("")
	inv.echoE("  " + B + "Security Posture:" + NC)
	switch {
	case st["prefix_unrestricted"] == "1":
		inv.echoE("    " + R + "Prefix scope:       UNRESTRICTED (all RFC 1918 — harden with 'tacctl scope prefixes <name>')" + NC)
	case st["prefix_count"] == "0":
		inv.echoE("    " + R + "Prefix scope:       EMPTY (no clients can connect)" + NC)
	default:
		inv.echoE("    " + G + "Prefix scope:       " + st["prefix_count"] + " CIDR(s) across all scopes" + NC)
	}
	if s := st["empty_prefix_scopes"]; s != "" {
		inv.echoE("      " + Y + "scopes with no prefixes: " + s + NC)
	}

	// IPv6 parity: a listener of any enabled backend on an IPv6 network
	// with no IPv6 CIDR in prefixes or allow lets v4-mapped clients bypass
	// the ACLs. The message names the first such listener (and its backend,
	// when there is more than one).
	listenerNet, listenerWho := "", "listener"
	for _, id := range enabled {
		b, err := set.Get(id)
		if err != nil {
			return err
		}
		ls, _ := b.Listeners().List()
		for _, l := range ls {
			if strings.HasSuffix(l.Network, "6") && listenerNet == "" {
				listenerNet = l.Network
				if multi {
					listenerWho = id + " listener " + l.Name
				}
			}
		}
	}
	if listenerNet != "" {
		if st["prefix_has_v6"] != "1" && st["allow_has_v6"] != "1" {
			inv.echoE("    " + R + "IPv6 ACL parity:    MISSING (" + listenerWho + " is " + listenerNet + " but no IPv6 CIDRs — v4-mapped clients bypass ACLs)" + NC)
		} else {
			inv.echoE("    " + G + "IPv6 ACL parity:    present" + NC)
		}
	}

	minSecret := strconv.Itoa(t.SecretMinLength)
	switch {
	case st["placeholder_scopes"] != "":
		inv.echoE("    " + R + "Shared secret:      PLACEHOLDER in scope(s): " + st["placeholder_scopes"] + " (run 'tacctl scope secret <name> generate')" + NC)
	case st["weak_scopes"] != "":
		inv.echoE("    " + R + "Shared secret:      weak in scope(s): " + st["weak_scopes"] + " (min " + minSecret + ")" + NC)
	default:
		inv.echoE("    " + G + "Shared secret:      all scopes ≥ " + minSecret + " chars" + NC)
	}

	// The management ACL (read_mgmt_acl_cidrs | wc -l): the global permit
	// list the device configs use.
	acl := 0
	for _, c := range a.Conf().GetList("mgmt_acl.permits") {
		if strings.TrimSpace(c) != "" {
			acl++
		}
	}
	switch acl {
	case 0:
		inv.echoE("    " + R + "Management ACL:     EMPTY (configure via 'tacctl config mgmt-acl add <cidr>')" + NC)
	case 1:
		inv.echoE("    " + G + "Management ACL:     configured (1 entry)" + NC)
	default:
		inv.echoE("    " + G + "Management ACL:     configured (" + strconv.Itoa(acl) + " entries)" + NC)
	}

	// Scopes. An orphan is a user referencing a scope that does not exist
	// (possible only in a legacy config; the store refuses one).
	switch {
	case st["scope_count"] == "0":
		inv.echoE("    " + R + "Scopes:             NONE (no auth targets defined)" + NC)
	case len(view.orphans) > 0:
		inv.echoE("    " + R + "Scopes:             ORPHAN references — users point at missing scopes" + NC)
		for _, pair := range view.orphans {
			u, s, _ := strings.Cut(pair, ":")
			inv.echoE("      " + R + "user '" + u + "' → scope '" + s + "' (does not exist)" + NC)
		}
	default:
		inv.echoE("    " + G + "Scopes:             configured (" + st["scope_count"] + " scope(s), " + st["total_refs"] + " user grant(s))" + NC)
		if s := st["empty_scopes"]; s != "" {
			inv.echoE("      " + Y + "empty scope(s): " + s + " (no users — intentional?)" + NC)
		}
	}
	if def := statusDefaultScope(a.Conf().Get, scopeNames); def == "" {
		inv.echoE("    " + Y + "Default scope:      UNSET (tacctl user add without --scopes will fail)" + NC)
	} else {
		inv.echoE("    " + G + "Default scope:      " + def + NC)
	}

	// Password age warnings: the days since each user's password_changed
	// (local midnight of that date), over password.max_age_days.
	inv.echo("")
	inv.echoE("  " + B + "Password Age Warnings:" + NC)
	now := a.Knobs.Now().Unix()
	warnings := 0
	for _, l := range view.pwdate {
		name, date, _ := strings.Cut(l, "|")
		if name == "" {
			continue
		}
		d, err := time.ParseInLocation("2006-01-02", date, time.Local)
		if err != nil || d.Unix() <= 0 {
			continue
		}
		if age := (now - d.Unix()) / 86400; age > int64(t.PasswordMaxAgeDays) {
			inv.echoE("    " + Y + name + ": password is " + fmt.Sprint(age) + " days old (changed " + date + ")" + NC)
			warnings++
		}
	}
	if warnings == 0 {
		inv.echoE("    " + G + "No passwords older than " + strconv.Itoa(t.PasswordMaxAgeDays) + " days" + NC)
	}
	// The device registry's open notices (device_scan.go).
	inv.statusDeviceNotices()
	inv.echo("")
	return nil
}

// statusDefaultScope is read_default_scope over the scope names the report
// read (none when the model could not be read): scope.default when it
// names a scope, else the only scope, else "".
func statusDefaultScope(get func(path, fallback string) (string, bool), names []string) string {
	v, _ := get("scope.default", "")
	if v != "" && contains(names, v) {
		return v
	}
	if len(names) == 1 {
		return names[0]
	}
	return ""
}
