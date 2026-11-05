package firewall

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/rett/tacctl/internal/execx"
)

// UnitName is the boot unit: a oneshot that loads the rules file, so the
// table is back after a reboot before the network and tacquito are up. It
// is tacctl's own unit; nftables.service (Ubuntu's /etc/nftables.conf starts
// with 'flush ruleset') is never enabled, started or touched by tacctl, and
// this unit orders itself after it so that a host that runs both ends with
// both.
const UnitName = "tacctl-breakglass-firewall.service"

// fallbackNft is where the unit finds nft when PATH does not say.
const fallbackNft = "/usr/sbin/nft"

// UnitText is the unit file: a oneshot, no stop action (stopping it never
// flushes anything), loaded early at boot.
func (e *Engine) UnitText() string {
	nft := fallbackNft
	if p, err := e.Runner.LookPath(Tool); err == nil && filepath.IsAbs(p) {
		nft = p
	}
	rules := e.Paths.FirewallRules
	return "# Written by tacctl: loads the nftables table that refuses the TCP connections\n" +
		"# of the addresses held for break-glass (" + rules + ", rewritten by every\n" +
		"# 'tacctl breakglass hold|release'). It touches no other table; nftables.service\n" +
		"# is not used and not touched.\n" +
		"[Unit]\n" +
		"Description=tacctl break-glass firewall (refuses the TCP connections of held addresses)\n" +
		"Documentation=man:tacctl(1)\n" +
		"DefaultDependencies=no\n" +
		"Wants=network-pre.target\n" +
		"After=nftables.service local-fs.target\n" +
		"Before=network-pre.target tacquito.service\n" +
		"ConditionPathExists=" + rules + "\n" +
		"\n" +
		"[Service]\n" +
		"Type=oneshot\n" +
		"RemainAfterExit=yes\n" +
		"ExecStart=" + nft + " -f " + rules + "\n" +
		"ExecReload=" + nft + " -f " + rules + "\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=sysinit.target\n"
}

// InstallUnit writes the boot unit when it is missing or not this text and
// enables it (not starts it: the table is loaded by Apply, the unit is for
// the next boot). Nothing is done without nft: the unit would load nothing.
// written is whether the file was written; an error is the first step that
// failed.
func (e *Engine) InstallUnit(ctx context.Context) (written bool, err error) {
	if _, lerr := e.Runner.LookPath(Tool); lerr != nil {
		return false, nil
	}
	unit := e.Paths.FirewallUnit
	want := e.UnitText()
	if have, rerr := os.ReadFile(unit); rerr != nil || string(have) != want {
		if err := writeAtomic(unit, []byte(want), 0o644); err != nil {
			return false, err
		}
		written = true
		if code := e.systemctl(ctx, "daemon-reload"); code != 0 {
			return written, errors.New("systemctl daemon-reload failed")
		}
	}
	if written || e.systemctl(ctx, "is-enabled", "--quiet", UnitName) != 0 {
		if code := e.systemctl(ctx, "enable", "--quiet", UnitName); code != 0 {
			return written, errors.New("systemctl enable " + UnitName + " failed")
		}
	}
	return written, nil
}

// RemoveUnit disables the boot unit and removes its file (” when there was
// none), then reloads systemd. A unit that is not there is not an error.
func (e *Engine) RemoveUnit(ctx context.Context) (removed string, err error) {
	if _, ok := statFile(e.Paths.FirewallUnit); !ok {
		return "", nil
	}
	e.systemctl(ctx, "disable", "--quiet", UnitName)
	if rerr := os.Remove(e.Paths.FirewallUnit); rerr != nil {
		return "", rerr
	}
	if code := e.systemctl(ctx, "daemon-reload"); code != 0 {
		return e.Paths.FirewallUnit, errors.New("systemctl daemon-reload failed")
	}
	return e.Paths.FirewallUnit, nil
}

// systemctl runs 'systemctl args...' with its output thrown away and returns
// its exit status (127 when it could not be run).
func (e *Engine) systemctl(ctx context.Context, args ...string) int {
	r, err := e.Runner.Run(ctx, execx.Cmd{Name: "systemctl", Args: args, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil && r.Code == 0 {
		return 127
	}
	return r.Code
}
