package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// radiusSandbox is a sandbox where tacctl has set up FreeRADIUS (the
// daemon binary and a rendered config exist: backend_radius_installed),
// the family given, every path a phase can write under the sandbox
// (sandboxPathEnv; /root of --keep-logs too: sandbox.run reroots).
func radiusSandbox(t *testing.T, family string) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.write("raddb/tacctl-radius.conf", "", 0o640)
	sb.write("radius-bin/radiusd", "#!/bin/sh\n", 0o755)
	if err := os.MkdirAll(sb.path("logrotate.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	sb.env = append(append(sb.env, sandboxPathEnv(sb.dir)...), "TACCTL_RADIUS_FAMILY="+family)
	return sb
}

// listing is 'find <dir> -printf "%P %m\n" | sort' of the sandbox.
func (sb *sandbox) listing() string {
	sb.t.Helper()
	var lines []string
	_ = filepath.Walk(sb.dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || p == sb.dir {
			return nil
		}
		rel, _ := filepath.Rel(sb.dir, p)
		lines = append(lines, rel+" "+strings.TrimPrefix(info.Mode().Perm().String(), "-"))
		return nil
	})
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// The acceptance of WP3.3c: '_phase radius upgrade files <tree>' writes the
// same files as 0.1.16's _radius_upgrade_files: the logrotate file, 0644,
// byte for byte what the bash wrote (tests/fixtures/golden/radius.logrotate.*,
// generated from the 0.1.16 tag with the recipe below), and nothing else.
//
//	git archive 0.1.16 | tar -x -C "$T"; mkdir -p "$D"/{raddb,bin,logrotate.d,...}
//	: > "$D/raddb/tacctl-radius.conf"; install -m 755 /dev/null "$D/bin/radiusd"
//	env -i PATH=/usr/bin:/bin TACCTL_SKIP_SUDO=1 TACCTL_ETC=... TACCTL_STATE_DIR=... \
//	    TACCTL_RADIUS_FAMILY=<family> TACCTL_RADIUS_DIR="$D/raddb" TACCTL_RADIUS_BIN="$D/bin/radiusd" \
//	    TACCTL_LOGROTATE_DIR="$D/logrotate.d" TACCTL_SYSTEMD_DIR="$D/systemd" \
//	    bash -c 'set -euo pipefail; source "$1"; backend_radius_upgrade files /nonexistent' _ "$T/bin/tacctl.sh"
//	cp "$D/logrotate.d/tacctl-radius" tests/fixtures/golden/radius.logrotate.<family>
func TestPhaseRadiusUpgradeFilesGolden(t *testing.T) {
	for _, family := range []string{"debian", "rhel"} {
		sb := radiusSandbox(t, family)
		before := sb.listing()
		out := sb.run("", []string{"_phase", "radius", "upgrade", "files", sb.path("tree")})
		sb.expect(0, "", "")
		if out != "" || sb.err.Len() != 0 {
			t.Errorf("%s: said %q / %q", family, out, sb.err.String())
		}
		golden, err := os.ReadFile("../../tests/fixtures/golden/radius.logrotate." + family)
		if err != nil {
			t.Fatal(err)
		}
		// The golden names the family's default log directory; the sandbox
		// has its own.
		defLog := map[string]string{"debian": "/var/log/freeradius", "rhel": "/var/log/radius"}[family]
		if got := strings.ReplaceAll(sb.read("logrotate.d/tacctl-radius"), sb.path("radius-log"), defLog); got != string(golden) {
			t.Errorf("%s: logrotate differs from the 0.1.16 golden:\n%s", family, got)
		}
		want := before + "\nlogrotate.d/tacctl-radius rw-r--r--"
		if got := sb.listing(); got != strings.Join(sortedLines(want), "\n") {
			t.Errorf("%s: files\n%s\nwant\n%s", family, got, want)
		}
		if len(sb.runner.Calls()) != 0 {
			t.Errorf("%s: ran %v", family, sb.runner.Argvs())
		}
	}
	// Not set up by tacctl (no drop-in, no rendered config): nothing.
	sb := radiusSandbox(t, "debian")
	if err := os.Remove(sb.path("raddb/tacctl-radius.conf")); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"_phase", "radius", "upgrade", "files"})
	sb.expect(0, "", "")
	if _, err := os.Stat(sb.path("logrotate.d/tacctl-radius")); err == nil {
		t.Error("written for a backend tacctl has not set up")
	}
}

func sortedLines(s string) []string {
	l := strings.Split(s, "\n")
	sort.Strings(l)
	return l
}

// Several phases in one process, and the lines they leave for the closing
// summary: uninstall data with --keep-logs archives the logs and says
// where ('SAVED ...').
func TestPhaseRadiusUninstallKeepLogs(t *testing.T) {
	sb := radiusSandbox(t, "debian")
	sb.write("radius-log/tacctl-auth.log", "x\n", 0o640)
	out := plain(sb.run("", []string{"_phase", "radius", "uninstall", "stop,data", "--keep-logs"}))
	sb.expect(0, "", "")
	re := regexp.MustCompile(`(?m)^\[INFO\] RADIUS logs saved to (` + regexp.QuoteMeta(sb.path("root")) + `/tacctl-radius-logs-\d{8}_\d{6}\.tar\.gz)\n`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("output:\n%s", out)
	}
	if !strings.HasSuffix(out, "SAVED RADIUS logs saved to: "+m[1]+"\n") {
		t.Errorf("no SAVED line:\n%s", out)
	}
	if !strings.Contains(strings.Join(sb.runner.Argvs(), "\n"), "tar czf "+m[1]+" -C "+sb.path("radius-log")+" tacctl-auth.log") {
		t.Errorf("calls %v", sb.runner.Argvs())
	}
	for _, f := range []string{"raddb/tacctl-radius.conf", "radius-log/tacctl-auth.log"} {
		if _, err := os.Stat(sb.path(f)); err == nil {
			t.Errorf("%s left", f)
		}
	}
}

// A phase that fails is named with its status; the ones after it do not
// run.
func TestPhaseFailure(t *testing.T) {
	sb := radiusSandbox(t, "debian")
	sb.run("", []string{"_phase", "radius", "install", "start,files"})
	sb.expect(1, "", "was not rendered.")
	errs := plain(sb.err.String())
	if !strings.Contains(errs, "was not rendered.\n[ERROR] Backend 'radius': install step 'start' failed (exit 1).\n") {
		t.Errorf("stderr %q", errs)
	}
	if _, err := os.Stat(sb.path("logrotate.d/tacctl-radius")); err == nil {
		t.Error("the phase after the failure ran")
	}
}

// Usage errors (exit 2), an unknown backend (exit 2), the hidden command's
// place in the tree.
func TestPhaseUsage(t *testing.T) {
	sb := newSandbox(t, true)
	usage := "[ERROR] " + phaseUsage + "\n"
	for _, args := range [][]string{
		{"_phase"},
		{"_phase", "radius"},
		{"_phase", "radius", "upgrade"},
		{"_phase", "radius", "upgrade", "files", "/t", "extra"},
		{"_phase", "radius", "reinstall", "files"},
		{"_phase", "radius", "uninstall", "data", "/tree"},
		{"_phase", "radius", "upgrade", "files", "--keep-logs"},
	} {
		sb.run("", args)
		if sb.code != 2 || plain(sb.err.String()) != usage || sb.out.Len() != 0 {
			t.Errorf("%q: %d %q %q", args, sb.code, sb.out.String(), sb.err.String())
		}
	}
	sb.run("", []string{"_phase", "radius", "upgrade", "files,bogus"})
	sb.expect(2, "", "[ERROR] Unknown upgrade phase 'bogus' (phases: preflight build config files finish).")
	sb.run("", []string{"_phase", "radius", "install", "stop"})
	sb.expect(2, "", "[ERROR] Unknown install phase 'stop' (phases: build files account start).")
	sb.run("", []string{"_phase", "ldap", "upgrade", "files"})
	sb.expect(2, "", "[ERROR] Unknown backend 'ldap'.")
	// Hidden: no usage, no completion.
	if c := child(newRoot(&invocation{app: newHarness(t, nil).app}), "_phase"); c == nil || !c.Hidden {
		t.Error("_phase is not a hidden command")
	}
}
