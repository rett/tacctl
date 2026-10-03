package cli

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
)

// BuildInfo is what the build stamped into the binary (cmd/tacctl's
// -ldflags -X variables; bin/tacctl.sh --build sets them from git).
type BuildInfo struct {
	Version string // git describe --tags --always --dirty
	Commit  string // git rev-parse HEAD
	Date    string // the commit's date (git log -1 --format=%cI): builds stay reproducible
}

// resolved fills what the linker flags left empty from the module's VCS
// stamp (a plain 'go build' in a checkout), else "unknown", as bash's
// get_version falls back to.
func (b BuildInfo) resolved(read func() (*debug.BuildInfo, bool)) BuildInfo {
	if b.Version == "" || b.Commit == "" || b.Date == "" {
		if info, ok := read(); ok && info != nil {
			var rev, at string
			modified := false
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					rev = s.Value
				case "vcs.time":
					at = s.Value
				case "vcs.modified":
					modified = s.Value == "true"
				}
			}
			if b.Commit == "" {
				b.Commit = rev
			}
			if b.Date == "" {
				b.Date = at
			}
			if b.Version == "" && rev != "" {
				b.Version = rev[:min(7, len(rev))]
				if modified {
					b.Version += "-dirty"
				}
			}
		}
	}
	for _, f := range []*string{&b.Version, &b.Commit, &b.Date} {
		if *f == "" {
			*f = "unknown"
		}
	}
	return b
}

// writeVersion prints 'tacctl <version>' (the bash line) and, for --long,
// the commit, the commit date, the Go version and whether the test knobs
// are compiled in (new in 0.2.0, docs/plans/go-rewrite.md 3.9 item 1).
func writeVersion(w io.Writer, b BuildInfo, long bool) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "tacctl %s\n", b.Version)
	if long {
		knobs := "off"
		if app.TestKnobs {
			knobs = "on"
		}
		fmt.Fprintf(&sb, "commit:     %s\n", b.Commit)
		fmt.Fprintf(&sb, "built:      %s (commit date)\n", b.Date)
		fmt.Fprintf(&sb, "go:         %s\n", runtime.Version())
		fmt.Fprintf(&sb, "test knobs: %s\n", knobs)
	}
	_, _ = io.WriteString(w, sb.String())
}

// tierUsersGroup is TIER_USERS_GROUP (lib/dispatch.sh).
const tierUsersGroup = "tac-users"

// tierManaged reports whether the caller is one the bash tier gate decides
// on with the model (caller_tier, lib/dispatch.sh): SUDO_USER set, not root,
// and a member of tac-users. For such a caller even 'version' can be denied
// (tier "none"), so the Go side hands it to bash until the gate is ported.
func tierManaged(ctx context.Context, a *app.App) bool {
	caller := a.Env.Get("SUDO_USER")
	if caller == "" || caller == "root" {
		return false
	}
	res, err := a.Runner.Run(ctx, execx.Cmd{Name: "id", Args: []string{"-nG", "--", caller}})
	if err != nil || res.Code != 0 {
		return false
	}
	for _, g := range strings.Fields(string(res.Stdout)) {
		if g == tierUsersGroup {
			return true
		}
	}
	return false
}
