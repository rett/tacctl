package cli

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/app"
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

// builtAt is the commit date as the person reading it knows it: the
// RFC 3339 stamp in the local zone as 'date time ZONE', or the stamp as it
// is when it is not one (a build that has none says "unknown").
func builtAt(stamp string) string {
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return stamp
	}
	return t.Local().Format("2006-01-02 15:04 MST")
}

// writeVersion prints 'tacctl <version>' (the bash line, also the first line
// of --long) and, for --long, the project, the address, the licence and the
// copyright under it after a blank line, then the commit, the
// commit date, the Go version and whether the test knobs are compiled in
// (new in 0.2.0, docs/plans/go-rewrite.md 3.9 item 1). The field labels
// are what bin/tacctl.sh and the upgrade checks read ('commit:').
func writeVersion(w io.Writer, b BuildInfo, long bool) {
	var sb strings.Builder
	if !long {
		fmt.Fprintf(&sb, "tacctl %s\n", b.Version)
		_, _ = io.WriteString(w, sb.String())
		return
	}
	knobs := "off"
	if app.TestKnobs {
		knobs = "on"
	}
	fmt.Fprintf(&sb, "tacctl %s\n\n", b.Version)
	sb.WriteString("Pluggable network-device AAA management\n")
	sb.WriteString("https://github.com/rett/tacctl · MIT License\n")
	sb.WriteString("Copyright (c) 2026 Everett C. Haimes III\n\n")
	for _, f := range [][2]string{
		{"commit:", b.Commit},
		{"built:", builtAt(b.Date) + " (commit date)"},
		{"go:", runtime.Version()},
		{"test knobs:", knobs},
	} {
		fmt.Fprintf(&sb, "%-12s %s\n", f[0], f[1])
	}
	_, _ = io.WriteString(w, sb.String())
}
