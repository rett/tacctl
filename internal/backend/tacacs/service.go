package tacacs

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
)

// systemctl runs systemctl with its output where 0.1.16 lets it go: stdout
// and stderr to the given writers (nil: discarded, as '>/dev/null' and
// '2>/dev/null'). It returns the exit status (127 when systemctl could not
// be run) and what was captured of stdout when stdout is nil.
func (b *Backend) systemctl(ctx context.Context, stdout, stderr io.Writer, args ...string) (int, string) {
	c := execx.Cmd{Name: "systemctl", Args: args, Stdout: stdout, Stderr: stderr}
	if stderr == nil {
		c.Stderr = io.Discard
	}
	res, err := b.env.Runner.Run(ctx, c)
	if err != nil && res.Code == 0 {
		res.Code = 127
	}
	return res.Code, string(res.Stdout)
}

// run runs a program with stdout passed through to the invocation's Stdout
// and stderr to its Stderr (a plain 'systemctl restart tacquito' line of
// the bash), returning the exit status.
func (b *Backend) run(ctx context.Context, args ...string) int {
	code, _ := b.systemctl(ctx, b.env.Out.Stdout, b.env.Out.Stderr, args...)
	return code
}

// quiet runs systemctl with stderr discarded and stdout passed through
// ('systemctl ... 2>/dev/null').
func (b *Backend) quiet(ctx context.Context, args ...string) int {
	code, _ := b.systemctl(ctx, b.env.Out.Stdout, nil, args...)
	return code
}

// capture is $(systemctl ... 2>/dev/null): stdout without its trailing
// newlines, and the exit status.
func (b *Backend) capture(ctx context.Context, args ...string) (string, int) {
	code, out := b.systemctl(ctx, nil, nil, args...)
	return strings.TrimRight(out, "\n"), code
}

// showProperty is 'systemctl show <unit> --property=<p> 2>/dev/null | cut
// -d= -f2'.
func (b *Backend) showProperty(ctx context.Context, unit, prop string) string {
	_, out := b.systemctl(ctx, nil, nil, "show", unit, "--property="+prop)
	return cutField2(out)
}

// cutField2 is 'cut -d= -f2' over text, as $(...) returns it: the second
// '='-separated field of each line, a line without '=' as it is.
func cutField2(text string) string {
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if f := strings.Split(l, "="); len(f) > 1 {
			lines[i] = f[1]
		}
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// Service is backend_tacacs_service. Without a listener (or with
// 'default') the action is on tacquito.service, which for start, stop and
// restart is every listener (the instances are PartOf= and WantedBy= it),
// and for is-active, since and pid the default listener's process; with
// one, it is on that listener's instance only. A changed config is always
// followed by a restart: tacquito has no reload of its own.
func (b *Backend) Service(ctx context.Context, action backend.ServiceAction, listener string) (string, error) {
	unit := Service
	if listener != "" && listener != "default" {
		unit = rtacacs.Unit(listener)
	}
	switch action {
	case backend.ServiceRestart, backend.ServiceReload:
		if b.quiet(ctx, "restart", unit) == 0 {
			b.out().Info("Service restarted.")
		} else {
			b.out().Warn("Service restart failed — run: sudo systemctl restart " + unit)
		}
		// A render may have added or removed a listener.
		if unit == Service {
			b.instancesSync(ctx)
		}
		return "", nil
	case backend.ServiceStart, backend.ServiceStop:
		return "", statusError(b.run(ctx, string(action), unit), "systemctl "+string(action)+" "+unit)
	case backend.ServiceEnable, backend.ServiceDisable:
		// At boot: every listener's unit, as start and stop reach them
		// through tacquito.service. A unit that is not there (an instance
		// whose listener was removed) is not an error for disable.
		units := []string{unit}
		if unit == Service {
			units = b.unitsAll()
		}
		return "", statusError(b.run(ctx, append([]string{string(action)}, units...)...), "systemctl "+string(action))
	case backend.ServiceIsActive:
		word, code := b.capture(ctx, "is-active", unit)
		return word, statusError(code, unit+" is "+word)
	case backend.ServiceSince:
		return b.showProperty(ctx, unit, "ActiveEnterTimestamp"), nil
	case backend.ServicePID:
		return b.showProperty(ctx, unit, "MainPID"), nil
	}
	return "", backend.ErrUnsupported
}

// statusError is a non-zero exit status of a program whose own messages
// were its report, as an *backend.Error carrying that status.
func statusError(code int, reason string) error {
	if code == 0 {
		return nil
	}
	return &backend.Error{Code: code, Reason: reason}
}

// instancesSync is _tacacs_instances_sync: every listener other than the
// default one has its instance enabled and running, and an enabled
// instance without a listener is stopped and disabled. Never fails.
func (b *Backend) instancesSync(ctx context.Context) {
	var names []string
	for _, l := range b.listenerLines() {
		if l.Name == "" || l.Name == "default" {
			continue
		}
		names = append(names, l.Name)
		unit := rtacacs.Unit(l.Name)
		if b.quiet(ctx, "enable", "--quiet", "--now", unit) != 0 {
			b.out().Warn("Could not enable and start " + unit + " — check: systemctl status " + unit)
		}
	}
	links, _ := filepath.Glob(filepath.Join(b.env.Paths.TacacsUnitDir, "tacquito.service.wants", "tacquito@*.service"))
	for _, link := range links {
		if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
			continue
		}
		inst := link[strings.LastIndex(link, "/tacquito@")+len("/tacquito@"):]
		inst = strings.TrimSuffix(inst, ".service")
		if slices.Contains(names, inst) {
			continue
		}
		b.quiet(ctx, "disable", "--quiet", "--now", rtacacs.Unit(inst))
	}
}

// settle is how long a restarted unit must stay up before a settings
// change counts as applied (TACCTL_SETTLE_SECONDS, sleep(1)'s syntax: a
// number with an optional s, m, h or d; one sleep cannot parse is none).
func (b *Backend) settle() time.Duration {
	s := b.env.Paths.SettleSeconds
	mult := 1.0
	if n := len(s); n > 0 {
		switch s[n-1] {
		case 's':
			s = s[:n-1]
		case 'm':
			s, mult = s[:n-1], 60
		case 'h':
			s, mult = s[:n-1], 3600
		case 'd':
			s, mult = s[:n-1], 86400
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 || math.IsNaN(f) {
		return 0
	}
	return time.Duration(f * mult * float64(time.Second))
}

func (b *Backend) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	if b.Sleep != nil {
		b.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// unitSettled is _tacacs_unit_settled: has the unit stayed up? A daemon
// that cannot bind its address exits within milliseconds of a start
// systemd already called successful.
func (b *Backend) unitSettled(ctx context.Context, unit string) bool {
	b.sleep(ctx, b.settle())
	code, _ := b.systemctl(ctx, b.env.Out.Stdout, b.env.Out.Stderr, "is-active", "--quiet", unit)
	return code == 0
}
