package cli

// The 'log' family (lib/service.sh cmd_log at 0.1.16), native since WP2.4d.
// Each backend prints its own section (Backend.Log, Backend.Accounting):
// every enabled backend, or the one --backend names. With more than one at
// work each section has a heading naming its backend; with one, the output
// is what it always was.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// logSpecs are the arguments of each verb, for completion (args.go).
var logSpecs = map[string]Spec{
	"tail":       {MaxArgs: 1, Flags: []Flag{logBackendFlag, {Names: []string{"-f", "--follow"}}}},
	"search":     {MinArgs: 1, MaxArgs: 1, Args: []string{KindUsers}, Flags: []Flag{logBackendFlag}},
	"failures":   {Flags: []Flag{logBackendFlag}},
	"accounting": {MaxArgs: 1, Flags: []Flag{logBackendFlag}},
	"clear":      {Flags: []Flag{logBackendFlag, {Names: []string{"--force", "-y", "--yes"}}}},
}

var logBackendFlag = Flag{Names: []string{"--backend"}, Value: true, Kind: KindBackends}

func logCmd(inv *invocation) *cobra.Command {
	sub := func(name, short string) *cobra.Command {
		return withRun(verb(name, short), inv.native(withPreflight, func(args []string) error {
			return inv.logRun(name, args)
		}))
	}
	c := verb("log <subcommand> [--backend <id>]", "Log viewer (tail, search, failures, accounting; --backend <id>)",
		sub("tail", "Show the last N log entries (-f: then follow new ones until Ctrl-C)"),
		sub("search", "Search the logs for a username or keyword"),
		sub("failures", "Show auth failures from the last 24 hours"),
		sub("accounting", "Show last N accounting log entries"),
		sub("clear", "Purge each backend's logs (confirms)"),
	)
	// No sub-command or an unknown one (a --backend before the sub-command
	// included): the usage, exit 1.
	c.RunE = inv.native(withPreflight, func([]string) error {
		inv.write(Usage("log", nil))
		return exit(1)
	})
	return c
}

// logRun is cmd_log for one sub-command: --backend <id> or --backend=<id>
// anywhere among args picks one backend; the other arguments go to every
// backend's log (accounting: its accounting tail) in order. A backend
// that fails ends the command with its status, as errexit does in bash.
func (inv *invocation) logRun(sub string, args []string) error {
	only, hasOnly, follow := "", false, false
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case sub == "tail" && (a == "-f" || a == "--follow"):
			follow = true
		case a == "--backend":
			if arg(args, i+1) == "" {
				return inv.usageErr("--backend needs a backend id. Usage: tacctl log " + sub + " [--backend <id>] ...")
			}
			only, hasOnly = args[i+1], true
			i++
		case strings.HasPrefix(a, "--backend="):
			only = strings.TrimPrefix(a, "--backend=")
			hasOnly = only != ""
		default:
			rest = append(rest, a)
		}
	}
	ids, err := inv.enabledOrFail()
	if err != nil {
		return err
	}
	set := inv.app.Backends()
	if hasOnly {
		if !set.Registry.Has(only) {
			return inv.usageErr("Unknown backend '" + only + "' (known: " + strings.Join(set.IDs(), " ") + ").")
		}
		ids = []string{only}
	}
	multi := len(ids) > 1
	for _, id := range ids {
		b, err := set.Get(id)
		if err != nil {
			return err
		}
		if multi {
			inv.write(backend.Heading(b))
		}
		if sub == "accounting" {
			err = b.Accounting(inv.ctx, "tail", rest, inv.stdout())
		} else {
			err = b.Log(inv.ctx, sub, rest, inv.stdout())
		}
		if err != nil {
			return err
		}
	}
	if follow {
		return inv.logFollow(ids, multi)
	}
	return nil
}

// logFollow is 'log tail -f' after the tails: every backend's follow
// commands at once, each complete line written as it comes (prefixed with
// the backend's id when more than one is at work), until Ctrl-C, which
// ends the command normally.
func (inv *invocation) logFollow(ids []string, multi bool) error {
	a := inv.app
	set := a.Backends()
	var mu sync.Mutex
	var wg sync.WaitGroup
	followed := 0
	ctx := inv.ctx
	inv.echoE(ui.Bold + "Following new entries (Ctrl-C to stop)..." + ui.NC)
	for _, id := range ids {
		b, err := set.Get(id)
		if err != nil {
			return err
		}
		f, ok := b.(backend.Follower)
		if !ok {
			a.Out.WarnE("Backend '" + id + "' has no log to follow.")
			continue
		}
		prefix := ""
		if multi {
			prefix = "[" + id + "] "
		}
		for _, argv := range f.FollowArgv() {
			followed++
			w := &lineWriter{mu: &mu, w: inv.stdout(), prefix: prefix}
			wg.Add(1)
			go func(argv []string) {
				defer wg.Done()
				res, err := a.Runner.Run(ctx, execx.Cmd{Name: argv[0], Args: argv[1:], Stdout: w, Stderr: w})
				w.flush()
				if ctx.Err() == nil && (err != nil || res.Code != 0) {
					mu.Lock()
					a.Out.WarnE("Stopped following " + id + ": " + strings.Join(argv, " ") + " ended.")
					mu.Unlock()
				}
			}(argv)
		}
	}
	if followed == 0 {
		return nil
	}
	wg.Wait()
	if errors.Is(ctx.Err(), context.Canceled) {
		inv.echo("")
	}
	return nil
}

// lineWriter writes whole lines to w, each behind prefix, one writer at a
// time (mu is shared by every followed source).
type lineWriter struct {
	mu     *sync.Mutex
	w      io.Writer
	prefix string
	buf    []byte
}

func (l *lineWriter) Write(p []byte) (int, error) {
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		l.mu.Lock()
		_, _ = io.WriteString(l.w, l.prefix+string(l.buf[:i+1]))
		l.mu.Unlock()
		l.buf = l.buf[i+1:]
	}
	return len(p), nil
}

// flush writes a last line without its newline.
func (l *lineWriter) flush() {
	if len(l.buf) > 0 {
		_, _ = l.Write([]byte{'\n'})
	}
}
