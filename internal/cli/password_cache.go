package cli

// The password cache of docs/plans/0.2.4-plan.md D70, the wiring (the
// agent, the socket, the in-flight rules and the lifetimes are
// internal/askpass).
//
// Shell side: the interactive 'tacctl shell' and the login console start
// an askpass agent in their own process when the policy turns the cache on
// for the caller's tier (the console) or when 'tacctl shell
// --password-cache' asks for it and the policy allows it. The agent is shut
// between lines. For each line that uses it ('device config pull', 'device
// config diff', 'ssh', 'device ssh': askpassWords) and only those, the loop
// opens it with a token made for that line and closes it, killing the
// token, when the line ends; '<socket>:<token>' goes to that line in the
// environment of the sudo process, never on sudo's command line, and the
// tiers drop-ins keep it for those lines only (tier.AskpassKeep).
//
// Root side: 'device config pull' (device_config_pull.go) and 'tacctl ssh'
// (ssh.go) read the variable once, remove it from their environment, and
// ask the agent as the user the sudo line came from (SUDO_UID).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
)

// How a shell run came by its password cache (shellRun.cacheMode).
const (
	cacheOff = iota // none
	cacheAsk        // 'tacctl shell --password-cache': the policy is asked
	cacheOn         // the console: its policy answer said yes
)

// newAskpassAgent makes the agent (askpass.New: tests replace it to
// simulate a memory limit).
var newAskpassAgent = askpass.New

// setNotDumpable marks the process not dumpable (tests replace it).
var setNotDumpable = askpass.MarkNotDumpable

// passwordCacheUnavailable is the one line the shell prints when it asked
// for a cache and could not have it (for the lock, the first words).
func passwordCacheUnavailable(err error) string {
	switch {
	case errors.Is(err, askpass.ErrNoLock):
		return "password cache unavailable: cannot lock memory"
	case errors.Is(err, askpass.ErrTraced):
		return "password cache unavailable: this process is being traced"
	case errors.Is(err, askpass.ErrNoDir):
		return "password cache unavailable: no private directory for its socket"
	}
	return "password cache unavailable: " + shortReason(err)
}

// passwordCache is the shell's agent and the lines it has to say.
type passwordCache struct {
	ag *askpass.Agent

	mu    sync.Mutex
	notes []string
}

// Notices of the cache (shell.PasswordCache).
const (
	noticeStored = "password cached for this session (console password-cache)"
)

func noticeForgotten(why string) string { return "password forgotten (" + why + ")" }

func (c *passwordCache) note(ev askpass.Event) {
	var l string
	switch ev.Kind {
	case askpass.EventStored:
		l = noticeStored
	case askpass.EventForgotten:
		l = noticeForgotten(ev.Why)
	default:
		return
	}
	c.mu.Lock()
	c.notes = append(c.notes, l)
	c.mu.Unlock()
}

// BeginLine, EndLine, Forget and Notices make the cache a
// shell.PasswordCache. The cache opens for the lines askpassWords names and
// no others, each with a token of its own.
func (c *passwordCache) BeginLine(words []string) string {
	if !askpassWords(words) {
		return ""
	}
	return c.ag.BeginLine()
}

func (c *passwordCache) EndLine() { c.ag.EndLine() }

func (c *passwordCache) Forget(why string) bool { return c.ag.Forget(why) }

func (c *passwordCache) Notices() []string {
	c.ag.Flush() // events queued by other goroutines (a store over the socket)
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.notes
	c.notes = nil
	return n
}

// close forgets the password and removes the socket (silently).
func (c *passwordCache) close() {
	if c == nil {
		return
	}
	c.ag.Forget(askpass.WhyExit)
	c.ag.Close()
}

// openPasswordCache starts the agent of an interactive shell run, or says
// why not and returns nil. Only the interactive shell has a process that
// persists between lines. The agent is created only when the policy turned
// the cache on (the console's answer, or the answer asked for under
// --password-cache): nothing is allocated, locked or marked otherwise.
func (inv *invocation) openPasswordCache(r shellRun, managed bool) *passwordCache {
	a := inv.app
	if r.cacheMode == cacheOff {
		return nil
	}
	if r.mode != shellInteractive {
		if r.cacheMode == cacheAsk {
			_, _ = fmt.Fprintln(a.Out.Stderr, "tacctl shell: --password-cache applies to the interactive shell only (-c and batch lines keep no process to hold it)")
		}
		return nil
	}
	idle, max := r.pcIdle, r.pcMax
	if r.cacheMode == cacheAsk {
		allowed, i, m := inv.plainShellCachePolicy(r, managed)
		if !allowed {
			return nil
		}
		idle, max = i, m
	}
	if idle <= 0 {
		idle = askpass.DefaultIdle
	}
	if max <= 0 {
		max = askpass.DefaultMax
	}
	c := &passwordCache{}
	ag, err := newAskpassAgent(askpass.Options{UID: os.Geteuid(), Idle: idle, Max: max, Notify: c.note})
	if err != nil {
		_, _ = fmt.Fprintln(a.Out.Stderr, passwordCacheUnavailable(err))
		return nil
	}
	dir, err := askpass.SocketDir(a.Env.Get, os.Geteuid())
	if err == nil {
		_, _, err = ag.Listen(dir)
	}
	if err != nil {
		ag.Close()
		_, _ = fmt.Fprintln(a.Out.Stderr, passwordCacheUnavailable(err))
		return nil
	}
	// The token Listen made is never handed out: the lines get their own.
	ag.EndLine()
	c.ag = ag
	return c
}

// plainShellCachePolicy is whether 'tacctl shell --password-cache' may have
// the cache and for how long. A caller who is not a tac-users member is
// not under a tier policy (they ask for it themselves); a managed caller's
// tier must be one the policy opened the cache to. When the policy cannot
// be read the cache stays off.
func (inv *invocation) plainShellCachePolicy(r shellRun, managed bool) (allowed bool, idle, max time.Duration) {
	a := inv.app
	if !managed {
		return true, askpass.DefaultIdle, askpass.DefaultMax
	}
	ctx, cancel := context.WithTimeout(inv.ctx, viewTimeout)
	defer cancel()
	args := append(append([]string{"-n"}, r.extraEnv...), r.exe, "_console-policy")
	res, err := a.Runner.Run(ctx, execx.Cmd{Name: "sudo", Args: args})
	if err != nil || res.Code != 0 {
		_, _ = fmt.Fprintln(a.Out.Stderr, "password cache unavailable: the policy could not be read")
		return false, 0, 0
	}
	pol, ok := console.ParseRemote(string(res.Stdout))
	if !ok || !pol.PasswordCache {
		_, _ = fmt.Fprintln(a.Out.Stderr, "password cache unavailable: it is not enabled for your tier (an administrator enables it with: tacctl console password-cache tiers <tiers>)")
		return false, 0, 0
	}
	return true, pol.PCIdle, pol.PCMax
}

// askpassWords reports whether a shell line uses the password cache: the
// lines tier.AskpassKeep keeps TACCTL_ASKPASS for, and for which the root
// side consumes the line's single get. 'device config diff' logs in to
// nothing unless it is given --pull (before any '--'), so it is not one
// of them without it: the cache stays shut for such a line.
func askpassWords(words []string) bool {
	switch {
	case len(words) == 0:
		return false
	case words[0] == "ssh":
		return true
	case words[0] == "device" && len(words) > 1 && words[1] == "ssh":
		return true
	case words[0] == "device" && len(words) > 2 && words[1] == "config" && words[2] == "pull":
		return true
	case words[0] == "device" && len(words) > 2 && words[1] == "config" && words[2] == "diff":
		for _, w := range words[3:] {
			switch w {
			case "--":
				return false
			case "--pull":
				return true
			}
		}
	}
	return false
}

// environWith is environ with TACCTL_ASKPASS replaced by value, or removed
// when value is empty.
func environWith(environ []string, value string) []string {
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		if strings.HasPrefix(kv, askpass.EnvVar+"=") {
			continue
		}
		out = append(out, kv)
	}
	if value != "" {
		out = append(out, askpass.EnvVar+"="+value)
	}
	return out
}

// --- the root side ------------------------------------------------------------

// processAskpass is the value TACCTL_ASKPASS had when the process started
// (captureAskpass): the environment itself no longer has it.
var processAskpass string

// captureAskpass is the first thing Main does: it takes TACCTL_ASKPASS out of
// environ, which it returns without it, and out of the process's own
// environment (so a program this process starts never inherits the token),
// and keeps the value for the one verb that uses it.
func captureAskpass(environ []string) []string {
	out := make([]string, 0, len(environ))
	found := false
	for _, kv := range environ {
		if v, ok := strings.CutPrefix(kv, askpass.EnvVar+"="); ok {
			processAskpass, found = v, true
			continue
		}
		out = append(out, kv)
	}
	if found {
		// Removing the variable, not reading the environment.
		_ = os.Unsetenv(askpass.EnvVar) //nolint:forbidigo // removing the token, not reading the environment
	}
	return out
}

// askpassValue is the cache's value for this process, once: what
// captureAskpass kept (cleared as it is handed over), or, where the
// invocation was built without Main (the in-process callers), the app's
// environment. The process environment is cleared of it either way.
func (inv *invocation) askpassValue() string {
	v := processAskpass
	processAskpass = ""
	if v == "" {
		v = inv.app.Env.Get(askpass.EnvVar)
	}
	_ = os.Unsetenv(askpass.EnvVar) //nolint:forbidigo // removing the token, not reading the environment
	return v
}

// takeAskpass is the client of the cache the variable names, as the user
// sudo was run by (SUDO_UID: the socket must be theirs), or nil when there
// is no cache, the value is malformed, or the process was not run through
// sudo by a user. The value is handed over once.
func (inv *invocation) takeAskpass() *askpass.Client {
	v := inv.askpassValue()
	if v == "" {
		return nil
	}
	uid, err := strconv.Atoi(inv.app.Env.Get("SUDO_UID"))
	if err != nil || uid <= 0 {
		return nil
	}
	c, err := askpass.NewClient(v)
	if err != nil {
		return nil
	}
	c.ExpectUID = uid
	return c
}
