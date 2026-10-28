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
// config diff', 'device config plan', 'ssh', 'device ssh': askpassWords) and
// only those, the loop
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
	"github.com/rett/tacctl/internal/shell"
)

// How a shell run came by its password cache (shellRun.cacheMode).
const (
	cacheOff = iota // none
	cacheAsk        // 'tacctl shell --password-cache': the policy is asked
	cacheOn         // the console: its policy answer said yes
)

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

// Holds reports whether a password is cached now.
func (c *passwordCache) Holds() bool { return c.ag.Cached() }

// Stop forgets the password, queueing the notice, and shuts the agent: the
// cache is off for the rest of the session ('console password-cache off').
func (c *passwordCache) Stop(why string) {
	c.ag.Forget(why)
	c.ag.Flush()
	c.ag.Close()
}

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
	c, err := inv.newPasswordCache(idle, max)
	if err != nil {
		_, _ = fmt.Fprintln(a.Out.Stderr, passwordCacheUnavailable(err))
		return nil
	}
	return c
}

// newPasswordCache starts an agent with the lifetimes (the defaults for 0) and
// its socket.
func (inv *invocation) newPasswordCache(idle, max time.Duration) (*passwordCache, error) {
	if idle <= 0 {
		idle = askpass.DefaultIdle
	}
	if max <= 0 {
		max = askpass.DefaultMax
	}
	c := &passwordCache{}
	ag, err := inv.hooks.agent(askpass.Options{UID: os.Geteuid(), Idle: idle, Max: max, Notify: c.note})
	if err != nil {
		return nil, err
	}
	dir, err := askpass.SocketDir(inv.app.Env.Get, os.Geteuid())
	if err == nil {
		_, _, err = ag.Listen(dir)
	}
	if err != nil {
		ag.Close()
		return nil, err
	}
	// The token Listen made is never handed out: the lines get their own.
	ag.EndLine()
	c.ag = ag
	return c, nil
}

// startPasswordCacheNow is shell.Options.CacheStart: 'console password-cache
// on' has saved the person's choice, and the running session starts the
// cache if the policy now says it is allowed for the tier and on for the
// person (the answer is asked again, so a tier a superuser closed meanwhile
// stays closed). The agent it returns replaces the session's (live).
func (inv *invocation) startPasswordCacheNow(r shellRun, live **passwordCache) (shell.PasswordCache, error) {
	pol, err := inv.callerPolicy(r)
	switch {
	case err != nil:
		return nil, errors.New("password cache unavailable: the policy could not be read")
	case !pol.PCAllowed:
		return nil, errors.New("password cache unavailable: it is not allowed for your tier (a superuser allows it with: tacctl console password-cache tiers <tiers>)")
	case !pol.PasswordCache:
		return nil, errors.New("password cache unavailable: it is off in your settings (console password-cache on)")
	}
	c, err := inv.newPasswordCache(pol.PCIdle, pol.PCMax)
	if err != nil {
		return nil, errors.New(passwordCacheUnavailable(err))
	}
	*live = c
	return c, nil
}

// callerPolicy asks the root side for the caller's policy line.
func (inv *invocation) callerPolicy(r shellRun) (console.Remote, error) {
	ctx, cancel := context.WithTimeout(inv.ctx, viewTimeout)
	defer cancel()
	args := append(append([]string{"-n"}, r.extraEnv...), r.exe, "_console-policy")
	res, err := inv.app.Runner.Run(ctx, execx.Cmd{Name: "sudo", Args: args})
	if err != nil || res.Code != 0 {
		return console.Remote{}, errors.New("the policy could not be read")
	}
	pol, ok := console.ParseRemote(string(res.Stdout))
	if !ok {
		return console.Remote{}, errors.New("the policy could not be read")
	}
	return pol, nil
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
	pol, err := inv.callerPolicy(r)
	if err != nil {
		_, _ = fmt.Fprintln(a.Out.Stderr, "password cache unavailable: the policy could not be read")
		return false, 0, 0
	}
	if !pol.PCAllowed {
		_, _ = fmt.Fprintln(a.Out.Stderr, "password cache unavailable: it is not enabled for your tier (an administrator enables it with: tacctl console password-cache tiers <tiers>)")
		return false, 0, 0
	}
	return true, pol.PCIdle, pol.PCMax
}

// askpassWords reports whether a shell line uses the password cache: the
// lines tier.AskpassKeep keeps TACCTL_ASKPASS for, and for which the root
// side consumes the line's single get. 'device config diff' and 'device
// config plan' log in to nothing unless they are given --pull (before any
// '--'), so they are not among them without it: the cache stays shut for
// such a line.
func askpassWords(words []string) bool {
	switch {
	case len(words) == 0:
		return false
	case words[0] == "ssh":
		return true
	case words[0] == "device" && len(words) > 1 && words[1] == "ssh":
		return true
	// a read as a device's local account (--login, 0.2.9 D136) never asks
	// the cache: its line leaves it shut
	case words[0] == "device" && len(words) > 2 && words[1] == "config" && localLoginLine(words[3:]):
		return false
	case words[0] == "device" && len(words) > 2 && words[1] == "config" && words[2] == "pull":
		return true
	// 'device onboard' asks the invoking user's own password after the
	// review (D136), which the cache may answer; the local account's never
	// comes from it
	case words[0] == "device" && len(words) > 1 && words[1] == "onboard":
		return true
	// 'device collect' logs in to addresses nobody registered as the caller
	// (the cache may answer); with --login it is a local account's one-shot
	// password, which never comes from the cache, so the line leaves it shut
	case words[0] == "device" && len(words) > 1 && words[1] == "collect":
		return !localLoginLine(words[2:])
	// 'device enroll' pulls the devices it registered, and may apply them,
	// as the caller (0.2.17 D269)
	case words[0] == "device" && len(words) > 1 && words[1] == "enroll":
		return true
	// 'device config apply' (with or without --check) logs in to the
	// devices as the caller (0.2.9, D141); 'shapes' reads and writes the
	// shape store and logs in to nothing, so its lines leave the cache shut
	// (and the sudoers alias does not name them).
	case words[0] == "device" && len(words) > 2 && words[1] == "config" && words[2] == "apply":
		return true
	// 'block adopt' reads one device with the caller's login (0.2.7):
	// 'scope block <scope> juniper adopt <device> <block>' and 'device block
	// <name> adopt <block>'.
	case words[0] == "scope" && len(words) > 4 && words[1] == "block" && words[4] == "adopt":
		return true
	case words[0] == "device" && len(words) > 3 && words[1] == "block" && words[3] == "adopt":
		return true
	case words[0] == "device" && len(words) > 2 && words[1] == "config" && (words[2] == "diff" || words[2] == "plan"):
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

// localLoginLine reports whether the words of a 'device config' verb give
// --login before any '--'.
func localLoginLine(words []string) bool {
	for _, w := range words {
		switch {
		case w == "--":
			return false
		case w == "--login" || strings.HasPrefix(w, "--login="):
			return true
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
	if inv.hooks != nil && inv.hooks.askpassFromApp {
		// A test: the app's environment only, no process state touched.
		return inv.app.Env.Get(askpass.EnvVar)
	}
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
