package cli

// The seen data at the start of a session: an interactive session of the
// console or of 'tacctl shell' starts 'device scan --if-stale --quiet' in the
// background, so that by the time the person looks at 'device list' the
// logins are in it, and nothing they type waits for it. The scan is the
// ordinary one under the same sudo rules as any line of the session (the
// operator tier's 'device scan *'); it does nothing when the cache is
// younger than five minutes or another scan holds it, so sessions that start
// together run one scan, and it connects to a device's ssh port for its
// host keys only when that device's last scan is a day old. It outlives the
// session, throws its output away, and a refusal or a failure is silent.

import (
	"context"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

// seenRefreshWords is the line a session start runs.
var seenRefreshWords = []string{"device", "scan", "--if-stale", "--quiet"}

// startSeenRefresh starts the background scan for a session of tier t. exe
// and extraEnv are what the session's own lines run with.
func (inv *invocation) startSeenRefresh(exe string, t tier.Tier, extraEnv []string) {
	a := inv.app
	if a.Paths.SkipSudo || !tier.Permits(t, "device", "scan") {
		return
	}
	argv := shellArgv(exe, seenRefreshWords, true, extraEnv, a.Env.Get)
	p, err := a.Runner.Start(context.Background(), execx.Cmd{Name: argv[0], Args: argv[1:], Detach: true})
	if err != nil || p == nil {
		return
	}
	// Reaped when it ends if this process is still there to do it.
	go func() { _, _ = p.Wait() }()
}
