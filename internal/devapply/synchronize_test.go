package devapply

import (
	"strings"
	"testing"
)

// A device that commits with 'commit synchronize' (two routing engines, or a
// virtual chassis) prints that word at the end of every entry of its
// history. The first apply writes such an entry; the next run's pre-flight
// reads it as the newest one and goes on, on either transport. It was
// 'pre-flight: show system commit: entry 0 ends "commit synchronize"'.
func TestPreflightReadsSynchronizedCommits(t *testing.T) {
	both(t, map[string]string{"commit.synchronize": ""}, func(t *testing.T, d *device) {
		p := &planner{desired: desiredLines()}
		o := apply(t, d, p, nil)
		wantExit(t, o, ExitApplied, ResultApplied)
		h := d.srv.History()
		if len(h) < 3 || strings.Join(h[0].Options, " ") != "synchronize" || strings.Join(h[1].Options, " ") != "synchronize" || h[1].RollbackIn != 10 {
			t.Fatalf("history %+v", h[:2])
		}

		// the pre-flight of the next run reads entry 0, 'commit synchronize'
		o = apply(t, d, p, nil)
		wantExit(t, o, ExitNoChange, ResultNoChange)
		o = check(t, d, p, nil)
		wantExit(t, o, ExitNoChange, ResultNoChange)
	})
}
