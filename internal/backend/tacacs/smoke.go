package tacacs

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rett/tacctl/internal/execx"
)

// SmokeResult is the verdict of the daemon load-smoke, with the bash
// return status as its value (store_smoke_hook: 0 passed, 2 skipped,
// anything else failed).
type SmokeResult int

// The verdicts.
const (
	SmokePassed  SmokeResult = 0 // tacquito loaded the file and served
	SmokeFailed  SmokeResult = 1 // it did not (message written)
	SmokeSkipped SmokeResult = 2 // no daemon binary on this machine
)

// The defaults of the load-smoke: how long tacquito gets to serve
// (TACACS_SMOKE_SECONDS), how often its log is looked at, and how long a
// daemon told to stop gets before it is killed (timeout -k 1).
const (
	SmokeTimeDefault = 5 * time.Second
	smokePoll        = 100 * time.Millisecond
	smokeKillAfter   = time.Second
)

// The log lines that tell a loaded daemon (both) and the causes of a
// failure the message names.
var (
	smokeServing = [][]byte{[]byte("serve on "), []byte("updated all providers from config source")}
	smokeCauses  = []struct{ line, msg string }{
		{"no users were unmarshalled", "Load-smoke: tacquito refuses a config with no users."},
		{"no secret providers were unmarshalled", "Load-smoke: tacquito refuses a config with no scopes."},
		{"error fetching config", "Load-smoke: tacquito could not parse the config."},
	}
)

// lockedBuffer collects the daemon's stderr while it is read.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) has(subs ...[]byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range subs {
		if !bytes.Contains(l.buf.Bytes(), s) {
			return false
		}
	}
	return true
}

// LoadSmoke is tacacs_load_smoke: start the real tacquito on a copy of a
// rendered tacquito.yaml and see whether it loads it. Loaded means the
// listener is up and the loader built its providers from the file; a config
// the loader rejects logs 'error fetching config' and the process exits
// (with status 0, so the log is what counts).
//
// Isolation: every flag that names a resource is set, so nothing falls
// back to a production default: the listener and the metrics exporter bind
// 127.0.0.1 on a kernel-chosen port (never :49), the accounting log and the
// config live in a private temp dir (the config in a directory of its own:
// tacquito watches it and logs every event there). The daemon runs under a
// deadline (so it dies even if tacctl is killed), is stopped as soon as the
// verdict is known, and the temp dir is removed. The failure message names
// the cause without echoing the daemon's log (a YAML error can quote a line
// of the config).
func (b *Backend) LoadSmoke(ctx context.Context, rendered string) SmokeResult {
	bin := b.tacquitoBin()
	if !executable(bin) {
		return SmokeSkipped
	}
	if !isRegular(rendered) {
		b.out().Error("Load-smoke: " + rendered + " not found.")
		return SmokeFailed
	}
	limit := b.SmokeTime
	if limit <= 0 {
		limit = SmokeTimeDefault
	}
	tmpd, err := os.MkdirTemp("", "tmp.")
	if err != nil {
		b.out().Error("Load-smoke: " + err.Error())
		return SmokeFailed
	}
	defer func() { _ = os.RemoveAll(tmpd) }()
	confDir, runDir := filepath.Join(tmpd, "conf"), filepath.Join(tmpd, "run")
	cfg := filepath.Join(confDir, "tacquito.yaml")
	err = os.Mkdir(confDir, 0o700)
	if err == nil {
		err = os.Mkdir(runDir, 0o700)
	}
	if err == nil {
		err = copyFile(rendered, cfg)
	}
	if err != nil {
		b.out().Error("Load-smoke: " + err.Error())
		return SmokeFailed
	}

	dctx, cancel := context.WithTimeout(ctx, limit+smokeKillAfter)
	defer cancel()
	log := &lockedBuffer{}
	p, err := b.env.Runner.Start(dctx, execx.Cmd{
		Name: bin,
		Args: []string{"-config", cfg, "-network", "tcp", "-address", "127.0.0.1:0",
			"-acct-log-path", filepath.Join(runDir, "accounting.log"),
			"-metrics-address", "127.0.0.1:0", "-level", "20"},
		Stdout: io.Discard,
		Stderr: log,
	})
	verdict := SmokeFailed
	if err == nil {
		done := make(chan struct{})
		go func() {
			_, _ = p.Wait()
			close(done)
		}()
		verdict = b.smokeWait(ctx, log, done, limit)
		// Stop it: TERM, then KILL (the deadline's cancel) if it lingers.
		_ = p.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(smokeKillAfter):
			cancel()
			<-done
		}
	}
	if verdict != SmokePassed {
		msg := "Load-smoke: tacquito did not start serving within " + seconds(limit) + "s."
		for _, c := range smokeCauses {
			if log.has([]byte(c.line)) {
				msg = c.msg
				break
			}
		}
		b.out().Error(msg)
	}
	return verdict
}

// smokeWait looks at the daemon's log every poll until both serving lines
// are there (passed), the daemon is gone or the time is up (failed).
func (b *Backend) smokeWait(ctx context.Context, log *lockedBuffer, done <-chan struct{}, limit time.Duration) SmokeResult {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(smokePoll)
	defer tick.Stop()
	for {
		if log.has(smokeServing...) {
			return SmokePassed
		}
		select {
		case <-done:
			// Gone: whatever it wrote before it went is all there is.
			if log.has(smokeServing...) {
				return SmokePassed
			}
			return SmokeFailed
		case <-deadline.C:
			return SmokeFailed
		case <-ctx.Done():
			return SmokeFailed
		case <-tick.C:
		}
	}
}

// seconds is a duration as the message counts it (whole seconds, as
// TACACS_SMOKE_SECONDS is; a fraction is printed as Go's %g).
func seconds(d time.Duration) string {
	if d%time.Second == 0 {
		return strconv.FormatInt(int64(d/time.Second), 10)
	}
	return strconv.FormatFloat(d.Seconds(), 'g', -1, 64)
}

// copyFile is cp src dst (a private copy, 0600).
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}
