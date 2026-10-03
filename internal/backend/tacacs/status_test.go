package tacacs

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// The status parts (tests/integration/status_and_scope_lookup.bats "status",
// tests/integration/listeners.bats "status and logs"): systemctl, ss and ps
// scripted as the bats stubs are.

// statusStubs is status_stubs of listeners.bats: every unit active but
// tacquito@down, PIDs 4242 (tacquito), 5151 (mgmt), 0 (down).
func (e *tenv) statusStubs() {
	e.run.OnFunc([]string{"systemctl"}, func(c execx.Cmd) (execx.Result, error) {
		args := " " + strings.Join(c.Args, " ") + " "
		switch c.Args[0] {
		case "is-active":
			if strings.Contains(args, "tacquito@down") {
				return execx.Result{Code: 3, Stdout: []byte("failed\n")}, nil
			}
			return execx.Result{Stdout: []byte("active\n")}, nil
		case "show":
			switch {
			case strings.Contains(args, "--property=ActiveEnterTimestamp"):
				return execx.Result{Stdout: []byte("ActiveEnterTimestamp=Mon 2026-04-21 10:00:00 UTC\n")}, nil
			case strings.Contains(args, "tacquito@mgmt") && strings.Contains(args, "--property=MainPID"):
				return execx.Result{Stdout: []byte("MainPID=5151\n")}, nil
			case strings.Contains(args, "tacquito@down") && strings.Contains(args, "--property=MainPID"):
				return execx.Result{Stdout: []byte("MainPID=0\n")}, nil
			case strings.Contains(args, "--property=MainPID"):
				return execx.Result{Stdout: []byte("MainPID=4242\n")}, nil
			}
		}
		return execx.Result{}, nil
	})
	e.ss(`LISTEN 0 128 *:4901 *:* users:(("tacquito",pid=4242,fd=3))`)
	e.run.On([]string{"ps"}, execx.Result{Stdout: []byte("12345\n")})
	e.b.Scrape = func(context.Context, string) string { return "" }
}

func (e *tenv) ss(line string) {
	out := ""
	if line != "" {
		out = line + "\n"
	}
	e.run.On([]string{"ss"}, execx.Result{Stdout: []byte(out)})
}

func (e *tenv) status(part backend.StatusPart) string {
	e.t.Helper()
	var w bytes.Buffer
	if err := e.b.Status(context.Background(), part, &w); err != nil {
		e.t.Fatal(err)
	}
	return w.String()
}

// "status: one listener prints exactly the lines it always printed";
// status_and_scope_lookup.bats "status: prints service active + PID +
// listening port".
func TestStatusServiceOneListener(t *testing.T) {
	e := newTenv(t)
	e.statusStubs()
	e.ss(`LISTEN 0 128 *:49 *:* users:(("tacquito",pid=4242,fd=3))`)
	out := e.status(backend.StatusService)
	want := "  " + ui.Bold + "Service:" + ui.NC + "              " + ui.Green + "active" + ui.NC + "\n" +
		"  " + ui.Bold + "Since:" + ui.NC + "                Mon 2026-04-21 10:00:00 UTC\n" +
		"  " + ui.Bold + "PID:" + ui.NC + "                  4242\n" +
		"  " + ui.Bold + "Memory:" + ui.NC + "               12.1 MB\n" +
		"  " + ui.Bold + "Listening:" + ui.NC + "            " + ui.Green + "*:49" + ui.NC + "\n" +
		"  " + ui.Bold + "Log level:" + ui.NC + "            info (20)\n"
	if out != want {
		t.Fatalf("got\n%q\nwant\n%q", out, want)
	}
	if !e.called(`^systemctl is-active tacquito$`) || !e.called(`^ps -o rss= -p 4242$`) || !e.called(`^ss -tlnp$`) {
		t.Fatal(e.run.Argvs())
	}
}

// "status: shows 'port 49 not detected' when ss finds nothing";
// "status: surfaces inactive service in red".
func TestStatusServiceDown(t *testing.T) {
	e := newTenv(t)
	e.run.On([]string{"systemctl", "is-active"}, execx.Result{Code: 3, Stdout: []byte("inactive\n")})
	e.run.On([]string{"systemctl", "show"}, execx.Result{Stdout: []byte("MainPID=0\n")})
	out := e.status(backend.StatusService)
	mustContain(t, out, ui.Red+"inactive"+ui.NC)
	mustContain(t, out, ui.Red+"port 49 not detected"+ui.NC)
	mustNotContain(t, out, "Since:")
	mustNotContain(t, out, "PID:")
	// No systemctl at all: unknown.
	e.run.Missing("systemctl")
	mustContain(t, e.status(backend.StatusService), ui.Red+"unknown"+ui.NC)
}

// "status: each further listener has its own line, state and accounting
// log"; "status: a port nobody listens on is named".
func TestStatusSeveralListeners(t *testing.T) {
	e := newTenv(t)
	e.writeOverrides("backends:\n  tacacs:\n    level: 30\nlisteners:\n  tacacs:\n    default: {network: tcp, address: '10.1.0.1:4901'}\n" +
		"    mgmt: {network: tcp, address: '127.0.0.1:4949'}\n    down: {network: tcp, address: '127.0.0.1:4950'}\n")
	writeFile(t, e.p.AcctLog, "a\nb\n")
	writeFile(t, filepath.Join(e.p.Log, "accounting-mgmt.log"), "c\n")
	e.statusStubs()
	out := e.status(backend.StatusService)
	mustMatchLine(t, out, `Listening:.*\*:4901`)
	mustNotContain(t, out, "port 49 not detected")
	mustMatchLine(t, out, `Listener down:.*failed.* — tcp 127\.0\.0\.1:4950 \(tacquito@down\.service\)$`)
	mustMatchLine(t, out, `Listener mgmt:.*active.* — tcp 127\.0\.0\.1:4949 \(tacquito@mgmt\.service, PID 5151\)$`)
	mustMatchLine(t, out, `Log level:.* debug \(30\)$`)
	acct := e.status(backend.StatusAccounting)
	mustMatchLine(t, acct, `Accounting log:.*\(2 entries\)$`)
	mustMatchLine(t, acct, `Accounting log \(mgmt\):.*\(1 entries\)$`)
	_ = e.status(backend.StatusActivity)
	if !e.called(`^journalctl -u tacquito -u tacquito@down\.service -u tacquito@mgmt\.service --no-pager`) {
		t.Fatal(e.run.Argvs())
	}

	e.reset()
	e.writeOverrides("listeners:\n  tacacs:\n    default: {network: tcp, address: '10.1.0.1:4902'}\n")
	mustContain(t, e.status(backend.StatusService), "port 4902 not detected")
}

// The config and accounting parts with one listener.
func TestStatusConfigAndAccounting(t *testing.T) {
	e := newTenv(t)
	if got := e.status(backend.StatusConfig); got != "  "+ui.Bold+"Config:"+ui.NC+"               "+e.p.Config+"\n" {
		t.Fatalf("%q", got)
	}
	if got := e.status(backend.StatusAccounting); got != "" {
		t.Fatalf("%q", got)
	}
	writeFile(t, e.p.AcctLog, "")
	if got := e.status(backend.StatusAccounting); got != "  "+ui.Bold+"Accounting log:"+ui.NC+"       0 (0 entries)\n" {
		t.Fatalf("%q", got)
	}
}

// The activity part: the counters of the default listener's exporter, a
// block per other listener, the recent errors of every listener's unit.
func TestStatusActivity(t *testing.T) {
	e := newTenv(t)
	var urls []string
	e.b.Scrape = func(_ context.Context, url string) string {
		urls = append(urls, url)
		if strings.Contains(url, "9100") {
			return ""
		}
		return "# HELP x\ntacquito_authenstart_handle_pap 7\ntacquito_authenpap_handle_error 2 1700000000\n" +
			"tacquito_stringy_handle_authorize_accept_pass_add 11\ntacquito_authenstart_handle_pap_other 99\n"
	}
	var journal strings.Builder
	for i := 1; i <= 7; i++ {
		journal.WriteString("Apr 21 tacquito[1]: ERROR: bad thing " + string(rune('0'+i)) + "\n")
		journal.WriteString("Apr 21 tacquito[1]: INFO: fine\n")
	}
	journal.WriteString("  ERROR: with blanks \\t  \n")
	e.run.On([]string{"journalctl"}, execx.Result{Stdout: []byte(journal.String())})
	out := e.status(backend.StatusActivity)
	want := "\n  " + ui.Bold + "Authentication Stats (since last restart):" + ui.NC + "\n" +
		"    Auth attempts:      7\n    Auth errors:        2\n    Authz granted:      11\n    Authz denied:       0\n" +
		"\n  " + ui.Bold + "Recent Errors (last 5):" + ui.NC + "\n" +
		"    " + ui.Red + "Apr 21 tacquito[1]: ERROR: bad thing 4" + ui.NC + "\n" +
		"    " + ui.Red + "Apr 21 tacquito[1]: ERROR: bad thing 5" + ui.NC + "\n" +
		"    " + ui.Red + "Apr 21 tacquito[1]: ERROR: bad thing 6" + ui.NC + "\n" +
		"    " + ui.Red + "Apr 21 tacquito[1]: ERROR: bad thing 7" + ui.NC + "\n" +
		"    " + ui.Red + "ERROR: with blanks \t" + ui.NC + "\n"
	if out != want {
		t.Fatalf("got\n%q\nwant\n%q", out, want)
	}
	if !e.called(`^journalctl -u tacquito --no-pager -n 100 --since 24 hours ago$`) || len(urls) != 1 || urls[0] != "http://127.0.0.1:8080/metrics" {
		t.Fatal(e.run.Argvs(), urls)
	}

	// Other listeners: a block each; the disabled sink is not scraped.
	e.reset()
	urls = nil
	e.run.On([]string{"journalctl"}, execx.Result{})
	e.writeOverrides("backends:\n  tacacs:\n    metrics_address: 127.0.0.1:0\nlisteners:\n  tacacs:\n" +
		"    mgmt: {network: tcp, address: '127.0.0.1:4949', metrics_address: '127.0.0.1:9100'}\n" +
		"    zz: {network: tcp, address: '127.0.0.1:4950'}\n")
	out = e.status(backend.StatusActivity)
	mustContain(t, out, ui.Yellow+"Metrics exporter disabled (tacctl config metrics enable)"+ui.NC)
	mustContain(t, out, ui.Bold+"Authentication Stats, listener mgmt (since last restart):"+ui.NC+"\n    "+ui.Yellow+
		"Metrics unavailable (http://127.0.0.1:9100/metrics)"+ui.NC)
	mustContain(t, out, ui.Bold+"Authentication Stats, listener zz:"+ui.NC+" no metrics exporter (listeners.tacacs.zz.metrics_address)")
	mustContain(t, out, ui.Green+"No errors in the last 24 hours"+ui.NC)
	if len(urls) != 1 {
		t.Fatal(urls)
	}
	// ':port' is scraped on localhost.
	if scrapeURL(":9090") != "http://localhost:9090/metrics" {
		t.Fatal(scrapeURL(":9090"))
	}
}

// The scrape is 'curl -s': whatever body comes back, "" when nothing does.
func TestHTTPScrape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("tacquito_authenstart_handle_pap 3\n"))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if got := httpScrape(context.Background(), scrapeURL(addr)); got != "tacquito_authenstart_handle_pap 3\n" {
		t.Fatalf("%q", got)
	}
	if got := httpScrape(context.Background(), "http://"+addr+"/other"); !strings.Contains(got, "404") {
		t.Fatalf("%q", got)
	}
	srv.Close()
	if got := httpScrape(context.Background(), scrapeURL(addr)); got != "" {
		t.Fatalf("%q", got)
	}
}

func TestHumanSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 512: "512", 1023: "1023", 1024: "1.0K", 4096: "4.0K", 1536: "1.5K", 1600: "1.6K",
		10239: "10K", 10240: "10K", 12288: "12K", 1048575: "1.0M", 1048576: "1.0M", 5 << 20: "5.0M", 1<<30 + 1: "1.1G"} {
		if got := humanSize(n); got != want {
			t.Fatalf("%d: %q, want %q", n, got, want)
		}
	}
	// A file's disk usage: allocated blocks.
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := duSize(p); got == "" || got == "1" {
		t.Fatalf("%q", got)
	}
}

func TestAwkHelpers(t *testing.T) {
	for in, want := range map[string]float64{"12345": 12345, "  7": 7, "1e3": 1000, "abc": 0, "3.5x": 3.5, "": 0} {
		if got := awkNumber(in); got != want {
			t.Fatalf("%q: %v", in, got)
		}
	}
	if firstField("a  b\tc", 2) != "c" || firstField("a", 3) != "" {
		t.Fatal("fields")
	}
	e := newTenv(t)
	e.run.On([]string{"ps"}, execx.Result{Stdout: []byte("1024\n2048\n")})
	if got := e.b.memory(context.Background(), "1"); got != "1.0 MB2.0 MB" {
		t.Fatalf("%q", got)
	}
	e.run.On([]string{"ps"}, execx.Result{})
	if got := e.b.memory(context.Background(), "1"); got != "" {
		t.Fatalf("%q", got)
	}
}
