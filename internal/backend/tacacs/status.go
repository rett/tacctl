package tacacs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/ui"
)

// echoLine is 'echo -e "<s>"' to w.
func echoLine(w io.Writer, s string) { writeString(w, ui.Echo(s)) }

// Status is backend_tacacs_status: one part of 'tacctl status' (service,
// config, accounting, activity) written to w; ErrUnsupported for any other
// part, the summary of 'tacctl backend status' included.
func (b *Backend) Status(ctx context.Context, part backend.StatusPart, w io.Writer) error {
	switch part {
	case backend.StatusService:
		b.statusService(ctx, w)
	case backend.StatusConfig:
		echoLine(w, "  "+ui.Bold+"Config:"+ui.NC+"               "+b.env.Paths.Config)
	case backend.StatusAccounting:
		b.statusAccounting(w)
	case backend.StatusActivity:
		b.statusActivity(ctx, w)
	default:
		return backend.ErrUnsupported
	}
	return nil
}

func stateColor(state string) string {
	if state == "active" {
		return ui.Green
	}
	return ui.Red
}

// statusService is _tacacs_status_service: the default listener's unit as
// this report always showed it (state, uptime, PID, memory, listening
// socket), one line per other listener's instance, and the log level every
// listener runs at.
func (b *Backend) statusService(ctx context.Context, w io.Writer) {
	// is-active prints the state and fails for anything but 'active': the
	// word is what is shown.
	state, _ := b.capture(ctx, "is-active", Service)
	state = or(state, "unknown")
	echoLine(w, "  "+ui.Bold+"Service:"+ui.NC+"              "+stateColor(state)+state+ui.NC)
	if state == "active" {
		since := b.showProperty(ctx, Service, "ActiveEnterTimestamp")
		echoLine(w, "  "+ui.Bold+"Since:"+ui.NC+"                "+since)
	}
	if pid := b.showProperty(ctx, Service, "MainPID"); pid != "" && pid != "0" {
		echoLine(w, "  "+ui.Bold+"PID:"+ui.NC+"                  "+pid)
		echoLine(w, "  "+ui.Bold+"Memory:"+ui.NC+"               "+b.memory(ctx, pid))
	}

	// Listening port: the default listener's, from the listener model.
	lines := b.listenerLines()
	first := backend.Listener{Name: "default", Network: "tcp", Address: ":49"}
	if len(lines) > 0 {
		first = lines[0]
	}
	port := first.Address[strings.LastIndex(first.Address, ":")+1:]
	if listen := b.listening(ctx, port); listen != "" {
		echoLine(w, "  "+ui.Bold+"Listening:"+ui.NC+"            "+ui.Green+listen+ui.NC)
	} else {
		echoLine(w, "  "+ui.Bold+"Listening:"+ui.NC+"            "+ui.Red+"port "+port+" not detected"+ui.NC)
	}

	// The other listeners, one instance each.
	for _, l := range lines {
		if l.Name == "" || l.Name == "default" {
			continue
		}
		unit := rtacacs.Unit(l.Name)
		istate, _ := b.capture(ctx, "is-active", unit)
		istate = or(istate, "unknown")
		ipid := b.showProperty(ctx, unit, "MainPID")
		if ipid != "" && ipid != "0" {
			ipid = ", PID " + ipid
		} else {
			ipid = ""
		}
		echoLine(w, "  "+ui.Bold+"Listener "+l.Name+":"+ui.NC+" "+stateColor(istate)+istate+ui.NC+" — "+
			l.Network+" "+l.Address+" ("+unit+ipid+")")
	}

	level, _ := b.setting("level")
	name := levelNames[level]
	if name == "" {
		name = "unknown"
	}
	echoLine(w, "  "+ui.Bold+"Log level:"+ui.NC+"            "+name+" ("+level+")")
}

// memory is ps -o rss= -p <pid> | awk '{printf "%.1f MB", $1/1024}'.
func (b *Backend) memory(ctx context.Context, pid string) string {
	res, _ := b.env.Runner.Run(ctx, execx.Cmd{Name: "ps", Args: []string{"-o", "rss=", "-p", pid}})
	var s strings.Builder
	for _, rec := range records(string(res.Stdout)) {
		fmt.Fprintf(&s, "%.1f MB", awkNumber(firstField(rec, 0))/1024)
	}
	return s.String()
}

// records are awk's input records: the lines of text, a last line without
// a newline included.
func records(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// firstField is awk's $(n+1) with the default field separator.
func firstField(rec string, n int) string {
	f := strings.Fields(rec)
	if n < len(f) {
		return f[n]
	}
	return ""
}

var awkNum = regexp.MustCompile(`^[ \t\n]*[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?`)

// awkNumber is awk's numeric value of a string: its longest numeric
// prefix, 0 when there is none.
func awkNumber(s string) float64 {
	m := awkNum.FindString(s)
	f, err := strconv.ParseFloat(strings.TrimLeft(m, " \t\n"), 64)
	if err != nil {
		return 0
	}
	return f
}

// listening is 'ss -tlnp 2>/dev/null | grep ":<port> " | awk '{print $4}'
// | head -1'.
func (b *Backend) listening(ctx context.Context, port string) string {
	res, _ := b.env.Runner.Run(ctx, execx.Cmd{Name: "ss", Args: []string{"-tlnp"}})
	for _, rec := range records(string(res.Stdout)) {
		if strings.Contains(rec, ":"+port+" ") {
			return firstField(rec, 3)
		}
	}
	return ""
}

// statusAccounting is _tacacs_status_accounting: the size and line count
// of every listener's accounting log.
func (b *Backend) statusAccounting(w io.Writer) {
	if log := b.env.Paths.AcctLog; isRegular(log) {
		echoLine(w, "  "+ui.Bold+"Accounting log:"+ui.NC+"       "+duSize(log)+" ("+lineCount(log)+" entries)")
	}
	for _, log := range b.acctLogs(false) {
		if !isRegular(log) {
			continue
		}
		name := strings.TrimSuffix(log[strings.LastIndex(log, "/accounting-")+len("/accounting-"):], ".log")
		echoLine(w, "  "+ui.Bold+"Accounting log ("+name+"):"+ui.NC+" "+duSize(log)+" ("+lineCount(log)+" entries)")
	}
}

// duSize is du -sh <file> | awk '{print $1}': the disk usage of a file
// (its allocated blocks), in du's human-readable form ("" when it cannot
// be read).
func duSize(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	n := st.Size()
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		n = sys.Blocks * 512
	}
	return humanSize(n)
}

// humanSize is du -h's rendering of a byte count: powers of 1024, rounded
// up, one decimal below 10 (4.0K, 9.9M), none from 10 on (12K); below 1024
// the plain number.
func humanSize(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10)
	}
	const units = "KMGTPE"
	p, i := int64(1024), 0
	for i+1 < len(units) && n/1024 >= p {
		p *= 1024
		i++
	}
	if tenths := (n*10 + p - 1) / p; tenths < 100 {
		return fmt.Sprintf("%d.%d%c", tenths/10, tenths%10, units[i])
	}
	whole := (n + p - 1) / p
	if whole >= 1024 && i+1 < len(units) {
		return fmt.Sprintf("1.0%c", units[i+1])
	}
	return fmt.Sprintf("%d%c", whole, units[i])
}

// lineCount is 'wc -l < <file>': its newlines ("" when it cannot be read).
func lineCount(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strconv.Itoa(strings.Count(string(data), "\n"))
}

// statusActivity is _tacacs_status_activity: the authentication counters
// of the default listener's exporter, a block per other listener (which
// exports metrics only when it sets metrics_address), then the recent
// errors of every listener's unit.
func (b *Backend) statusActivity(ctx context.Context, w io.Writer) {
	writeString(w, "\n")
	echoLine(w, "  "+ui.Bold+"Authentication Stats (since last restart):"+ui.NC)
	addr, _ := b.setting("metrics_address")
	b.statusStats(ctx, w, addr)

	if !b.legacyUnits() && len(b.listenerLines()) > 1 {
		for _, l := range b.effectiveListeners() {
			if l.Name == "" || l.Name == "default" {
				continue
			}
			writeString(w, "\n")
			if l.MetricsAddress == "" || l.MetricsAddress == "-" {
				echoLine(w, "  "+ui.Bold+"Authentication Stats, listener "+l.Name+":"+ui.NC+
					" no metrics exporter (listeners.tacacs."+l.Name+".metrics_address)")
			} else {
				echoLine(w, "  "+ui.Bold+"Authentication Stats, listener "+l.Name+" (since last restart):"+ui.NC)
				b.statusStats(ctx, w, l.MetricsAddress)
			}
		}
	}

	writeString(w, "\n")
	echoLine(w, "  "+ui.Bold+"Recent Errors (last 5):"+ui.NC)
	args := append(b.journalUnits(), "--no-pager", "-n", "100", "--since", "24 hours ago")
	res, _ := b.env.Runner.Run(ctx, execx.Cmd{Name: "journalctl", Args: args})
	var errs []string
	for _, rec := range records(string(res.Stdout)) {
		if strings.Contains(rec, "ERROR:") {
			errs = append(errs, rec)
		}
	}
	if len(errs) > 5 {
		errs = errs[len(errs)-5:]
	}
	if len(errs) == 0 {
		echoLine(w, "    "+ui.Green+"No errors in the last 24 hours"+ui.NC)
		return
	}
	for _, line := range errs {
		// 'while read -r line' trims the blanks around each line.
		echoLine(w, "    "+ui.Red+strings.Trim(line, " \t")+ui.NC)
	}
}

// The counters of the exporter that the activity report prints.
var statCounters = [][2]string{
	{"Auth attempts:      ", "tacquito_authenstart_handle_pap"},
	{"Auth errors:        ", "tacquito_authenpap_handle_error"},
	{"Authz granted:      ", "tacquito_stringy_handle_authorize_accept_pass_add"},
	{"Authz denied:       ", "tacquito_stringy_handle_authorize_fail"},
}

// statusStats is _tacacs_status_stats: the four counters of the exporter
// at a metrics address, or why there are none. The "disabled" sink is not
// scraped.
func (b *Backend) statusStats(ctx context.Context, w io.Writer, addr string) {
	if addr == rtacacs.MetricsSink {
		echoLine(w, "    "+ui.Yellow+"Metrics exporter disabled (tacctl config metrics enable)"+ui.NC)
		return
	}
	url := scrapeURL(addr)
	scrape := b.Scrape
	if scrape == nil {
		scrape = httpScrape
	}
	metrics := strings.TrimRight(scrape(ctx, url), "\n")
	if metrics == "" {
		echoLine(w, "    "+ui.Yellow+"Metrics unavailable ("+url+")"+ui.NC)
		return
	}
	for _, c := range statCounters {
		value := ""
		for _, rec := range records(metrics) {
			if strings.HasPrefix(rec, c[1]+" ") {
				value = firstField(rec, 1)
				break
			}
		}
		echoLine(w, "    "+c[0]+or(value, "0"))
	}
}

// httpScrape is 'curl -s <url>': the body of whatever answer came back, ""
// on any failure. It waits at most 5 seconds and uses no proxy.
func httpScrape(ctx context.Context, url string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return string(body)
}
