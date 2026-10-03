package radius

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// Status is backend_radius_status: one part of 'tacctl status'. The first
// four parts read well one after the other, with no heading of their own;
// summary is what 'tacctl backend status' adds after the listeners.
func (m *Module) Status(ctx context.Context, part backend.StatusPart, w io.Writer) error {
	switch part {
	case backend.StatusService:
		m.statusService(ctx, w)
	case backend.StatusConfig:
		m.statusConfig(w)
	case backend.StatusAccounting:
		m.statusAccounting(w)
	case backend.StatusActivity:
		m.statusActivity(w)
	case backend.StatusSummary:
		for _, n := range m.notes() {
			if n.Kind == "vendors" {
				statusVendors(w, n.Detail)
			}
		}
	default:
		return backend.ErrUnsupported
	}
	return nil
}

// statusService is _radius_status_service.
func (m *Module) statusService(ctx context.Context, w io.Writer) {
	state, _ := m.systemctlOut(ctx, "is-active", m.L.Unit)
	if state == "" {
		state = "unknown"
	}
	color := ui.Green
	if state != "active" {
		color = ui.Red
	}
	echo(w, "  "+ui.Bold+"Service:"+ui.NC+"              "+color+state+ui.NC+" ("+m.L.Unit+")")
	if state == "active" {
		v, _ := m.systemctlOut(ctx, "show", m.L.Unit, "--property=ActiveEnterTimestamp")
		echo(w, "  "+ui.Bold+"Since:"+ui.NC+"                "+cutField2(v))
	}
	pid, _ := m.systemctlOut(ctx, "show", m.L.Unit, "--property=MainPID")
	pid = cutField2(pid)
	if pid != "" && pid != "0" {
		echo(w, "  "+ui.Bold+"PID:"+ui.NC+"                  "+pid)
		res, _ := m.runner.Run(ctx, execx.Cmd{Name: "ps", Args: []string{"-o", "rss=", "-p", pid}})
		echo(w, "  "+ui.Bold+"Memory:"+ui.NC+"               "+awkMegabytes(string(res.Stdout)))
	}
	for _, l := range m.effectiveListeners() {
		if bound := m.probe(ctx, l.Network, l.Address); bound != "" {
			echo(w, "  "+ui.Bold+"Listening ("+l.Name+"):"+ui.NC+"     "+ui.Green+bound+"/udp"+ui.NC)
		} else {
			echo(w, "  "+ui.Bold+"Listening ("+l.Name+"):"+ui.NC+"     "+ui.Red+"port "+portOf(l.Address)+"/udp not detected"+ui.NC)
		}
	}
}

// portOf is "${addr##*:}".
func portOf(addr string) string { return addr[strings.LastIndexByte(addr, ':')+1:] }

// probe is backend_listener_probe: the local address something listens on
// for that network and port, or "". It is the fourth field of the first line
// of 'ss -ulnp' (-tlnp for tcp) that has ":<port> ".
func (m *Module) probe(ctx context.Context, network, address string) string {
	flags := "-tlnp"
	if strings.HasPrefix(network, "udp") {
		flags = "-ulnp"
	}
	res, _ := m.runner.Run(ctx, execx.Cmd{Name: "ss", Args: []string{flags}})
	needle := ":" + portOf(address) + " "
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if strings.Contains(line, needle) {
			if f := awkFields(line); len(f) >= 4 {
				return f[3]
			}
			return ""
		}
	}
	return ""
}

// awkFields splits a line as awk does with its default separator: runs of
// blanks (space, tab, newline).
func awkFields(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' })
}

// awkMegabytes is "awk '{printf "%.1f MB", $1/1024}'" over ps's output: one
// figure per line, none for no output.
func awkMegabytes(s string) string {
	var b strings.Builder
	if s == "" {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		f := awkFields(line)
		v := 0.0
		if len(f) > 0 {
			v = awkNumber(f[0])
		}
		fmt.Fprintf(&b, "%.1f MB", v/1024)
	}
	return b.String()
}

// awkNumber is awk's string to number: the longest numeric prefix, else 0.
func awkNumber(s string) float64 {
	end := 0
	for i := 1; i <= len(s); i++ {
		if _, err := strconv.ParseFloat(s[:i], 64); err == nil {
			end = i
		}
	}
	if end == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(s[:end], 64)
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return 0
	}
	return v
}

// statusConfig is _radius_status_config.
func (m *Module) statusConfig(w io.Writer) {
	echo(w, "  "+ui.Bold+"Config:"+ui.NC+"               "+m.L.Conf)
	echo(w, "  "+ui.Bold+"Authentication:"+ui.NC+"       PAP against the store's bcrypt hashes (no CHAP, MS-CHAP or EAP)")
	for _, n := range m.notes() {
		switch n.Kind {
		case "commands":
			echo(w, "  "+ui.Yellow+"Command rules:"+ui.NC+"        not enforced over RADIUS (commands.<group> of: "+n.Detail+")")
		case "secret":
			echo(w, "  "+ui.Yellow+"Secrets:"+ui.NC+"              beyond what every RADIUS client takes ("+strconv.Itoa(m.SecretConstraints().MaxLen)+" characters, no space, ASCII): "+n.Detail)
		case "filters":
			echo(w, "  "+ui.Bold+"Connection filters:"+ui.NC+"   enforced ("+n.Detail+")")
		case "vendors":
			statusVendors(w, n.Detail)
		}
	}
}

// statusVendors is _radius_status_vendors: the vendor-attributes line from
// the 'vendors' note ('<scopes that enable one>|<scopes served>|<tagged
// addresses>'): a count, not a line per scope ('tacctl scope list' has
// those).
func statusVendors(w io.Writer, detail string) {
	f := strings.SplitN(detail, "|", 3)
	for len(f) < 3 {
		f = append(f, "")
	}
	enabling, _ := strconv.Atoi(f[0])
	tagged, _ := strconv.Atoi(f[2])
	if enabling == 0 && tagged == 0 {
		echo(w, "  "+ui.Bold+"Vendor attributes:"+ui.NC+"    not sent (no scope enables one: tacctl scope vendor-attrs <scope> enable <vendor>)")
		return
	}
	echo(w, "  "+ui.Bold+"Vendor attributes:"+ui.NC+"    enabled for "+f[0]+" of "+f[1]+" scope(s), "+f[2]+" tagged address(es) (tacctl scope list)")
}

// statusAccounting is _radius_status_accounting: the size and record count
// of the detail file.
func (m *Module) statusAccounting(w io.Writer) {
	st, err := os.Stat(m.L.AcctLog)
	if err != nil || !st.Mode().IsRegular() {
		return
	}
	echo(w, "  "+ui.Bold+"Accounting log:"+ui.NC+"       "+duHuman(diskUsage(st))+" ("+strconv.Itoa(countRecords(m.L.AcctLog))+" records)")
}

// countRecords is _radius_acct_records: the lines of a detail file that
// start with a non-blank, one per record ('grep -c').
func countRecords(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	n := 0
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if line != "" && !isBlank(line[0]) {
			n++
		}
		if err != nil {
			return n
		}
	}
}

// isBlank is [[:space:]] for an ASCII byte.
func isBlank(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// statusActivity is _radius_status_activity: FreeRADIUS has no counters to
// scrape, so the figures are counted from the auth log tacctl's policy
// writes, over its last 24 hours.
func (m *Module) statusActivity(w io.Writer) {
	recent := m.authRecent()
	var accepted, rejected int
	var rejects []string
	for _, l := range recent {
		if strings.Contains(l, " Access-Accept ") {
			accepted++
		}
		if strings.Contains(l, " Access-Reject ") {
			rejected++
			rejects = append(rejects, l)
		}
	}
	echo(w, "")
	echo(w, "  "+ui.Bold+"Authentication (last 24 hours, from "+baseName(m.L.AuthLog)+"):"+ui.NC)
	echo(w, "    Accepted:           "+strconv.Itoa(accepted))
	echo(w, "    Rejected:           "+strconv.Itoa(rejected))
	echo(w, "")
	echo(w, "  "+ui.Bold+"Recent Rejects (last 5):"+ui.NC)
	if rejected == 0 {
		echo(w, "    "+ui.Green+"No rejects in the last 24 hours"+ui.NC)
		return
	}
	if len(rejects) > 5 {
		rejects = rejects[len(rejects)-5:]
	}
	for _, l := range rejects {
		echo(w, "    "+ui.Red+l+ui.NC)
	}
}

func baseName(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

// authRecent is _radius_auth_recent: the lines of the auth log from the last
// 24 hours (it is written in local time), without their newlines. Nothing
// when the log cannot be read. The test is awk's '($1 " " $2) >= cutoff' on
// the two date fields.
func (m *Module) authRecent() []string {
	f, err := os.Open(m.L.AuthLog)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	cutoff := m.now().Local().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	var out []string
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			line = strings.TrimSuffix(line, "\n")
			fl := awkFields(line)
			var a, b string
			if len(fl) > 0 {
				a = fl[0]
			}
			if len(fl) > 1 {
				b = fl[1]
			}
			if a+" "+b >= cutoff {
				out = append(out, line)
			}
		}
		if err != nil {
			return out
		}
	}
}

// diskUsage is the bytes a file occupies (du's figure): its blocks.
func diskUsage(st os.FileInfo) int64 { return blocksOf(st) }

// duHuman is 'du -sh': 1024-based units, rounded up, one decimal below 10.
func duHuman(bytes int64) string {
	if bytes <= 0 {
		return "0"
	}
	const suffixes = "KMGTPE"
	v := float64(bytes)
	exp := 0
	for v >= 1024 && exp < len(suffixes) {
		v /= 1024
		exp++
	}
	suffix := ""
	if exp > 0 {
		suffix = string(suffixes[exp-1])
	}
	if v < 10 && exp > 0 {
		t := math.Ceil(v*10) / 10
		if t < 10 {
			return fmt.Sprintf("%.1f%s", t, suffix)
		}
		v = t
	}
	n := math.Ceil(v)
	if n >= 1024 && exp < len(suffixes) {
		return fmt.Sprintf("%.1f%s", 1.0, string(suffixes[exp]))
	}
	return fmt.Sprintf("%d%s", int64(n), suffix)
}

// echo writes line as 'echo -e "<line>"' prints it.
func echo(w io.Writer, line string) {
	text, stop := echoE(line)
	if !stop {
		text += "\n"
	}
	_, _ = io.WriteString(w, text)
}
