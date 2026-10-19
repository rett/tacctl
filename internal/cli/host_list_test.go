package cli

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// hostListRows are the rows of the host table by host name, each as its
// whitespace-separated cells.
func hostListRows(out string) (header []string, rows map[string][]string) {
	rows = map[string][]string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) > 0 && f[0] == "NAME":
			header = f
		case len(f) > 2 && header != nil:
			rows[f[0]] = f
		}
	}
	return header, rows
}

// cell is the cell of the column named col in a row of the host table.
func hostListCell(t *testing.T, header []string, row []string, col string) string {
	t.Helper()
	for i, h := range header {
		if h == col {
			if i < len(row) {
				return row[i]
			}
			return ""
		}
	}
	t.Fatalf("no column %s in %v", col, header)
	return ""
}

func hostListJSONOf(t *testing.T, out string) map[string]hostListJSON {
	t.Helper()
	var js []hostListJSON
	if err := json.Unmarshal([]byte(out), &js); err != nil {
		t.Fatalf("host list --json: %v\n%s", err, out)
	}
	m := map[string]hostListJSON{}
	for _, h := range js {
		m[h.Name] = h
	}
	if len(m) != len(js) {
		t.Fatalf("a host twice: %+v", js)
	}
	return m
}

func TestHostListAddressColumn(t *testing.T) {
	sb := hostLab(t)
	out := plain(sb.run("", []string{"host", "list"}))
	header, rows := hostListRows(out)
	// After TARGET, before SCOPE.
	if len(header) < 4 || header[1] != "TARGET" || header[2] != "ADDRESS" || header[3] != "SCOPE" {
		t.Fatalf("header %v\n%s", header, out)
	}
	// A recorded address is shown; a host with none gets a dash.
	if got := hostListCell(t, header, rows["web2"], "ADDRESS"); got != "192.168.1.12" {
		t.Errorf("web2 address %q\n%s", got, out)
	}
	if got := hostListCell(t, header, rows["web1"], "ADDRESS"); got != "-" {
		t.Errorf("web1 address %q\n%s", got, out)
	}
	if got := hostListCell(t, header, rows["web2"], "TARGET"); got != "root@web2.example.net" {
		t.Errorf("web2 target %q", got)
	}

	// A held host keeps its address and is marked in STATE after it.
	sb.recordHostAddress("web1", "192.168.1.10")
	holdHost(t, sb, "web1", "locked out of sudo")
	out = plain(sb.run("", []string{"host", "list"}))
	header, rows = hostListRows(out)
	if got := hostListCell(t, header, rows["web1"], "ADDRESS"); got != "192.168.1.10" {
		t.Errorf("held web1 address %q\n%s", got, out)
	}
	if header[len(header)-1] != "STATE" || hostListCell(t, header, rows["web1"], "STATE") != "BREAK-GLASS" {
		t.Errorf("held host not marked\n%s", out)
	}
	if !strings.Contains(out, "1 host(s) held for break-glass") {
		t.Errorf("no footer\n%s", out)
	}
}

func TestHostListAddressColumnEngineer(t *testing.T) {
	sb := hostLab(t)
	out := sb.asEngineer("", "host", "list")
	header, rows := hostListRows(out)
	if sb.code != 0 || len(header) < 3 || header[2] != "ADDRESS" {
		t.Fatalf("%d %v\n%s", sb.code, header, out)
	}
	if _, ok := rows["db1"]; ok {
		t.Errorf("an engineer lists another scope's host:\n%s", out)
	}
	if got := hostListCell(t, header, rows["web2"], "ADDRESS"); got != "192.168.1.12" {
		t.Errorf("web2 address %q\n%s", got, out)
	}
}

func TestHostListJSON(t *testing.T) {
	sb := hostLab(t)
	sb.recordHostAddress("web1", "192.168.1.10")
	holdHost(t, sb, "web1", "locked out of sudo")
	// Anything the table says on standard error stays off the JSON's stdout.
	out := sb.run("", []string{"host", "list", "--json"})
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	if strings.Contains(out, "\x1b") || !strings.HasPrefix(out, "[") {
		t.Fatalf("not JSON:\n%s", out)
	}
	byName := hostListJSONOf(t, out)
	if len(byName) != 3 {
		t.Fatalf("%d hosts:\n%s", len(byName), out)
	}
	w1, w2, db1 := byName["web1"], byName["web2"], byName["db1"]
	if w1.Target != "root@192.168.1.10" || w1.Port != 22 || w1.Scope != "lab" || w1.Server != "192.0.2.1" || w1.Method != "tacplus" ||
		w1.Identity != "" || w1.Address != "192.168.1.10" || w1.Local || w1.Findings == nil || len(w1.Findings) != 0 {
		t.Errorf("web1 %+v", w1)
	}
	if w1.Breakglass == nil || !w1.Breakglass.Held || w1.Breakglass.Address != "192.168.1.10" || w1.Breakglass.Reason != "locked out of sudo" || w1.Breakglass.Since == "" {
		t.Errorf("web1 hold %+v", w1.Breakglass)
	}
	if w2.Address != "192.168.1.12" || w2.Breakglass != nil || db1.Address != "" || db1.Scope != "prod" || db1.Breakglass != nil {
		t.Errorf("web2 %+v, db1 %+v", w2, db1)
	}
	// The key names are the contract; a host that is not held has no hold.
	var raw []map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	for _, r := range raw {
		for _, k := range []string{"name", "local", "target", "port", "scope", "server", "method", "identity", "address", "users", "drift", "findings"} {
			if _, ok := r[k]; !ok {
				t.Errorf("%v lacks %q", r["name"], k)
			}
		}
		if _, has := r["breakglass"]; has != (r["name"] == "web1") {
			t.Errorf("%v: breakglass %v", r["name"], r["breakglass"])
		}
	}
	// A registered port and key file belong to the target.
	sb.write("state/linux-hosts", "web1|root@192.168.1.10|2222|lab|192.0.2.1|/etc/tacctl/id_web1\n", 0o600)
	if got := hostListJSONOf(t, sb.run("", []string{"host", "list", "--json"}))["web1"]; got.Port != 2222 || got.Identity != "/etc/tacctl/id_web1" {
		t.Errorf("port and identity %+v", got)
	}
	if _, rows := hostListRows(plain(sb.run("", []string{"host", "list"}))); rows["web1"][1] != "root@192.168.1.10:2222" {
		t.Errorf("table row %v", rows["web1"])
	}
}

func TestHostListJSONDrift(t *testing.T) {
	sb := hostLab(t)
	// web1's address is answered by another scope than its own.
	sb.write("state/linux-hosts", "web1|root@web1.example.net||lab|192.0.2.1|\n", 0o600)
	sb.recordHostAddress("web1", "10.99.0.20")
	js := hostListJSONOf(t, sb.run("", []string{"host", "list", "--json"}))
	if want := "web1: registered in scope 'lab', but 10.99.0.20 is answered by scope 'prod'"; !strings.Contains(js["web1"].Drift, want) {
		t.Errorf("drift %q", js["web1"].Drift)
	}
	// The table carries the same text as a warning; the JSON is only JSON.
	if sb.stderr() != "" {
		t.Errorf("--json warns on standard error: %q", sb.stderr())
	}
	if out := plain(sb.run("", []string{"host", "list", "--json"})); strings.Contains(out, "[WARN]") || strings.Contains(out, "finding(s)") {
		t.Errorf("--json prints the table's warnings:\n%s", out)
	}
	if out := plain(sb.run("", []string{"host", "list"})); !strings.Contains(out, "[WARN] "+js["web1"].Drift) {
		t.Errorf("table warning lacks %q:\n%s", js["web1"].Drift, out)
	}
}

func TestHostListJSONFindings(t *testing.T) {
	sb := renameLab(t)
	// Two names equal ignoring case, and a host named like a device.
	sb.write("state/linux-hosts", hostLines+"Web1|root@192.168.1.10||lab|192.0.2.1|\nlab-sw|root@192.0.2.60||lab|192.0.2.1|\n", 0o600)
	js := hostListJSONOf(t, sb.run("", []string{"host", "list", "--json"}))
	if len(js) != 5 {
		t.Fatalf("%d hosts", len(js))
	}
	for _, n := range []string{"web1", "Web1"} {
		fs := js[n].Findings
		if len(fs) == 0 || !strings.Contains(fs[0].Text, "the hosts 'web1', 'Web1' are one name ignoring case") ||
			!strings.HasPrefix(fs[0].Fix, "tacctl host forget <name>") {
			t.Errorf("%s findings %+v", n, fs)
		}
	}
	// Web1 also has upper case in its name (a Names finding); web1 has not.
	if len(js["web1"].Findings) != 1 || len(js["Web1"].Findings) != 2 {
		t.Errorf("findings of web1 %+v and Web1 %+v", js["web1"].Findings, js["Web1"].Findings)
	}
	if fs := js["lab-sw"].Findings; len(fs) != 1 || !strings.Contains(fs[0].Text, "has the name of the device 'lab-sw'") || fs[0].Fix != "tacctl host rename lab-sw <new>" {
		t.Errorf("lab-sw findings %+v", fs)
	}
	if len(js["db1"].Findings) != 0 || len(js["web2"].Findings) != 0 {
		t.Errorf("findings on hosts the findings do not name: %+v %+v", js["db1"], js["web2"])
	}
	// An engineer is told none, whatever they list.
	ej := hostListJSONOf(t, sb.asEngineer("", "host", "list", "--json"))
	if sb.code != 0 || len(ej) == 0 {
		t.Fatalf("engineer: %d %q", sb.code, sb.stderr())
	}
	for n, h := range ej {
		if h.Findings == nil || len(h.Findings) != 0 {
			t.Errorf("engineer sees findings on %s: %+v", n, h.Findings)
		}
	}
}

// A host with upper case in its name has a Names finding: the footer counts
// it and --json lists it under the host; an engineer is told neither.
func TestHostListNamesFinding(t *testing.T) {
	sb := hostLab(t)
	sb.write("state/linux-hosts", hostLines+"Cache1|root@192.168.1.20||lab|192.0.2.1|\n", 0o600)
	if out := plain(sb.run("", []string{"host", "list"})); !strings.Contains(out, "1 finding(s): see tacctl config validate") {
		t.Errorf("footer:\n%s", out)
	}
	js := hostListJSONOf(t, sb.run("", []string{"host", "list", "--json"}))
	fs := js["Cache1"].Findings
	if len(fs) != 1 || !strings.Contains(fs[0].Text, "the host 'Cache1' has upper case in its name") || fs[0].Fix != "tacctl host rename Cache1 cache1" {
		t.Errorf("Cache1 findings %+v", fs)
	}
	if len(js["web1"].Findings) != 0 {
		t.Errorf("web1 findings %+v", js["web1"].Findings)
	}
	if out := plain(sb.asEngineer("", "host", "list")); strings.Contains(out, "finding(s)") {
		t.Errorf("engineer footer:\n%s", out)
	}
	for n, h := range hostListJSONOf(t, sb.asEngineer("", "host", "list", "--json")) {
		if len(h.Findings) != 0 {
			t.Errorf("engineer sees findings on %s: %+v", n, h.Findings)
		}
	}
}

func TestHostListJSONEngineer(t *testing.T) {
	sb := hostLab(t)
	holdHost(t, sb, "web1", "locked out of sudo")
	holdHost(t, sb, "db1", "other scope")
	js := hostListJSONOf(t, sb.asEngineer("", "host", "list", "--json"))
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	if _, ok := js["db1"]; ok || len(js) != 2 || js["web1"].Name == "" || js["web2"].Name == "" {
		t.Errorf("an engineer's hosts: %+v", js)
	}
	if h := js["web1"].Breakglass; h == nil || !h.Held || h.Reason != "locked out of sudo" {
		t.Errorf("the hold of an engineer's host: %+v", h)
	}
	if js["web2"].Address != "192.168.1.12" {
		t.Errorf("web2 %+v", js["web2"])
	}
}

func TestHostListJSONEmpty(t *testing.T) {
	sb := newSandbox(t, true)
	// No host at all: an empty array, not a message.
	if got := sb.run("", []string{"host", "list", "--json"}); sb.code != 0 || got != "[]\n" {
		t.Errorf("no hosts: %d %q %q", sb.code, got, sb.stderr())
	}
	// None in an engineer's scopes: the same.
	sb = engineerSandbox(t)
	sb.write("state/linux-hosts", "db1|root@192.0.2.11||prod|192.0.2.1|\n", 0o600)
	if got := sb.asEngineer("", "host", "list", "--json"); sb.code != 0 || strings.TrimSpace(got) != "[]" {
		t.Errorf("none in the scopes: %d %q %q", sb.code, got, sb.stderr())
	}
	if got := sb.asEngineer("", "host", "list"); !strings.Contains(got, "None in your scopes.") {
		t.Errorf("table: %q", got)
	}
}

func TestHostListArguments(t *testing.T) {
	sb := hostLab(t)
	sb.run("", []string{"host", "list", "--bogus"})
	sb.expect(1, "", "Unknown option: '--bogus'")
	if !strings.Contains(sb.stderr(), "Usage: tacctl host list [--json]") {
		t.Errorf("stderr %q", sb.stderr())
	}
	sb.run("", []string{"host", "list", "web1"})
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Usage: tacctl host list [--json]") {
		t.Errorf("an argument: %d %q", sb.code, sb.stderr())
	}
}

// The USERS column and the JSON's users are one count.
func TestHostListJSONUsers(t *testing.T) {
	sb := hostLab(t)
	js := hostListJSONOf(t, sb.run("", []string{"host", "list", "--json"}))
	table := plain(sb.run("", []string{"host", "list"}))
	header, rows := hostListRows(table)
	for n, h := range js {
		if got := hostListCell(t, header, rows[n], "USERS"); got != strconv.Itoa(h.Users) {
			t.Errorf("%s: table %s, JSON %d", n, got, h.Users)
		}
	}
}

// The --local host is a row like the others: local, no ssh port, the address
// its record has, and no hold.
func TestHostListJSONLocalHost(t *testing.T) {
	sb := hostLab(t)
	sb.write("state/linux-hosts", hostLines+"here|local||lab|192.0.2.1|\n", 0o600)
	sb.recordHostAddress("here", "127.0.0.1")
	out := sb.run("", []string{"host", "list", "--json"})
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	here, ok := hostListJSONOf(t, out)["here"]
	if !ok || !here.Local || here.Port != 0 || here.Address != "127.0.0.1" || here.Breakglass != nil || here.Target != "local" || here.Scope != "lab" {
		t.Errorf("here %+v\n%s", here, out)
	}
	var raw []map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	for _, r := range raw {
		if r["name"] != "here" {
			continue
		}
		if _, has := r["breakglass"]; has {
			t.Errorf("a local host has a hold: %v", r)
		}
	}
}
