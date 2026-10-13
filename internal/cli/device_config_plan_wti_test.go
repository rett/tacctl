package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// 'device config plan' for a WTI unit, end to end against the fake unit
// (device_config_pull_wti_test.go): the checklist and the IP tables block it
// makes from the last pull, the refusals of the verb and the files. The
// planner's own output is pinned by the goldens of internal/devconf/plan.

const (
	wtiPlanCommunity = "SENTINELplan-9f3a"
	wtiPlanSecret    = "lab-secret-0123456789abcdef"
)

// planBoxWTI is a box with one unit, pulled once, whose scope has a
// management permit list, an SNMP community and version, so that the plan
// has an AAA step, an SNMP step and the IP tables block.
func planBoxWTI(t *testing.T) *pullBox {
	t.Helper()
	b := newWTIBox(t, "administrator", 1)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
	b.run("scope", "mgmt-acl", "lab", "add", "10.10.0.0/16")
	if b.sb.code != 0 {
		t.Fatalf("mgmt-acl: %d %s", b.sb.code, b.sb.stderr())
	}
	plain(b.sb.cfgRun(wtiPlanCommunity+"\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, route, "SUDO_USER=alice"))
	b.run("scope", "snmp", "lab", "version", "v2c")
	if out := b.run("device", "config", "pull", "pdu1"); b.sb.code != 0 {
		t.Fatalf("pull: %d %s %s", b.sb.code, out, b.sb.stderr())
	}
	return b
}

func TestPlanWTIFromTheLastPull(t *testing.T) {
	b := planBoxWTI(t)
	logins := b.srv.Logins()
	out := b.run("device", "config", "plan", "pdu1")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	// the plan reads no unit and writes none
	if b.srv.Logins() != logins {
		t.Errorf("plan logged in to the unit (%d, was %d)", b.srv.Logins(), logins)
	}
	if got := b.srv.Saved(); len(got) != 0 {
		t.Errorf("the unit saved: %q", got)
	}
	for _, want := range []string{
		"##### pdu1  192.168.1.40  scope lab  wti (TACACS+) #####",
		"##### DO THESE STEPS ON: pdu1 #####",
		"/N  28  2  Primary host/address  -> 1 (IPv4), then 10.0.0.42   was: 192.0.2.42",
		"/N  25  7  Read-Only Community   -> <the scope's SNMP community: tacctl scope snmp lab show --reveal>",
		"ESC ESC  leave /N: wait for \"Saving configuration to flash\"",
		"##### END OF STEPS #####",
		"##### IP TABLES (replaces every entry; see the notes): pdu1 #####",
		"<iptables>\niptables -A INPUT -i lo -j ACCEPT\n",
		"\niptables -A INPUT -j DROP\niptables -A OUTPUT -j ACCEPT\niptables -P INPUT DROP\n",
		"</iptables>\n##### END OF IP TABLES: pdu1 #####",
		"WARNING: the pull saw 1 other session on the unit",
		"tacctl device config plan pdu1 --backout",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	for _, bad := range []string{"PASTE FROM HERE", "configure private", "commit confirmed", "write memory"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q in a unit's plan", bad)
		}
	}
	// the only lines that are not comments are the block's, between its banners
	inside := false
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "##### IP TABLES"):
			inside = true
		case strings.HasPrefix(l, "##### END OF IP TABLES"):
			inside = false
		case strings.HasPrefix(l, "#") || l == "":
		case !inside || !regexp.MustCompile(`^(</?iptables>|iptables -[AP] .{1,250})$`).MatchString(l):
			t.Errorf("a line that is not a comment and not of the block: %q", l)
		}
	}
	// no secret in the plan, the audit line or standard error
	noSecrets(t, "the plan", out, wtiPlanCommunity, wtiPlanSecret, testPassword)
	noSecrets(t, "stderr", b.sb.stderr(), wtiPlanCommunity, wtiPlanSecret, testPassword)
	al := b.auditLines("device config plan")
	if len(al) != 1 || !strings.Contains(al[0], "device config plan user=alice device=pdu1 status=needs-change sections=snmp,aaa,mgmt-acl converge=no secrets=placeholders out=-") {
		t.Errorf("audit %q", al)
	}
	noSecrets(t, "audit", strings.Join(al, "\n"), wtiPlanCommunity, wtiPlanSecret, testPassword)

	// --secrets types the value and says so on both streams
	out = b.run("device", "config", "plan", "pdu1", "--secrets")
	if b.sb.code != 0 || !strings.Contains(out, "-> "+wtiPlanCommunity) || !strings.Contains(out, "-> "+wtiPlanSecret) ||
		!strings.Contains(out, "THIS OUTPUT HOLDS THE SNMP COMMUNITY AND THE TACACS+ SECRET OF SCOPE lab") ||
		!strings.Contains(b.sb.stderr(), "pdu1: THIS OUTPUT HOLDS THE SNMP COMMUNITY") {
		t.Errorf("--secrets: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if al := b.auditLines("device config plan"); len(al) != 1 || !strings.Contains(al[0], "secrets=values") || strings.Contains(al[0], wtiPlanCommunity) {
		t.Errorf("audit %q", al)
	}
	// --json: the same fields, no value
	js := b.run("device", "config", "plan", "pdu1", "--json", "--secrets")
	var docs []map[string]any
	if err := json.Unmarshal([]byte(js), &docs); err != nil || len(docs) != 1 {
		t.Fatalf("json: %v\n%s", err, js)
	}
	if docs[0]["status"] != "needs-change" || docs[0]["vendor"] != "wti" || docs[0]["holds_secret"] != true {
		t.Errorf("json: %v", docs[0])
	}
	if strings.Contains(js, wtiPlanCommunity) || strings.Contains(js, wtiPlanSecret) {
		t.Errorf("the community in the JSON:\n%s", js)
	}
	if region, _ := docs[0]["region"].([]any); !slices.ContainsFunc(region, func(x any) bool { return x == "<iptables>" }) {
		t.Errorf("no block in the JSON region: %v", docs[0]["region"])
	}
	if bo, _ := docs[0]["backout"].([]any); len(bo) == 0 {
		t.Errorf("no back-out in the JSON")
	}
}

func TestPlanWTIBackoutAndFiles(t *testing.T) {
	b := planBoxWTI(t)
	out := b.run("device", "config", "plan", "pdu1", "--backout")
	if b.sb.code != 0 {
		t.Fatalf("--backout without a plan: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	// no plan was made yet: nothing was kept
	if !strings.Contains(out, "nothing to back out") && !strings.Contains(out, "BACK-OUT") {
		t.Errorf("--backout before a plan:\n%s", out)
	}
	plan := b.run("device", "config", "plan", "pdu1")
	if b.sb.code != 0 {
		t.Fatalf("plan: %d", b.sb.code)
	}
	_ = plan
	out = b.run("device", "config", "plan", "pdu1", "--backout")
	for _, want := range []string{"BACK-OUT of the plan for pdu1", "##### BACK-OUT, IP TABLES (replaces every entry; see the notes): pdu1 #####",
		"<iptables>\niptables -A INPUT -i lo -j ACCEPT\n", "##### UNDO THESE STEPS ON: pdu1 #####", "/N  28  2  Primary host/address  -> 1 (IPv4), then 192.0.2.42   was: 1 (IPv4), then 10.0.0.42"} {
		if !strings.Contains(out, want) && !strings.Contains(unwrapPlan(out), want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	noSecrets(t, "the back-out", out, wtiPlanCommunity, wtiPlanSecret, testPassword)

	// --out-dir: a .txt and the back-out, no .set; 0600 in a 0700 directory
	dir := filepath.Join(t.TempDir(), "plans")
	b.run("device", "config", "plan", "pdu1", "--out-dir", dir)
	if b.sb.code != 0 {
		t.Fatalf("--out-dir: %d %s", b.sb.code, b.sb.stderr())
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
		if st, _ := e.Info(); st.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v", e.Name(), st.Mode().Perm())
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"pdu1.backout.txt", "pdu1.txt"}) {
		t.Errorf("files %v", names)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "pdu1.txt"))
	if !strings.Contains(string(data), "##### DO THESE STEPS ON: pdu1 #####") || strings.Contains(string(data), wtiPlanCommunity) {
		t.Errorf("pdu1.txt:\n%s", data)
	}
	// --out: one file
	f := filepath.Join(t.TempDir(), "pdu1.txt")
	b.run("device", "config", "plan", "pdu1", "--out", f)
	if b.sb.code != 0 {
		t.Fatalf("--out: %d %s", b.sb.code, b.sb.stderr())
	}
	if _, err := os.Stat(f); err != nil {
		t.Error(err)
	}
}

func TestPlanWTIRefusals(t *testing.T) {
	b := planBoxWTI(t)
	bad := func(want string, args ...string) {
		t.Helper()
		out := b.run(append([]string{"device", "config", "plan"}, args...)...)
		if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), want) || strings.Contains(out, "##### DO THESE STEPS") {
			t.Errorf("%v: exit %d stdout %q stderr %q", args, b.sb.code, out, b.sb.stderr())
		}
	}
	bad("a WTI unit (pdu1) has none", "pdu1", "--plain")
	bad("a WTI unit (pdu1) has no roles or system section", "pdu1", "--section", "roles")
	bad("a WTI unit (pdu1) has no roles or system section", "--all", "--section", "aaa,system")
	bad("never planned", "pdu1", "--section", "breakglass")
	bad("never planned", "pdu1", "--section", "netconf")

	// --section selects: aaa alone has no block
	out := b.run("device", "config", "plan", "pdu1", "--section", "aaa")
	if b.sb.code != 0 || strings.Contains(out, "<iptables>") || !strings.Contains(out, "Primary host/address") || strings.Contains(out, "Read-Only Community  ") {
		t.Errorf("--section aaa: %d\n%s", b.sb.code, out)
	}
	out = b.run("device", "config", "plan", "pdu1", "--section", "mgmt-acl")
	if b.sb.code != 0 || !strings.Contains(out, "<iptables>") || strings.Contains(out, "DO THESE STEPS") {
		t.Errorf("--section mgmt-acl: %d\n%s", b.sb.code, out)
	}
	// --from outside the list: the block is not made, the rest is
	out = b.run("device", "config", "plan", "pdu1", "--from", "198.51.100.77")
	if b.sb.code != 0 || strings.Contains(out, "<iptables>") || !strings.Contains(out, "198.51.100.77 is not permitted") ||
		!strings.Contains(out, "DO THESE STEPS") {
		t.Errorf("--from: %d\n%s", b.sb.code, out)
	}
	// --from inside it: the block is made
	out = b.run("device", "config", "plan", "pdu1", "--from", "10.10.3.4")
	if b.sb.code != 0 || !strings.Contains(out, "<iptables>") {
		t.Errorf("--from inside: %d\n%s", b.sb.code, out)
	}
	// --converge beside a first region: the line that says to plan again
	out = b.run("device", "config", "plan", "pdu1", "--converge")
	if b.sb.code != 0 || !strings.Contains(unwrapPlan(out), "cleanup comes after this region is pasted and verified") {
		t.Errorf("--converge: %d\n%s", b.sb.code, out)
	}
	// selectors take the unit
	for _, args := range [][]string{{"--all"}, {"--vendor", "wti"}, {"--scope", "lab"}} {
		out = b.run(append([]string{"device", "config", "plan"}, args...)...)
		if b.sb.code != 0 || !strings.Contains(out, "DO THESE STEPS ON: pdu1") {
			t.Errorf("%v: %d\n%s\n%s", args, b.sb.code, out, b.sb.stderr())
		}
	}
	// the exit code of a unit that needs a change
	b.run("device", "config", "plan", "pdu1", "--exit-code")
	if b.sb.code != 2 {
		t.Errorf("--exit-code: %d", b.sb.code)
	}
}

// plan --pull reads the unit first, as any device.
func TestPlanWTIPull(t *testing.T) {
	b := planBoxWTI(t)
	before := b.srv.Logins()
	out := b.run("device", "config", "plan", "pdu1", "--pull")
	if b.sb.code != 0 {
		t.Fatalf("--pull: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if b.srv.Logins() <= before {
		t.Errorf("--pull did not log in to the unit")
	}
	if !strings.Contains(out, "##### DO THESE STEPS ON: pdu1 #####") {
		t.Errorf("no plan after --pull:\n%s", out)
	}
	if got := b.srv.Saved(); len(got) != 0 {
		t.Errorf("the unit saved: %q", got)
	}
}

// plan --pull reads a unit that was never pulled (one password prompt) and
// plans it; a selection takes it.
func TestPlanWTIPullsAndPlansAUnit(t *testing.T) {
	b := newWTIBox(t, "administrator", 0)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
	out := b.run("device", "config", "plan", "pdu1", "--pull")
	if b.sb.code != 0 || !strings.Contains(out, "##### DO THESE STEPS ON: pdu1 #####") {
		t.Fatalf("plan --pull: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if b.srv.Logins() != 2 || b.pw.asked != 1 {
		t.Errorf("--pull: %d logins, %d password prompts, want the pages' session, the directory's and one prompt", b.srv.Logins(), b.pw.asked)
	}
	if got := b.srv.Saved(); len(got) != 0 {
		t.Errorf("the unit saved: %q", got)
	}
	if strings.Contains(out, "does not cover") || strings.Contains(b.sb.stderr(), "skipped") {
		t.Errorf("the unit was left out:\n%s\n%s", out, b.sb.stderr())
	}
}

// A unit of a RADIUS scope is planned from the RADIUS page's rendering: the
// TACACS+ page that is on is one finding, and --converge switches it off.
func TestPlanWTIRadiusScope(t *testing.T) {
	b := newWTIBox(t, "administrator", 0)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
	b.sb.run("", []string{"scope", "vendor-attrs", "lab", "enable", "cisco,juniper,wti"})
	b.sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\nlisteners:\n  radius:\n    auth: {network: udp, address: \"10.0.0.77:1645\", role: auth}\n", 0o600)
	b.sb.run("", []string{"scope", "auth-method", "lab", "radius"})
	if out := b.run("device", "config", "pull", "pdu1"); b.sb.code != 0 {
		t.Fatalf("pull: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	out := b.run("device", "config", "plan", "pdu1")
	if b.sb.code != 0 {
		t.Fatalf("plan: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"scope lab  wti (RADIUS) #####", "/N  29  2  Primary Host/Address", "1 (IPv4), then 10.0.0.77",
		"/N  29  9  Authentication Port", "-> 1645", "/N  29  1  Enable", "-> 2 (On)", "the unit's TACACS+ page is in use while the scope uses RADIUS"} {
		if !strings.Contains(unwrapPlan(out), want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "/N  28") {
		t.Errorf("a step on the TACACS+ page:\n%s", out)
	}
	// --converge: the unit has a first region, so the cleanup is deferred
	out = b.run("device", "config", "plan", "pdu1", "--converge")
	if !strings.Contains(unwrapPlan(out), "cleanup comes after this region is pasted and verified") {
		t.Errorf("--converge:\n%s", out)
	}
	noSecrets(t, "output", out+b.storeText(), wtiSentinels...)
}
