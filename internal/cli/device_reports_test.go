package cli

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/reports"
)

// 'device reports' end to end, in-process, on the sandbox of native_test.go
// (alice the superuser of prod and lab, bob the operator of lab, carol the
// read-only user of lab and dmz). The accounts are faked: every user's home is
// <sandbox>/home/<user>, so the reports are files of the sandbox.

// reportsBox is a sandbox with four devices and the records of three pulls.
type reportsBox struct {
	t  *testing.T
	sb *sandbox
}

func newReportsBox(t *testing.T) *reportsBox {
	t.Helper()
	sb := newSandbox(t, true)
	home := filepath.Join(sb.dir, "home")
	sb.hooks.sshAccountOf = func(name string) (sshAccount, error) {
		return sshAccount{UID: 1000, GID: 1000, Home: filepath.Join(home, name)}, nil
	}
	sb.write("state/tacctl.yaml", testBcryptOverride+"server:\n  name: tacctl\n", 0o600)
	sb.write("state/devices.yaml", `version: 1
settings:
  stale_days: 30
devices:
  sw1:
    address: 192.168.1.10
    vendor: cisco
    description: Access switch
    location: Rack 4, DC1
  jsw1:
    address: 192.168.1.20
    vendor: juniper
    location: Lab rack 2
  ap1:
    address: 192.168.1.30
    vendor: other
  rtr1:
    address: 10.99.0.1
    vendor: cisco
`, 0o600)
	st := devconf.Store{Records: filepath.Join(sb.dir, "var-lib", "devices-config.json"), Dir: filepath.Join(sb.dir, "var-lib", "device-config")}
	recs, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	recs.Put("sw1", devconf.Record{Address: "192.168.1.10", Vendor: "cisco", Result: devconf.ResultOK,
		Pulled: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC), Model: "WS-C3850-48P", Serial: "SN000001", Release: "16.12.4"})
	recs.Put("jsw1", devconf.Record{Address: "192.168.1.20", Vendor: "juniper", Result: devconf.ResultOK,
		Pulled: time.Date(2026, 11, 5, 9, 30, 0, 0, time.UTC), Model: "EX4300-48T", Serial: "SN000002", Release: "25.4R1-S2.3",
		Members: []devconf.Member{
			{ID: "0", Role: "master", Model: "EX4300-48T", Serial: "SN000002", Release: "25.4R1-S2.3", Status: "Prsnt", Priority: 129},
			{ID: "1", Role: "backup", Model: "EX4300-48T", Serial: "SN000003", Release: "25.4R1-S2.3", Status: "Prsnt", Priority: 129}}})
	if err := st.Save(recs); err != nil {
		t.Fatal(err)
	}
	return &reportsBox{t: t, sb: sb}
}

const (
	asSuper    = "tac-users tac-superuser"
	asOperator = "tac-users tac-operator"
	asReadonly = "tac-users tac-readonly"
)

// as runs 'tacctl device reports <args>' for a user of a group.
func (b *reportsBox) as(user, groups string, args ...string) string {
	b.t.Helper()
	return b.sb.asUser(user, groups, append([]string{"device", "reports"}, args...)...)
}

// dir is the reports directory of a user.
func (b *reportsBox) dir(user string) string {
	return filepath.Join(b.sb.dir, "home", user, "reports", "devices")
}

var writtenRE = regexp.MustCompile(`Report (\S+) written: (\S+)`)

// generate makes a report as a user and returns its name.
func (b *reportsBox) generate(user, groups string, args ...string) string {
	b.t.Helper()
	out := b.as(user, groups, append([]string{"generate"}, args...)...)
	m := writtenRE.FindStringSubmatch(out)
	if b.sb.code != 0 || m == nil {
		b.t.Fatalf("generate %v: %d %q %q", args, b.sb.code, out, b.sb.stderr())
	}
	return m[1]
}

// audits are the audit lines of the last run about reports.
func (b *reportsBox) audits() []string {
	var out []string
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "logger" {
			if l := strings.Join(c.Args, " "); strings.Contains(l, "device reports access") {
				out = append(out, l)
			}
		}
	}
	return out
}

func TestReportsGenerateTypesAndFormats(t *testing.T) {
	b := newReportsBox(t)
	for _, typ := range reports.Types() {
		for _, format := range reports.Formats() {
			if format == reports.FormatPDF {
				continue // made by an external tool: device_reports_pdf_test.go
			}
			t.Run(typ+"-"+format, func(t *testing.T) {
				out := b.as("alice", asSuper, "generate", "--type", typ, "--format", format, "--stdout")
				if b.sb.code != 0 {
					t.Fatalf("exit %d %q", b.sb.code, b.sb.stderr())
				}
				for _, dev := range []string{"sw1", "jsw1", "rtr1"} {
					if typ == reports.TypeMembers && dev == "rtr1" {
						continue // no model and no serial: no member row
					}
					if !strings.Contains(out, dev) {
						t.Errorf("no %s in the %s %s report:\n%s", dev, typ, format, out)
					}
				}
				switch format {
				case reports.FormatCSV:
					rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
					if err != nil || len(rows) < 2 || strings.Join(rows[0], ",") != strings.Join(reports.Columns(typ), ",") {
						t.Errorf("csv: %v %v", err, rows)
					}
				case reports.FormatJSON:
					var doc struct {
						Schema int              `json:"schema"`
						Type   string           `json:"type"`
						Rows   []map[string]any `json:"rows"`
					}
					if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Type != typ || doc.Schema != 1 || len(doc.Rows) == 0 {
						t.Errorf("json: %v %+v", err, doc)
					}
				}
			})
		}
	}
	// --stdout stores nothing
	if _, err := os.Stat(b.dir("alice")); !os.IsNotExist(err) {
		t.Errorf("--stdout made the directory: %v", err)
	}
}

func TestReportsRowsOfEachType(t *testing.T) {
	b := newReportsBox(t)
	out := b.as("alice", asSuper, "generate", "--type", "inventory", "--format", "csv", "--stdout")
	rows, _ := csv.NewReader(strings.NewReader(out)).ReadAll()
	got := map[string][]string{}
	for _, r := range rows[1:] {
		got[r[0]] = r
	}
	// name, address, vendor, scope, model, serial, release, members, location, description, pulled
	want := map[string]string{
		"sw1":  "sw1,192.168.1.10,cisco,lab,WS-C3850-48P,SN000001,16.12.4,-,\"Rack 4, DC1\",Access switch,2026-11-04 10:00",
		"jsw1": "jsw1,192.168.1.20,juniper,lab,EX4300-48T,SN000002,25.4R1-S2.3,2,Lab rack 2,,2026-11-05 09:30",
		"ap1":  "ap1,192.168.1.30,other,lab,,,,-,,,never",
		"rtr1": "rtr1,10.99.0.1,cisco,prod,,,,-,,,never",
	}
	if len(got) != len(want) {
		t.Fatalf("%d rows:\n%s", len(got), out)
	}
	for name, w := range want {
		var line strings.Builder
		cw := csv.NewWriter(&line)
		_ = cw.Write(got[name])
		cw.Flush()
		if strings.TrimSpace(line.String()) != w {
			t.Errorf("%s: %q, want %q", name, strings.TrimSpace(line.String()), w)
		}
	}
	// the members report: one row for each chassis member, one for a
	// standalone device with a serial, none for a device with neither
	out = b.as("alice", asSuper, "generate", "--type", "members", "--format", "csv", "--stdout")
	for _, w := range []string{"jsw1,0,master,EX4300-48T,SN000002", "jsw1,1,backup,EX4300-48T,SN000003", "sw1,-,-,WS-C3850-48P,SN000001"} {
		if !strings.Contains(out, w) {
			t.Errorf("members report lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "rtr1") || strings.Contains(out, "ap1") {
		t.Errorf("a device with no model and no serial has a member row:\n%s", out)
	}
	// the config report: a device that was never pulled is a row of 'never'
	out = b.as("alice", asSuper, "generate", "--type", "config", "--format", "csv", "--stdout")
	if !strings.Contains(out, "rtr1,prod,never,never,-") {
		t.Errorf("config report:\n%s", out)
	}
}

// A JSON report carries the filters of the command: the keys scope and vendor,
// only those that were given, {} for none; the stored file has the same.
func TestReportsJSONCarriesTheFilters(t *testing.T) {
	b := newReportsBox(t)
	filters := func(out string) map[string]string {
		t.Helper()
		var doc struct {
			Filters map[string]string `json:"filters"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Filters == nil {
			t.Fatalf("%v %q", err, out)
		}
		return doc.Filters
	}
	if f := filters(b.as("alice", asSuper, "generate", "--type", "software", "--format", "json", "--stdout")); len(f) != 0 {
		t.Errorf("no filters: %v", f)
	}
	if f := filters(b.as("alice", asSuper, "generate", "--type", "software", "--format", "json", "--stdout", "--scope", "lab")); len(f) != 1 || f["scope"] != "lab" {
		t.Errorf("scope: %v", f)
	}
	f := filters(b.as("alice", asSuper, "generate", "--type", "software", "--format", "json", "--stdout", "--scope", "lab", "--vendor", "cisco"))
	if len(f) != 2 || f["scope"] != "lab" || f["vendor"] != "cisco" {
		t.Errorf("both: %v", f)
	}
	name := b.generate("alice", asSuper, "--type", "software", "--format", "json", "--vendor", "cisco")
	body, err := os.ReadFile(filepath.Join(b.dir("alice"), name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if f := filters(string(body)); len(f) != 1 || f["vendor"] != "cisco" {
		t.Errorf("stored: %v", f)
	}
}

func TestReportsGenerateStoresTheFiles(t *testing.T) {
	b := newReportsBox(t)
	out := b.as("alice", asSuper, "generate", "--type", "inventory", "--format", "csv", "--scope", "lab", "--vendor", "cisco")
	m := writtenRE.FindStringSubmatch(out)
	if b.sb.code != 0 || m == nil {
		t.Fatalf("%d %q %q", b.sb.code, out, b.sb.stderr())
	}
	name := m[1]
	if want := "inventory-" + time.Now().UTC().Format("20060102"); name != want && !strings.HasPrefix(name, "inventory-") {
		t.Errorf("name %q", name)
	}
	dir := b.dir("alice")
	if m[2] != filepath.Join(dir, name+".csv") {
		t.Errorf("path %q", m[2])
	}
	for _, p := range []string{filepath.Join(dir, name+".csv"), filepath.Join(dir, name+".csv.meta")} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("directory: %v %v", st, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, name+".csv.meta"))
	meta, err := reports.ParseMeta(raw)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != name || meta.Type != "inventory" || meta.Format != "csv" || meta.User != "alice" || meta.Count != 1 ||
		meta.Command != "tacctl device reports generate --type inventory --format csv --scope lab --vendor cisco" ||
		meta.Filters["scope"] != "lab" || meta.Filters["vendor"] != "cisco" || len(meta.Filters) != 2 ||
		!meta.OldestData.Equal(time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("meta %+v", meta)
	}
	body, _ := os.ReadFile(filepath.Join(dir, name+".csv"))
	if meta.Size != int64(len(body)) || strings.Contains(string(body), "jsw1") || strings.Contains(string(body), "rtr1") {
		t.Errorf("size %d for %d bytes:\n%s", meta.Size, len(body), body)
	}

	// a second report of the same type and day gets -2, whatever its format
	if second := b.generate("alice", asSuper, "--type", "inventory", "--format", "json"); second != name+"-2" {
		t.Errorf("second report %q, want %q", second, name+"-2")
	}
	if third := b.generate("alice", asSuper, "--type", "inventory"); third != name+"-3" {
		t.Errorf("third report %q", third)
	}
	// --name
	b.generate("alice", asSuper, "--type", "members", "--name", "chassis.2026")
	if _, err := os.Stat(filepath.Join(dir, "chassis.2026.txt")); err != nil {
		t.Error(err)
	}
	// a name in use, in any format, is refused, and nothing is written
	b.as("alice", asSuper, "generate", "--type", "members", "--name", "chassis.2026", "--format", "json")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'chassis.2026' exists already") {
		t.Errorf("name in use: %d %q", b.sb.code, b.sb.stderr())
	}
	if _, err := os.Stat(filepath.Join(dir, "chassis.2026.json")); !os.IsNotExist(err) {
		t.Error("a report was written over a name in use")
	}
}

func TestReportsGenerateArguments(t *testing.T) {
	b := newReportsBox(t)
	for _, c := range []struct {
		want string
		args []string
	}{
		{"--type is required", []string{"generate"}},
		{"Unknown report type 'devices'", []string{"generate", "--type", "devices"}},
		{"Unknown report format 'docx' (valid formats: text, csv, json, pdf)", []string{"generate", "--type", "inventory", "--format", "docx"}},
		{"Invalid report name: a report name does not start with a dot", []string{"generate", "--type", "inventory", "--name", ".hidden"}},
		{"Invalid report name: a report name holds only letters", []string{"generate", "--type", "inventory", "--name", "a/b"}},
		{"at most 64 bytes", []string{"generate", "--type", "inventory", "--name", strings.Repeat("x", 65)}},
		{"--name names the stored report; --stdout stores nothing", []string{"generate", "--type", "inventory", "--name", "x", "--stdout"}},
		{"--vendor takes cisco, juniper, wti or other", []string{"generate", "--type", "inventory", "--vendor", "hp"}},
		{"Unknown option: '--as'", []string{"generate", "--type", "inventory", "--as", "bob"}},
	} {
		b.as("alice", asSuper, c.args...)
		if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), c.want) {
			t.Errorf("%v: exit %d %q", c.args, b.sb.code, b.sb.stderr())
		}
	}
	// a scope that does not exist, a user with no account
	b.as("alice", asSuper, "generate", "--type", "inventory", "--scope", "nowhere")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "Scope 'nowhere' does not exist") {
		t.Errorf("scope: %d %q", b.sb.code, b.sb.stderr())
	}
	b.as("carol", asReadonly, "generate", "--type", "inventory")
	if b.sb.code != 0 {
		t.Fatalf("carol: %d %q", b.sb.code, b.sb.stderr())
	}
	b.sb.hooks.sshAccountOf = func(string) (sshAccount, error) { return sshAccount{}, os.ErrNotExist }
	b.as("carol", asReadonly, "generate", "--type", "inventory")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "the user 'carol' has no account on this server") {
		t.Errorf("no account: %d %q", b.sb.code, b.sb.stderr())
	}
	b.as("carol", asReadonly, "generate", "--type", "inventory", "--stdout")
	if b.sb.code != 0 {
		t.Errorf("--stdout needs no account: %d %q", b.sb.code, b.sb.stderr())
	}
}

// A report holds the devices the scopes of the user cover, and a superuser all.
func TestReportsFollowTheScopes(t *testing.T) {
	b := newReportsBox(t)
	seen := func(user, groups string) string {
		out := b.as(user, groups, "generate", "--type", "inventory", "--format", "csv", "--stdout")
		if b.sb.code != 0 {
			t.Fatalf("%s: %d %q", user, b.sb.code, b.sb.stderr())
		}
		rows, _ := csv.NewReader(strings.NewReader(out)).ReadAll()
		var names []string
		for _, r := range rows[1:] {
			names = append(names, r[0])
		}
		return strings.Join(names, " ")
	}
	if got := seen("alice", asSuper); got != "ap1 jsw1 rtr1 sw1" {
		t.Errorf("superuser: %q", got)
	}
	if got := seen("bob", asOperator); got != "ap1 jsw1 sw1" {
		t.Errorf("operator of lab: %q", got)
	}
	if got := seen("carol", asReadonly); got != "ap1 jsw1 sw1" {
		t.Errorf("read-only user of lab and dmz: %q", got)
	}
	// a scope that is not his own is a scope that does not exist
	b.as("bob", asOperator, "generate", "--type", "inventory", "--scope", "prod", "--stdout")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "Scope 'prod' does not exist") {
		t.Errorf("another scope: %d %q", b.sb.code, b.sb.stderr())
	}
	// the metadata and the files are the user's own
	name := b.generate("bob", asOperator, "--type", "software")
	if _, err := os.Stat(filepath.Join(b.dir("bob"), name+".txt")); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(b.dir("alice")); !os.IsNotExist(err) {
		t.Error("a report was written in another home")
	}
}

// --pull is the engineer tier's: a lower tier is refused before anything is
// read or written.
func TestReportsPullNeedsTheEngineerTier(t *testing.T) {
	b := newReportsBox(t)
	for _, c := range []struct{ user, groups, tier string }{{"bob", asOperator, "operator"}, {"carol", asReadonly, "readonly"}} {
		b.as(c.user, c.groups, "generate", "--type", "inventory", "--pull")
		if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "--pull runs 'tacctl device config pull', which is not permitted for the "+c.tier+" tier") {
			t.Errorf("%s: %d %q", c.user, b.sb.code, b.sb.stderr())
		}
		if _, err := os.Stat(b.dir(c.user)); !os.IsNotExist(err) {
			t.Errorf("%s: a refused --pull made the directory", c.user)
		}
	}
	// and without --pull the same users generate
	b.generate("carol", asReadonly, "--type", "config")
}

func TestReportsLimitText(t *testing.T) {
	size := reportLimitText(reports.CheckLimits(11<<20, 1, reports.DefaultMaxSize, reports.DefaultMaxCount))
	count := reportLimitText(reports.CheckLimits(10, 101, reports.DefaultMaxSize, reports.DefaultMaxCount))
	for _, c := range []struct{ got, setting, verb string }{{size, "reports.max_size", "max-size <bytes>"}, {count, "reports.max_count", "max-count <n>"}} {
		if !strings.Contains(c.got, "(the setting "+c.setting+"; a superuser changes it with: tacctl config reports "+c.verb+")") || !strings.Contains(c.got, "tacctl device reports remove <name>") {
			t.Errorf("%q", c.got)
		}
	}
	if !strings.Contains(count, "101 reports, over the count limit of 100 reports") {
		t.Errorf("%q", count)
	}
}

// The 101st report is refused with the setting and the way out; the files in
// the directory that tacctl did not make are not reports.
func TestReportsCountLimitIsEnforced(t *testing.T) {
	b := newReportsBox(t)
	dir := b.dir("bob")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < reports.DefaultMaxCount; i++ {
		name := "old-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		mb, err := reports.MarshalMeta(reports.Meta{Name: name, Type: "inventory", Format: "text", User: "bob",
			Generated: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".txt.meta"), mb, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b.as("bob", asOperator, "generate", "--type", "software")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "that would be 101 reports, over the count limit of 100 reports (the setting reports.max_count; a superuser changes it with: tacctl config reports max-count <n>). Remove one with: tacctl device reports remove <name>") {
		t.Errorf("%d %q", b.sb.code, b.sb.stderr())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2*reports.DefaultMaxCount+1 {
		t.Errorf("%d files", len(ents))
	}
	// --stdout is not stored, so no limit applies
	b.as("bob", asOperator, "generate", "--type", "software", "--stdout")
	if b.sb.code != 0 {
		t.Errorf("--stdout: %d %q", b.sb.code, b.sb.stderr())
	}
	// removing one makes room
	b.as("bob", asOperator, "remove", "old-aa", "--yes")
	if b.generate("bob", asOperator, "--type", "software") == "" {
		t.Error("no room after a removal")
	}
}

func TestReportsListShowExportRenameRemove(t *testing.T) {
	b := newReportsBox(t)
	if out := b.as("alice", asSuper, "list"); b.sb.code != 0 || !strings.Contains(out, "Device reports (0)") || !strings.Contains(out, "None. Make one with: tacctl device reports generate --type inventory") {
		t.Errorf("empty list: %d %q", b.sb.code, out)
	}
	if out := b.as("alice", asSuper, "list", "--json"); strings.TrimSpace(out) != "[]" {
		t.Errorf("empty json: %q", out)
	}
	inv := b.generate("alice", asSuper, "--type", "inventory", "--format", "csv", "--scope", "lab")
	soft := b.generate("alice", asSuper, "--type", "software")
	// a file of the user's own
	if err := os.WriteFile(filepath.Join(b.dir("alice"), "notes.md"), []byte("# mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := b.as("alice", asSuper, "list")
	for _, w := range []string{"Device reports (3)", "NAME", "TYPE", "FORMAT", "SIZE", "GENERATED", inv, soft, "notes", "other", "3 reports, "} {
		if !strings.Contains(out, w) {
			t.Errorf("list lacks %q:\n%s", w, out)
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) >= 5 && f[0] == "notes" && (f[1] != "other" || f[2] != "md") {
			t.Errorf("the other file: %q", l)
		}
	}
	var listed []map[string]any
	if err := json.Unmarshal([]byte(b.as("alice", asSuper, "list", "--json")), &listed); err != nil || len(listed) != 3 {
		t.Fatalf("json: %v %v", err, listed)
	}
	byName := map[string]map[string]any{}
	for _, r := range listed {
		byName[r["name"].(string)] = r
	}
	if r := byName[inv]; r["type"] != "inventory" || r["format"] != "csv" || r["user"] != "alice" || r["owner"] != "alice" || r["rows"].(float64) != 3 || r["other"] != false {
		t.Errorf("json row: %v", r)
	}
	if r := byName["notes"]; r["other"] != true || r["file"] != "notes.md" {
		t.Errorf("json other: %v", r)
	}

	// show
	out = b.as("alice", asSuper, "show", inv)
	for _, w := range []string{"Report " + inv, "Type:", "inventory", "Generated:", " UTC", "User:         alice",
		"Command:      tacctl device reports generate --type inventory --format csv --scope lab", "Filters:      scope=lab",
		"Oldest data:  2026-11-04", "Format:       csv", "Rows:         3", "Size:",
		"Download:     scp alice@tacctl:reports/devices/" + inv + ".csv ."} {
		if !strings.Contains(out, w) {
			t.Errorf("show lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "sw1") {
		t.Errorf("show printed the content:\n%s", out)
	}
	out = b.as("alice", asSuper, "show", inv+".csv", "--content")
	if !strings.Contains(out, "name,address,vendor,scope") || !strings.Contains(out, "sw1,192.168.1.10") {
		t.Errorf("show --content:\n%s", out)
	}
	if out = b.as("alice", asSuper, "show", "notes"); !strings.Contains(out, "other (a file in the directory that tacctl did not make)") {
		t.Errorf("show other:\n%s", out)
	}
	b.as("alice", asSuper, "show", "nothing")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "there is no report 'nothing'") {
		t.Errorf("show nothing: %d %q", b.sb.code, b.sb.stderr())
	}

	// export: standard output, a file, no overwrite
	body, _ := os.ReadFile(filepath.Join(b.dir("alice"), inv+".csv"))
	if out = b.as("alice", asSuper, "export", inv); out != string(body) {
		t.Errorf("export:\n%q\n%q", out, body)
	}
	dest := filepath.Join(b.sb.homePath(""), "copy.csv")
	b.as("alice", asSuper, "export", inv, "--out", dest)
	if got, err := os.ReadFile(dest); err != nil || string(got) != string(body) {
		t.Errorf("export --out: %v %q", err, got)
	}
	if st, _ := os.Stat(dest); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	b.as("alice", asSuper, "export", inv, "--out", dest)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "exists (--force replaces it)") {
		t.Errorf("export over a file: %d %q", b.sb.code, b.sb.stderr())
	}
	b.as("alice", asSuper, "export", soft, "--out", dest, "--force")
	if got, _ := os.ReadFile(dest); strings.Contains(string(got), "name,address") || b.sb.code != 0 {
		t.Errorf("export --force: %d %q", b.sb.code, got)
	}
	b.as("alice", asSuper, "export", inv, "--force")
	if b.sb.code != 2 {
		t.Errorf("--force alone: %d", b.sb.code)
	}

	// rename: file and metadata, the name inside the metadata too
	b.as("alice", asSuper, "rename", inv, "lab-inventory")
	if b.sb.code != 0 {
		t.Fatalf("rename: %d %q", b.sb.code, b.sb.stderr())
	}
	dir := b.dir("alice")
	for _, gone := range []string{inv + ".csv", inv + ".csv.meta"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s is still there", gone)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "lab-inventory.csv.meta"))
	if m, err := reports.ParseMeta(raw); err != nil || m.Name != "lab-inventory" || m.Type != "inventory" {
		t.Errorf("meta after rename: %v %+v", err, m)
	}
	for _, c := range []struct {
		want string
		args []string
	}{
		{"exists: a report is never overwritten", []string{"rename", "lab-inventory", soft}},
		{"exists: a report is never overwritten", []string{"rename", "lab-inventory", "notes"}},
		{"is a file that tacctl did not make: it is not renamed", []string{"rename", "notes", "other"}},
		{"Invalid report name", []string{"rename", "lab-inventory", "a b"}},
	} {
		b.as("alice", asSuper, c.args...)
		if b.sb.code == 0 || !strings.Contains(b.sb.stderr(), c.want) {
			t.Errorf("%v: %d %q", c.args, b.sb.code, b.sb.stderr())
		}
	}

	// remove: asks, a no leaves it, a file of the user's own is never removed
	if out = b.as("alice", asSuper, "remove", "lab-inventory"); !strings.Contains(out, "Aborted.") && !strings.Contains(b.sb.stderr()+out, "Aborted") {
		t.Errorf("remove without an answer: %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "lab-inventory.csv")); err != nil {
		t.Error("removed without a yes")
	}
	b.as("alice", asSuper, "remove", "notes", "--yes")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "is a file that tacctl did not make: it is not removed") {
		t.Errorf("remove other: %d %q", b.sb.code, b.sb.stderr())
	}
	b.as("alice", asSuper, "remove", "lab-inventory", "--yes")
	if b.sb.code != 0 {
		t.Fatalf("remove: %d %q", b.sb.code, b.sb.stderr())
	}
	for _, gone := range []string{"lab-inventory.csv", "lab-inventory.csv.meta"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s is still there", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.md")); err != nil {
		t.Error("the user's own file went")
	}
}

// Two files with one name (two formats of one report name) need the extension.
func TestReportsExtensionAmbiguity(t *testing.T) {
	b := newReportsBox(t)
	b.generate("alice", asSuper, "--type", "software", "--name", "fleet", "--format", "csv")
	// a file of the user's own with the same base name
	if err := os.WriteFile(filepath.Join(b.dir("alice"), "fleet.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b.as("alice", asSuper, "show", "fleet")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'fleet' names several reports (fleet.csv, fleet.json): give the file name with its extension") {
		t.Errorf("%d %q", b.sb.code, b.sb.stderr())
	}
	if out := b.as("alice", asSuper, "show", "fleet.json"); b.sb.code != 0 || !strings.Contains(out, "other (a file") {
		t.Errorf("with the extension: %d %q", b.sb.code, out)
	}
	if out := b.as("alice", asSuper, "export", "fleet.csv"); b.sb.code != 0 || !strings.Contains(out, "name,vendor,model,release,pulled") {
		t.Errorf("export: %d %q", b.sb.code, out)
	}
	// the name is taken in any extension
	b.as("alice", asSuper, "generate", "--type", "software", "--name", "fleet", "--format", "text")
	if b.sb.code != 1 {
		t.Errorf("a name taken by another extension: %d", b.sb.code)
	}
	if got := b.sb.asUser("alice", asSuper, "_completion-names", "reports"); !strings.Contains(got, "fleet.csv\n") || !strings.Contains(got, "fleet.json\n") {
		t.Errorf("completion: %q", got)
	}
}

// Metadata that cannot be used leaves a file listed as other, with the reason.
func TestReportsDamagedMetadata(t *testing.T) {
	b := newReportsBox(t)
	name := b.generate("alice", asSuper, "--type", "config")
	if err := os.WriteFile(filepath.Join(b.dir("alice"), name+".txt.meta"), []byte(`{"schema": 9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := b.as("alice", asSuper, "list"); !strings.Contains(out, "other") {
		t.Errorf("list:\n%s", out)
	}
	if out := b.as("alice", asSuper, "show", name); !strings.Contains(out, "schema 9, newer than the 1 this tacctl reads") {
		t.Errorf("show:\n%s", out)
	}
}

// The content of an 'other' file is cleaned before it is printed, and the
// first 200 lines are the most show prints.
func TestReportsShowContentIsCappedAndCleaned(t *testing.T) {
	b := newReportsBox(t)
	if err := os.MkdirAll(b.dir("alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString("first \x1b[31mred\x1b[0m\n")
	for i := 2; i <= 250; i++ {
		sb.WriteString("line\n")
	}
	if err := os.WriteFile(filepath.Join(b.dir("alice"), "big.txt"), []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	out := b.as("alice", asSuper, "show", "big", "--content")
	if strings.Contains(out, "\x1b") || !strings.Contains(out, "first ?[31mred?[0m") || countLines(out, "line") != 199 ||
		!strings.Contains(out, "... 50 more lines; 'tacctl device reports export big' prints all of it.") {
		t.Errorf("show --content: %d lines\n%.300s", strings.Count(out, "\n"), out)
	}
}

// countLines is how many lines of text are exactly line.
func countLines(text, line string) int {
	n := 0
	for _, l := range strings.Split(text, "\n") {
		if l == line {
			n++
		}
	}
	return n
}

// generate follows the settings of 'config reports' and the user's own limit
// (D326): the global count of one refuses a second report, an own limit of no
// cap lifts it for that user only, and an own size of one byte refuses a report.
func TestReportsFollowTheConfiguredLimits(t *testing.T) {
	b := newReportsBox(t)
	b.sb.asAlice("", "config", "reports", "max-count", "1")
	b.sb.expect(0, "", "")
	if b.generate("bob", asOperator, "--type", "software") == "" {
		t.Fatal("the first report was refused")
	}
	b.as("bob", asOperator, "generate", "--type", "software")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "the setting reports.max_count") {
		t.Errorf("global count: %d %q", b.sb.code, b.sb.stderr())
	}
	b.sb.asAlice("", "user", "reports-limit", "bob", "max-count", "0")
	b.sb.expect(0, "", "")
	if b.generate("bob", asOperator, "--type", "members") == "" {
		t.Error("an own limit of no cap did not lift the global count")
	}
	b.sb.asAlice("", "user", "reports-limit", "bob", "max-size", "1")
	b.sb.expect(0, "", "")
	b.as("bob", asOperator, "generate", "--type", "inventory")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "reports.max_size") {
		t.Errorf("own size: %d %q", b.sb.code, b.sb.stderr())
	}
}

// The config report's state and applied date are the configuration state that
// 'device list' shows from the operator tier up (D69): a read-only user's
// report has "-" for both (null in JSON), an operator's has them, and the
// pulled date, which the other reports hold too, stays.
func TestReportsConfigStateIsOperatorAndUp(t *testing.T) {
	b := newReportsBox(t)
	st := devconf.Store{Records: filepath.Join(b.sb.dir, "var-lib", "devices-config.json"), Dir: filepath.Join(b.sb.dir, "var-lib", "device-config")}
	recs, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := recs.Of("sw1")
	rec.Applied = &devconf.Applied{Result: devconf.AppliedApplied, At: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	recs.Put("sw1", *rec)
	if err := st.Save(recs); err != nil {
		t.Fatal(err)
	}

	op := b.as("bob", asOperator, "generate", "--type", "config", "--format", "csv", "--stdout")
	if !strings.Contains(op, "sw1,lab,never,2026-11-04 10:00,2026-11-05 12:00") || !strings.Contains(op, "jsw1,lab,never,2026-11-05 09:30,-") {
		t.Errorf("the operator's config report has no state and applied date:\n%s", op)
	}
	ro := b.as("carol", asReadonly, "generate", "--type", "config", "--format", "csv", "--stdout")
	for _, want := range []string{"sw1,lab,-,2026-11-04 10:00,-", "jsw1,lab,-,2026-11-05 09:30,-"} {
		if !strings.Contains(ro, want) {
			t.Errorf("the read-only config report lacks %q:\n%s", want, ro)
		}
	}
	for _, word := range []string{"lab,never,", "lab,differs,", "lab,ok,", "lab,failed,", "2026-11-05 12:00"} {
		if strings.Contains(ro, word) {
			t.Errorf("the read-only config report shows %q:\n%s", word, ro)
		}
	}
	js := b.as("carol", asReadonly, "generate", "--type", "config", "--format", "json", "--stdout")
	var doc struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(js), &doc); err != nil || len(doc.Rows) == 0 {
		t.Fatalf("json: %v\n%s", err, js)
	}
	for _, row := range doc.Rows {
		if v, ok := row["state"]; !ok || v != nil {
			t.Errorf("state of %v: %v, want null", row["name"], v)
		}
		if v, ok := row["applied"]; !ok || v != nil {
			t.Errorf("applied of %v: %v, want null", row["name"], v)
		}
	}
	// the other reports keep the pulled date and the facts that 'device show'
	// shows a read-only user (the next tests hold what it does not show)
	if inv := b.as("carol", asReadonly, "generate", "--type", "inventory", "--format", "csv", "--stdout"); !strings.Contains(inv, "2026-11-04 10:00") {
		t.Errorf("inventory:\n%s", inv)
	}
}

// What the pull read of a device (model, serial, release, chassis members) is
// the operator tier's in 'device show' and 'device list'; the reports follow
// the same rule (configVisible). Inventory: the three facts are "-" and the
// members count is "-", the rest of the row (address, vendor, scope, location,
// description, pulled) is what it was.
func TestReportsInventoryFactsAreOperatorAndUp(t *testing.T) {
	b := newReportsBox(t)
	op := b.as("bob", asOperator, "generate", "--type", "inventory", "--format", "csv", "--stdout")
	for _, want := range []string{
		"sw1,192.168.1.10,cisco,lab,WS-C3850-48P,SN000001,16.12.4,-,\"Rack 4, DC1\",Access switch,2026-11-04 10:00",
		"jsw1,192.168.1.20,juniper,lab,EX4300-48T,SN000002,25.4R1-S2.3,2,Lab rack 2,,2026-11-05 09:30"} {
		if !strings.Contains(op, want) {
			t.Errorf("the operator's inventory lacks %q:\n%s", want, op)
		}
	}
	ro := b.as("carol", asReadonly, "generate", "--type", "inventory", "--format", "csv", "--stdout")
	for _, want := range []string{
		"sw1,192.168.1.10,cisco,lab,,,,-,\"Rack 4, DC1\",Access switch,2026-11-04 10:00",
		"jsw1,192.168.1.20,juniper,lab,,,,-,Lab rack 2,,2026-11-05 09:30"} {
		if !strings.Contains(ro, want) {
			t.Errorf("the read-only inventory lacks %q:\n%s", want, ro)
		}
	}
	for _, word := range []string{"WS-C3850-48P", "EX4300-48T", "SN00000", "16.12.4", "25.4R1"} {
		if strings.Contains(ro, word) {
			t.Errorf("the read-only inventory shows %q:\n%s", word, ro)
		}
	}
	txt := b.as("carol", asReadonly, "generate", "--type", "inventory", "--stdout")
	for _, word := range []string{"WS-C3850-48P", "EX4300-48T", "SN00000", "16.12.4", "25.4R1"} {
		if strings.Contains(txt, word) {
			t.Errorf("the read-only text inventory shows %q:\n%s", word, txt)
		}
	}
	js := b.as("carol", asReadonly, "generate", "--type", "inventory", "--format", "json", "--stdout")
	var doc struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(js), &doc); err != nil || len(doc.Rows) == 0 {
		t.Fatalf("json: %v\n%s", err, js)
	}
	for _, row := range doc.Rows {
		for _, k := range []string{"model", "serial", "release"} {
			if v, ok := row[k]; !ok || v != "" {
				t.Errorf("%s of %v: %v, want empty", k, row["name"], v)
			}
		}
		if v, ok := row["members"]; !ok || v != float64(0) {
			t.Errorf("members of %v: %v, want 0", row["name"], v)
		}
		if row["name"] == "sw1" && row["pulled"] != "2026-11-04T10:00:00Z" {
			t.Errorf("pulled of sw1: %v", row["pulled"])
		}
	}
}

// The members report has no rows for a read-only user (a device with neither
// model nor serial has no row, and its members are not read).
func TestReportsMembersAreOperatorAndUp(t *testing.T) {
	b := newReportsBox(t)
	op := b.as("bob", asOperator, "generate", "--type", "members", "--format", "csv", "--stdout")
	for _, want := range []string{"jsw1,0,master,EX4300-48T,SN000002", "jsw1,1,backup,EX4300-48T,SN000003", "sw1,-,-,WS-C3850-48P,SN000001"} {
		if !strings.Contains(op, want) {
			t.Errorf("the operator's members report lacks %q:\n%s", want, op)
		}
	}
	for _, format := range []string{"csv", "text", "json"} {
		ro := b.as("carol", asReadonly, "generate", "--type", "members", "--format", format, "--stdout")
		if b.sb.code != 0 {
			t.Fatalf("%s: exit %d %q", format, b.sb.code, b.sb.stderr())
		}
		for _, word := range []string{"jsw1", "sw1", "EX4300-48T", "WS-C3850-48P", "SN00000"} {
			if format != "json" && strings.Contains(ro, word) {
				t.Errorf("the read-only members report (%s) shows %q:\n%s", format, word, ro)
			}
		}
		if format == "json" {
			var doc struct {
				Rows []map[string]any `json:"rows"`
			}
			if err := json.Unmarshal([]byte(ro), &doc); err != nil || len(doc.Rows) != 0 {
				t.Errorf("the read-only members json has rows: %v\n%s", err, ro)
			}
		}
	}
	ro := b.as("carol", asReadonly, "generate", "--type", "members", "--format", "csv", "--stdout")
	if got := strings.Count(strings.TrimSpace(ro), "\n"); got != 0 {
		t.Errorf("the read-only members report has more than the header:\n%s", ro)
	}
}

// The software report: the model and the release are "-" for a read-only
// user, the name, the vendor and the pulled date stay.
func TestReportsSoftwareFactsAreOperatorAndUp(t *testing.T) {
	b := newReportsBox(t)
	op := b.as("bob", asOperator, "generate", "--type", "software", "--format", "csv", "--stdout")
	if !strings.Contains(op, "sw1,cisco,WS-C3850-48P,16.12.4,2026-11-04 10:00") {
		t.Errorf("the operator's software report:\n%s", op)
	}
	ro := b.as("carol", asReadonly, "generate", "--type", "software", "--format", "csv", "--stdout")
	for _, want := range []string{"sw1,cisco,,,2026-11-04 10:00", "jsw1,juniper,,,2026-11-05 09:30"} {
		if !strings.Contains(ro, want) {
			t.Errorf("the read-only software report lacks %q:\n%s", want, ro)
		}
	}
	txt := b.as("carol", asReadonly, "generate", "--type", "software", "--stdout")
	for _, word := range []string{"WS-C3850-48P", "EX4300-48T", "16.12.4", "25.4R1"} {
		if strings.Contains(ro, word) || strings.Contains(txt, word) {
			t.Errorf("the read-only software report shows %q:\n%s%s", word, ro, txt)
		}
	}
}

// 'export --out' writes inside the caller's home only; ~ and variables are
// not expanded, and the report is not even read for a refused path.
func TestReportsExportOutIsInsideTheHome(t *testing.T) {
	b := newReportsBox(t)
	outside := t.TempDir()
	for _, path := range []string{filepath.Join(outside, "x.csv"), "~/x.csv", "$HOME/x.csv", b.sb.homePath("../x.csv")} {
		b.as("alice", asSuper, "export", "anything", "--out", path)
		if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--out '"+path+"'") ||
			!strings.Contains(b.sb.stderr(), "tacctl does not expand ~ or variables; name a path inside your home, relative to the current directory.") {
			t.Errorf("export --out %s: %d %q", path, b.sb.code, b.sb.stderr())
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("written outside the home: %v", ents)
	}
}
