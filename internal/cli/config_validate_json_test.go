package cli

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

// 'config validate --json' (docs/plans/0.2.15-plan.md D219-D221): the
// object of the plan, nothing else on standard output, and the exit status
// of the text report.

// validateJSONOf decodes the whole of out as the object of D220: a field the
// object does not have, or anything after it, fails the test.
func validateJSONOf(t *testing.T, out string) validateJSON {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var v validateJSON
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("not the JSON object: %v\n%s", err, out)
	}
	if dec.More() {
		t.Fatalf("standard output holds more than the object:\n%s", out)
	}
	return v
}

// sections are the sections the findings of v are in.
func (v validateJSON) sections() []string {
	var out []string
	for _, f := range v.Findings {
		if !slices.Contains(out, f.Section) {
			out = append(out, f.Section)
		}
	}
	return out
}

// find is the first finding of a section, or nil.
func (v validateJSON) find(section string) *validateFinding {
	for i := range v.Findings {
		if v.Findings[i].Section == section {
			return &v.Findings[i]
		}
	}
	return nil
}

// A store that validates prints valid: true, no error and the warnings the
// text report has, and exits 0; the object has every field of D220.
func TestConfigValidateJSONValid(t *testing.T) {
	sb := renderedSandbox(t)
	out := sb.run("", []string{"config", "validate", "--json"})
	if sb.code != 0 {
		t.Fatalf("exit %d: %q", sb.code, sb.stderr())
	}
	v := validateJSONOf(t, out)
	if !v.Valid || v.Errors != 0 || v.Mode != "store" {
		t.Errorf("valid %v, errors %d, mode %q", v.Valid, v.Errors, v.Mode)
	}
	if v.Counts == nil || v.Counts.Users != 3 || v.Counts.Groups != 3 || v.Counts.Scopes != 4 {
		t.Errorf("counts %+v", v.Counts)
	}
	if !slices.Contains(v.Backends, "tacacs") {
		t.Errorf("backends %v", v.Backends)
	}
	// The scopes have no break-glass user: a warning, which does not count.
	if f := v.find("breakglass"); f == nil || f.Level != levelWarning || f.Fix != "tacctl scope breakglass <scope> add <name>" ||
		strings.Contains(f.Text, "tacctl scope breakglass") {
		t.Errorf("breakglass finding %+v", f)
	}
	if v.Warnings != len(v.Findings) {
		t.Errorf("warnings %d, findings %d", v.Warnings, len(v.Findings))
	}
	if sb.err.Len() != 0 {
		t.Errorf("standard error: %q", sb.err.String())
	}
	// The text report says the same.
	sb.run("", []string{"config", "validate"})
	sb.expect(0, "Configuration is valid.", "")
}

// An error finding makes valid false, exit 1, and the object is printed all
// the same; the count is the one the text report states.
func TestConfigValidateJSONError(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.run("", []string{"config", "validate", "--json"})
	if sb.code != 1 {
		t.Fatalf("exit %d", sb.code)
	}
	v := validateJSONOf(t, out)
	if v.Valid || v.Errors != 1 {
		t.Fatalf("valid %v, errors %d: %s", v.Valid, v.Errors, out)
	}
	f := v.find("rendered")
	if f == nil || f.Level != levelError || f.Backend != "tacacs" || f.Fix != "tacctl config render" ||
		!strings.HasSuffix(f.Text, " is missing") {
		t.Fatalf("rendered finding %+v", f)
	}
	if sb.err.Len() != 0 && strings.Contains(sb.stderr(), "Validation failed") {
		t.Errorf("the verdict is on standard error: %q", sb.stderr())
	}
	sb.run("", []string{"config", "validate"})
	sb.expect(1, "", "Validation failed with 1 error(s).")
	// Rendered, it is valid again.
	sb.run("", []string{"config", "render"})
	if v := validateJSONOf(t, sb.run("", []string{"config", "validate", "--json"})); !v.Valid || sb.code != 0 {
		t.Errorf("after the render: %+v, exit %d", v, sb.code)
	}
}

// legacySandbox is an installation that has a tacquito.yaml and no store.
func legacySandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, false)
	sb.write("etc/tacquito.yaml", fixture(t, "tacquito.minimal.yaml"), 0o640)
	return sb
}

// Without a store the report is the legacy one: the mode says so, the
// store line is a warning, and a tacquito.yaml that does not parse is an
// error of the yaml section.
func TestConfigValidateJSONLegacy(t *testing.T) {
	sb := legacySandbox(t)
	v := validateJSONOf(t, sb.run("", []string{"config", "validate", "--json"}))
	if v.Mode != "legacy" {
		t.Errorf("mode %q", v.Mode)
	}
	if f := v.find("store"); f == nil || f.Level != levelWarning || f.Fix != "tacctl store import" {
		t.Errorf("store finding %+v", f)
	}
	if v.find("yaml") != nil {
		t.Errorf("yaml finding for a file that parses: %+v", v.find("yaml"))
	}
	sb.write("etc/tacquito.yaml", "users: [\n", 0o640)
	v = validateJSONOf(t, sb.run("", []string{"config", "validate", "--json"}))
	if sb.code != 1 || v.Valid || v.Counts != nil {
		t.Errorf("exit %d, valid %v", sb.code, v.Valid)
	}
	if f := v.find("yaml"); f == nil || f.Level != levelError || !strings.HasPrefix(f.Text, "the YAML is not valid: ") {
		t.Errorf("yaml finding %+v", f)
	}
}

// unreadableModelSandbox is a store that does not parse.
func unreadableModelSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.write("state/store.yaml", "users: [\n", 0o600)
	return sb
}

// A model that cannot be read: standard output is the object alone (the
// complaint is on standard error), the counts are null, the findings name
// the store's own and the structure.
func TestConfigValidateJSONUnreadableModel(t *testing.T) {
	sb := unreadableModelSandbox(t)
	out := sb.run("", []string{"config", "validate", "--json"})
	if sb.code != 1 {
		t.Fatalf("exit %d", sb.code)
	}
	v := validateJSONOf(t, out)
	if v.Counts != nil || !strings.Contains(out, `"counts": null`) {
		t.Errorf("counts %+v", v.Counts)
	}
	if f := v.find("store"); f == nil || f.Level != levelError {
		t.Errorf("store finding %+v", f)
	}
	if f := v.find("structure"); f == nil || f.Text != "users, groups and scopes could not be read (see standard error)" {
		t.Errorf("structure finding %+v", f)
	}
	if n := strings.Count(sb.stderr(), "tacctl store: "); n != 1 {
		t.Errorf("the model's complaint is on standard error %d times: %q", n, sb.stderr())
	}
	if strings.Contains(out, "tacctl store: ") {
		t.Errorf("the complaint is on standard output:\n%s", out)
	}
	if v.Errors != len(v.Findings)-v.Warnings || v.Errors < 2 {
		t.Errorf("errors %d, warnings %d, findings %d", v.Errors, v.Warnings, len(v.Findings))
	}
}

// backendsUnreadableSandbox enables a backend there is none of.
func backendsUnreadableSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "backends:\n  enabled:\n  - tacacs\n  - nosuch\n", 0o600)
	return sb
}

// The enabled list cannot be read: an error of the backends section, and no
// backend is listed (an empty array, not null).
func TestConfigValidateJSONBackendsUnreadable(t *testing.T) {
	sb := backendsUnreadableSandbox(t)
	out := sb.run("", []string{"config", "validate", "--json"})
	v := validateJSONOf(t, out)
	if sb.code != 1 || v.Valid {
		t.Errorf("exit %d, valid %v", sb.code, v.Valid)
	}
	if f := v.find("backends"); f == nil || f.Level != levelError || !strings.Contains(f.Text, "nosuch") {
		t.Errorf("backends finding %+v", f)
	}
	if !strings.Contains(out, `"backends": []`) {
		t.Errorf("backends are not an empty array:\n%s", out)
	}
}

// An option the verb does not have is a usage error and prints no object.
func TestConfigValidateJSONUsage(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.run("", []string{"config", "validate", "--jsno"})
	if sb.code != 1 || out != "" || !strings.Contains(sb.stderr(), "Unknown option: '--jsno'") ||
		!strings.Contains(sb.stderr(), "Usage: tacctl config validate [--json]") {
		t.Errorf("exit %d, stdout %q, stderr %q", sb.code, out, sb.stderr())
	}
}

// kitchenSink is an installation with something wrong in every section the
// checks of a readable model reach: both backends, names with upper case,
// hosts registered twice, a block without its file, a hold without a device,
// settings of a group nobody has, a file the render did not write.
func kitchenSink(t *testing.T) *hostSandbox {
	t.Helper()
	hs := newHostSandbox(t)
	sandboxRADIUS(hs.sandbox)
	hs.write("state/tacctl.yaml", "backends:\n  enabled:\n  - tacacs\n  - radius\n", 0o600)
	hs.run(nil, "config", "render")
	hs.expect(0, "Rendered", "")
	hs.legacyStoreCase("  bob:", "  Bob:")
	hs.legacyStoreCase("  prod-inner:", "  Prod-Inner:")
	hs.write("state/devices.yaml", "version: 1\ndevices:\n  Core-SW1:\n    address: 10.99.0.1\n    vendor: cisco\n", 0o600)
	hs.write("state/linux-hosts", "Web1|root@192.0.2.10||lab|192.0.2.1|\nweb1|root@192.0.2.10||lab|192.0.2.1|\nweb3|root@192.0.2.12||gone|192.0.2.1|\n", 0o600)
	hs.write("state/tacctl.yaml", `backends:
  enabled:
  - tacacs
  - radius
scope:
  default: nosuchscope
tier:
  ghost: engineer
snmp_scope:
  ghost: {}
privileges:
  operator:
  - 'exec all: ping'
  readonly: []
breakglass_hold:
  sw-core-1:
    address: 10.0.1.5
    since: '2026-10-10T14:02:00+00:00'
    by: alice
    reason: console
  nohold:
    since: '2026-10-10T14:02:00+00:00'
commands:
  operator:
  - name: clear
    action: permit
  - name: ip
    action: permit
    match:
    - '^route'
  - name: ''
    action: permit
blocks:
  lab:
    juniper:
    - snmp
`, 0o600)
	hs.write("var-lib/device-config/ghost-sw.yaml", "version: 1\n", 0o600)
	// A private copy an interrupted command left, long enough ago.
	old := hs.path("state", ".apply.1234")
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	then := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, then, then); err != nil {
		t.Fatal(err)
	}
	// A file tacctl rendered, edited by hand.
	hs.write("etc/tacquito.yaml", "# edited\n", 0o640)
	return hs
}

// Every section of D220 turns up in some installation, and no finding has a
// section the list does not name; the text report counts as many errors as
// the object, but for a block of drifted artifacts, which it counts once.
func TestConfigValidateJSONEverySection(t *testing.T) {
	seen := map[string]bool{}
	for name, sb := range map[string]*sandbox{
		"kitchen sink":     kitchenSink(t).sandbox,
		"unreadable model": unreadableModelSandbox(t),
		"backends":         backendsUnreadableSandbox(t),
		"legacy":           legacySandbox(t),
	} {
		if name == "legacy" {
			sb.write("etc/tacquito.yaml", "users: [\n", 0o640)
		}
		v := validateJSONOf(t, sb.run("", []string{"config", "validate", "--json"}))
		for _, f := range v.Findings {
			if !slices.Contains(validateSections, f.Section) {
				t.Errorf("%s: a finding of section %q, which D220 does not name: %+v", name, f.Section, f)
			}
			if f.Level != levelError && f.Level != levelWarning {
				t.Errorf("%s: level %q", name, f.Level)
			}
			if f.Text == "" {
				t.Errorf("%s: a finding without text: %+v", name, f)
			}
			seen[f.Section] = true
		}
		errs, warns := 0, 0
		for _, f := range v.Findings {
			if f.Level == levelError {
				errs++
			} else {
				warns++
			}
		}
		if v.Errors != errs || v.Warnings != warns || v.Valid != (errs == 0) || (sb.code == 1) != (errs > 0) {
			t.Errorf("%s: errors %d (%d), warnings %d (%d), valid %v, exit %d", name, v.Errors, errs, v.Warnings, warns, v.Valid, sb.code)
		}
		if v.Mode == "" || v.Backends == nil {
			t.Errorf("%s: mode %q, backends %v", name, v.Mode, v.Backends)
		}
	}
	for _, sec := range validateSections {
		if !seen[sec] {
			t.Errorf("no installation has a finding of section %q", sec)
		}
	}
}

// What the findings carry: the hosts a finding names, the backend a finding
// belongs to, the fix apart from the text, and the data --fix-names reads
// from a 'names' finding.
func TestConfigValidateJSONKitchenSink(t *testing.T) {
	hs := kitchenSink(t)
	out := hs.run(nil, "config", "validate", "--json")
	v := validateJSONOf(t, out)
	if hs.code != 1 || v.Valid {
		t.Errorf("exit %d, valid %v", hs.code, v.Valid)
	}
	var dup *validateFinding
	for i, f := range v.Findings {
		if f.Section == "linux_hosts" && strings.HasPrefix(f.Text, "the hosts ") {
			dup = &v.Findings[i]
		}
	}
	if dup == nil || !slices.Equal(dup.Hosts, []string{"Web1", "web1"}) || !strings.HasPrefix(dup.Fix, "tacctl host forget <name> drops") ||
		strings.Contains(dup.Text, "tacctl host forget") {
		t.Errorf("the hosts registered twice: %+v", dup)
	}
	// Findings of the other sections name no host.
	for _, f := range v.Findings {
		if f.Hosts != nil && f.Section != "linux_hosts" && f.Section != "names" {
			t.Errorf("hosts on %+v", f)
		}
	}
	for _, f := range v.Findings {
		switch f.Section {
		case "drift":
			if f.Backend != "tacacs" || f.Level != levelError || !strings.HasSuffix(f.Text, "etc/tacquito.yaml — edited since tacctl rendered it") ||
				!strings.Contains(f.Fix, "tacctl config render --force") {
				t.Errorf("drift %+v", f)
			}
		case "rendered":
			if f.Backend == "" {
				t.Errorf("rendered without a backend: %+v", f)
			}
			if f.Backend == "radius" && f.Fix != "tacctl config render" {
				t.Errorf("rendered %+v", f)
			}
		case "vendor_attrs":
			if f.Backend != "radius" || f.Level != levelWarning || !strings.HasPrefix(f.Fix, "tacctl scope vendor-attrs <scope> enable") {
				t.Errorf("vendor_attrs %+v", f)
			}
		case "breakglass_hold":
			// An orphan does not count toward the exit status, a hold
			// without an address does.
			wantLevel := levelWarning
			if strings.Contains(f.Text, "has no address") {
				wantLevel = levelError
			}
			if f.Level != wantLevel || !strings.HasPrefix(f.Fix, "tacctl breakglass release ") || strings.Contains(f.Text, "tacctl breakglass") {
				t.Errorf("breakglass_hold %+v", f)
			}
		case "store", "yaml", "structure", "overrides", "scope_default", "backends":
			if f.Level != levelError {
				t.Errorf("%+v is not an error", f)
			}
		default:
			if f.Backend != "" {
				t.Errorf("a backend on %+v", f)
			}
		}
	}

	// The data of the names findings, as the collector hands them on.
	r := hs.validateReport()
	type rename struct{ kind, name, to, verb string }
	var got []rename
	for _, f := range r.findings() {
		if f.Section == "names" {
			got = append(got, rename{f.Kind, f.Name, f.To, f.Verb})
		}
	}
	want := []rename{
		{"device", "Core-SW1", "core-sw1", "device rename"},
		{"host", "Web1", "<new>", "host rename"},
		{"user", "Bob", "bob", "user rename"},
		{"scope", "Prod-Inner", "prod-inner", "scope rename"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("names findings carry %v, want %v", got, want)
	}
}

// validateReport is the collector's report of this sandbox, as the text and
// the JSON printers have it.
func (sb *sandbox) validateReport() *validateReport {
	sb.t.Helper()
	runner := &fake.Runner{}
	runner.On([]string{"systemctl"}, execx.Result{})
	runner.On([]string{"logger"}, execx.Result{})
	runner.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	fakePasswd(runner)
	a := app.New(nil, paths.NewEnv(sb.env), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &sb.out, Stderr: &sb.err}, runner)
	a.Paths = a.Paths.Reroot(sb.dir)
	inv := &invocation{ctx: context.Background(), app: a, hooks: sb.hooks}
	r := &validateReport{}
	inv.collectValidate(r)
	return r
}

// A restricted caller gets the view of the text report: no finding about
// hosts or names, which are other scopes' as well, and no hold defect.
func TestConfigValidateJSONEngineerView(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/linux-hosts", "Web1|root@192.0.2.10||lab|192.0.2.1|\nweb1|root@192.0.2.10||lab|192.0.2.1|\ndb1|root@192.0.2.11||prod|192.0.2.1|\n", 0o600)
	sb.legacyStoreCase("  alice:", "  Alice:")
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\nbreakglass_hold:\n  nohold:\n    since: '2026-10-10T14:02:00+00:00'\n", 0o600)

	v := validateJSONOf(t, sb.run("", []string{"config", "validate", "--json"}))
	if v.find("names") == nil || v.find("linux_hosts") == nil || v.find("breakglass_hold") == nil {
		t.Fatalf("the superuser's view lacks a finding: %v", v.sections())
	}

	v = validateJSONOf(t, sb.asEngineer("", "config", "validate", "--json"))
	for _, sec := range []string{"names", "linux_hosts", "breakglass_hold"} {
		if v.find(sec) != nil {
			t.Errorf("the engineer's view has a %q finding: %+v", sec, v.find(sec))
		}
	}
	// The same view in text.
	if out := sb.asEngineer("", "config", "validate"); strings.Contains(out, "Names:") || strings.Contains(out, "one name ignoring case") || strings.Contains(out, "Break-glass hold:") {
		t.Errorf("the engineer's text report:\n%s", out)
	}
}

// config validate is the operator's, with and without --json; the object is
// the same view the text report gives that caller.
func TestConfigValidateJSONIsTheOperators(t *testing.T) {
	sb := newSandbox(t, true)
	asBob := func(args ...string) string {
		return sb.cfgRun("", args, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-operator\n")})
		}, "SUDO_USER=bob")
	}
	v := validateJSONOf(t, asBob("config", "validate", "--json"))
	if strings.Contains(sb.stderr(), "not permitted") || v.Mode != "store" {
		t.Errorf("exit %d, mode %q, stderr %q", sb.code, v.Mode, sb.stderr())
	}
	// The next verb of the family is not.
	asBob("config", "dump")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the operator tier") {
		t.Errorf("config dump: %d %q", sb.code, sb.stderr())
	}
}

// The text report counts a block of drifted artifacts as one error, the
// object counts each artifact; counts the model could not give are null.
func TestValidateReportCounts(t *testing.T) {
	parallel(t)
	r := &validateReport{counts: map[string]string{"users": "3", "groups": "?", "scopes": "4"}}
	r.found(howRaw, "", validateFinding{Section: "drift", Level: levelError})
	r.found(howRaw, "", validateFinding{Section: "drift", Level: levelError, repeat: true})
	r.found(howEchoE, "", validateFinding{Section: "names", Level: levelWarning})
	r.line(howEchoE, "not a finding")
	if r.errors() != 2 || r.textErrors() != 1 || r.warnings() != 1 || len(r.findings()) != 3 {
		t.Errorf("errors %d, text errors %d, warnings %d, findings %d", r.errors(), r.textErrors(), r.warnings(), len(r.findings()))
	}
	if r.countsJSON() != nil {
		t.Errorf("counts with a group count the model could not give: %+v", r.countsJSON())
	}
	r.counts["groups"] = "2"
	if c := r.countsJSON(); c == nil || *c != (validateCounts{Users: 3, Groups: 2, Scopes: 4}) {
		t.Errorf("counts %+v", c)
	}
}
