package model_test

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// Ports of the legacy halves of tests/unit/model.bats and
// tests/unit/yaml.bats ("legacy mode"), and of the 'store show' tests of
// tests/integration/store_cli.bats.

// legacy is model_load in an importEnv: the loaded store and model.
func (e *importEnv) load() (*store.Store, *model.Model, string) {
	e.t.Helper()
	s, m, mode, err := model.Load(e.paths())
	if err != nil {
		e.t.Fatalf("model_load: %v", err)
	}
	return s, m, mode
}

func (e *importEnv) get(kind string, args ...string) string {
	e.t.Helper()
	s, _, _ := e.load()
	lines, code, err := model.Get(s, kind, args...)
	if err != nil || code != 0 {
		e.t.Fatalf("model_%s %v: %d %v", kind, args, code, err)
	}
	return strings.Join(lines, "\n")
}

func (e *importEnv) view(name string, args ...string) (string, int) {
	e.t.Helper()
	_, m, _ := e.load()
	lines, code, err := m.View(name, args...)
	if err != nil {
		e.t.Fatalf("view %s: %v", name, err)
	}
	return strings.Join(lines, "\n"), code
}

func (e *importEnv) useStore(name string) {
	e.t.Helper()
	if err := os.WriteFile(e.store, readFile(e.t, fixtures+name), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func TestLoadNeitherStoreNorConfig(t *testing.T) {
	// model.bats "model_dump: fails cleanly when neither store nor config
	// exists"
	e := newImportEnv(t)
	_, _, _, err := model.Load(e.paths())
	var ns *model.NoSourceError
	if !errors.As(err, &ns) {
		t.Fatalf("want *NoSourceError, got %v", err)
	}
	if got := err.Error(); got != "No store at "+e.store+" and no config at "+e.config+"." {
		t.Errorf("%q", got)
	}
}

func TestLoadStoreWinsOverConfig(t *testing.T) {
	// model.bats "store loader: the store wins over tacquito.yaml once it
	// exists"
	e := newImportEnv(t)
	e.place(fixtures + "tacquito.multiscope.yaml")
	e.useStore("store.minimal.yaml")
	if _, _, mode := e.load(); mode != "store" {
		t.Errorf("mode %s", mode)
	}
	if got := e.get("users"); got != "" {
		t.Errorf("users: %q", got)
	}
	if got := e.get("scopes"); got != "lab" {
		t.Errorf("scopes: %q", got)
	}
}

func TestLegacyLoaderReadsConfig(t *testing.T) {
	// model.bats "legacy loader: reads tacquito.yaml when no store exists"
	e := newImportEnv(t)
	e.place(ms)
	s, _, mode := e.load()
	if mode != "legacy" {
		t.Errorf("mode %s", mode)
	}
	got, err := model.ShowJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(readFile(t, fixtures+"model/multiscope.json")); got != want {
		t.Errorf("model differs from model/multiscope.json:\n%s", got)
	}
}

func TestLegacyLoaderMultiscopeReaders(t *testing.T) {
	// model.bats "legacy loader: reads the multiscope fixture as the
	// pre-store readers did"
	e := newImportEnv(t)
	e.place(ms)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"scopes"}, "dmz\nlab\nprod\nprod-inner"},
		{[]string{"scopes", "prod", "secret"}, "prod-secret-0123456789abcdef"},
		{[]string{"scopes", "prod-inner", "secret"}, "inner-secret-0123456789abcdef"},
		{[]string{"scopes", "lab", "secret"}, "lab-secret-0123456789abcdef"},
		{[]string{"scopes", "dmz", "secret"}, "dmz-secret-0123456789abcdef"},
		{[]string{"scopes", "prod", "prefixes"}, "10.0.0.0/8"},
		{[]string{"scopes", "prod-inner", "prefixes"}, "10.10.99.0/24"},
		{[]string{"scopes", "lab", "prefixes"}, "172.16.0.0/12\n192.168.0.0/16"},
		{[]string{"scopes", "dmz", "prefixes"}, "203.0.113.0/24"},
		// A user's scopes keep the order they were granted in.
		{[]string{"users", "alice", "scopes"}, "prod\nlab"},
		{[]string{"users", "bob", "scopes"}, "lab"},
		{[]string{"users", "carol", "scopes"}, "lab\ndmz"},
		{[]string{"groups"}, "operator\nreadonly\nsuperuser"},
		{[]string{"groups", "readonly", "priv_lvl"}, "1"},
		{[]string{"groups", "operator", "priv_lvl"}, "7"},
		{[]string{"groups", "superuser", "priv_lvl"}, "15"},
	} {
		if got := e.get(c.args[0], c.args[1:]...); got != c.want {
			t.Errorf("%v: %q, want %q", c.args, got, c.want)
		}
	}
}

func TestLegacyLoaderOldLayout(t *testing.T) {
	// model.bats "legacy loader: reads users added by cmd_add's old layout
	// as the pre-store readers did"
	e := newImportEnv(t)
	e.place(fixtures + "legacy.import-edge.yaml")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"users", "alice", "group"}, "superuser"},
		{[]string{"users", "alice", "hash"}, "24326224313224" + strings.Repeat("41", 53)},
		{[]string{"users", "dave", "group"}, "helpdesk"},
		{[]string{"filters", "allow"}, "10.0.0.0/8\n192.168.0.0/16"},
		{[]string{"filters", "deny"}, "10.66.0.0/16"},
		{[]string{"groups", "helpdesk", "priv_lvl"}, "5"},
	} {
		if got := e.get(c.args[0], c.args[1:]...); got != c.want {
			t.Errorf("%v: %q, want %q", c.args, got, c.want)
		}
	}
}

func TestLegacyLoaderErrors(t *testing.T) {
	// The legacy loader's errors are store errors (printed 'tacctl store:
	// ...'), never quoting the file.
	e := newImportEnv(t)
	if err := os.WriteFile(e.config, []byte("secrets: [{key: \"leaky-secret-0123456789\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := model.Load(e.paths())
	if msg := store.Report(err); !strings.HasPrefix(msg, "tacctl store: "+e.config+": ") || strings.Contains(msg, "leaky") {
		t.Errorf("%s", msg)
	}
	if err := os.WriteFile(e.config, []byte("- a list\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = model.Load(e.paths())
	if msg := store.Report(err); msg != "tacctl store: "+e.config+": top level is not a YAML mapping" {
		t.Errorf("%s", msg)
	}
}

// --- yaml.bats: the same readers with no store (legacy read-only mode) -------

func legacyMode(t *testing.T) *importEnv {
	t.Helper()
	e := newImportEnv(t)
	e.place(ms)
	if model.Mode(e.store) != "legacy" {
		t.Fatal("not legacy")
	}
	return e
}

func TestLegacyModeScopeReaders(t *testing.T) {
	// yaml.bats "legacy mode: scope readers answer from tacquito.yaml"
	e := legacyMode(t)
	if got := e.get("scopes"); len(strings.Split(got, "\n")) != 4 {
		t.Errorf("scopes: %q", got)
	}
	if _, code := e.view("has", "scopes", "prod-inner"); code != 0 {
		t.Error("prod-inner does not exist")
	}
	if _, code := e.view("has", "scopes", "nonexistent"); code != 1 {
		t.Error("nonexistent exists")
	}
	if got := e.get("scopes", "prod", "secret"); got != "prod-secret-0123456789abcdef" {
		t.Errorf("secret %q", got)
	}
	for _, c := range []struct {
		view, arg, want string
	}{
		{"scope-prefixes", "lab", "192.168.0.0/16\n172.16.0.0/12"},
		{"prefix-owner", "10.10.99.5/24", "prod-inner"},
		{"scope-users", "lab", "alice\nbob\ncarol"},
	} {
		if got, _ := e.view(c.view, c.arg); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.view, c.arg, got, c.want)
		}
	}
}

func TestLegacyModeUserAndGroupReaders(t *testing.T) {
	// yaml.bats "legacy mode: user and group readers answer from
	// tacquito.yaml"
	e := legacyMode(t)
	if got := e.get("users", "alice", "scopes"); got != "prod\nlab" {
		t.Errorf("%q", got)
	}
	if got := e.get("users", "carol", "group"); got != "readonly" {
		t.Errorf("%q", got)
	}
	if got := e.get("groups", "operator", "priv_lvl"); got != "7" {
		t.Errorf("%q", got)
	}
	if got, _ := e.view("user-privlvl", "alice"); got != "15" {
		t.Errorf("%q", got)
	}
	if got, _ := e.view("user-rows"); got != "alice|superuser|active|unknown|prod,lab\n"+
		"bob|operator|active|unknown|lab\ncarol|readonly|active|unknown|lab,dmz" {
		t.Errorf("%q", got)
	}
}

func TestLegacyModeMissingScope(t *testing.T) {
	// yaml.bats "legacy mode: a user pointing at a missing scope is
	// reported, not hidden"
	e := legacyMode(t)
	if err := os.WriteFile(e.config, bytes.ReplaceAll(readFile(t, e.config), []byte("\n      - dmz\n"), []byte("\n      - nosuchscope\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := e.view("user-info", "carol")
	if code != 0 {
		t.Fatal(code)
	}
	hasLine(t, out, "scope=lab|1")
	hasLine(t, out, "scope=nosuchscope|0")
	out, _ = e.view("status", "16")
	hasLine(t, out, "orphan=carol:nosuchscope")
	out, _ = e.view("validate", "full")
	hasLine(t, out, "ERROR:User 'carol' references nonexistent scope 'nosuchscope'")
}

// --- store_cli.bats: 'tacctl store show' -----------------------------------------

func show(t *testing.T, e *importEnv, asJSON bool) (stdout, stderr string, err error) {
	t.Helper()
	var o, w bytes.Buffer
	err = model.Show(ui.Output{Stdout: &o, Stderr: &w}, e.paths(), asJSON)
	return o.String(), w.String(), err
}

func TestShowLegacyMode(t *testing.T) {
	// store_cli.bats "store show: legacy mode prints the model derived from
	// tacquito.yaml as YAML", and "store mode prints the same model, with
	// no legacy warning"
	e := newImportEnv(t)
	e.place(ms)
	out, errOut, err := show(t, e, false)
	if err != nil {
		t.Fatal(err)
	}
	if errOut != ui.Yellow+"[WARN]"+ui.NC+" No store yet — showing the model derived from "+e.config+" (legacy read-only mode).\n" {
		t.Errorf("stderr: %q", errOut)
	}
	if want := string(readFile(t, "testdata/store.multiscope.show.yaml")); out != want {
		t.Errorf("stdout:\n%s", out)
	}
	if _, err := os.Stat(e.store); err == nil {
		t.Error("show wrote a store")
	}
	legacyView := out
	if err := store.Import(ui.Output{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, store.ImportOptions{
		StorePath: e.store, ConfigPath: e.config, DatesDir: e.dates, DisabledDir: e.disabled, LegacyDir: e.legacyDir,
	}); err != nil {
		t.Fatal(err)
	}
	out, errOut, err = show(t, e, false)
	if err != nil || errOut != "" || out != legacyView {
		t.Errorf("store mode: %v %q\n%s", err, errOut, out)
	}
}

func TestShowJSON(t *testing.T) {
	// store_cli.bats "store show --json: prints the model as JSON"
	e := newImportEnv(t)
	e.useStore("store.multiscope.yaml")
	out, errOut, err := show(t, e, true)
	if err != nil || errOut != "" {
		t.Fatal(err, errOut)
	}
	if want := string(readFile(t, fixtures+"model/multiscope.json")); out != want {
		t.Errorf("%s", out)
	}
	// Legacy mode prints the same JSON, after the warning.
	e = newImportEnv(t)
	e.place(ms)
	out, errOut, err = show(t, e, true)
	if err != nil || !strings.Contains(errOut, "legacy read-only mode") || out != string(readFile(t, fixtures+"model/multiscope.json")) {
		t.Errorf("legacy: %v %q\n%s", err, errOut, out)
	}
}

func TestShowNoSource(t *testing.T) {
	// store_cli.bats "store show: fails when there is neither a store nor
	// a config"
	e := newImportEnv(t)
	out, errOut, err := show(t, e, false)
	var ns *model.NoSourceError
	if !errors.As(err, &ns) || out != "" || errOut != "" {
		t.Fatalf("%v %q %q", err, out, errOut)
	}
	if !strings.HasPrefix(err.Error(), "No store at") {
		t.Error(err)
	}
}

func TestLegacyLoadWrapper(t *testing.T) {
	s, m, err := model.LegacyLoad(ms, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if m.User("alice") == nil || m.Scope("prod-inner") == nil {
		t.Error("model lacks entries")
	}
	if js, _ := model.ShowJSON(s); js != string(readFile(t, fixtures+"model/multiscope.json")) {
		t.Error("store differs")
	}
	if _, _, err := model.LegacyLoad("/nonexistent.yaml", "", ""); err == nil {
		t.Error("loaded a missing file")
	}
}
