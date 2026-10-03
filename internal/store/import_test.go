package store_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// Ports of tests/unit/store_import.bats (the importer half; the
// equivalence half is internal/model's legacy_equiv_test.go) and of the
// import tests of tests/integration/store_cli.bats.

// hashD is store_import.bats HASH_D.
var hashD = "24326224313224" + strings.Repeat("44", 53)

// ienv is tmpenv as the importer sees it: the state dir (env.path is its
// store.yaml), the live tacquito.yaml and the backup directories.
type ienv struct {
	*env
	config, dates, disabled, legacyDir string
	snapshots                          int
}

func newImportEnv(t *testing.T) *ienv {
	t.Helper()
	e := &ienv{env: newEnv(t)}
	root := filepath.Dir(e.dir)
	e.config = filepath.Join(root, "etc", "tacquito.yaml")
	e.dates = filepath.Join(e.dir, "backups", "password-dates")
	e.disabled = filepath.Join(e.dir, "backups", "disabled")
	e.legacyDir = filepath.Join(e.dir, "backups", "legacy")
	for _, d := range []string{filepath.Dir(e.config), e.dates} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// place is place_fixture: copy a fixture to the live tacquito.yaml.
func (e *ienv) place(name string) {
	e.t.Helper()
	e.write(e.config, string(readFile(e.t, fixtures+name)))
}

func (e *ienv) write(path, text string) {
	e.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// edit rewrites the live tacquito.yaml.
func (e *ienv) edit(fn func(string) string) {
	e.t.Helper()
	e.write(e.config, fn(string(readFile(e.t, e.config))))
}

// edgeSidecars is edge_sidecars: the sidecars of legacy.import-edge.yaml.
func (e *ienv) edgeSidecars() {
	e.t.Helper()
	e.write(filepath.Join(e.dates, "alice.date"), "2026-08-15\n")
	e.write(filepath.Join(e.dates, "dave.date"), "2026-01-02\n")
	e.write(filepath.Join(e.dates, "erin.date"), "not a date\n")
	e.write(filepath.Join(e.disabled, "dave.hash"), hashD+"\n")
}

// appendSecret is append_secret: one more secrets[] entry at the end of
// the live tacquito.yaml.
func (e *ienv) appendSecret(name, key, prefix string) {
	e.edit(func(s string) string {
		return s + "  - name: " + name + "\n    secret:\n      group: tacquito\n      key: " + key +
			"\n    handler:\n      type: *handler_type_start\n    type: *provider_type_prefix\n" +
			"    options:\n      prefixes: |\n        [\n          \"" + prefix + "\"\n        ]\n"
	})
}

func (e *ienv) opts(args ...string) store.ImportOptions {
	o := store.ImportOptions{
		StorePath: e.path, ConfigPath: e.config, DatesDir: e.dates,
		DisabledDir: e.disabled, LegacyDir: e.legacyDir,
		Snapshot: func() error { e.snapshots++; return nil },
		Now:      func() time.Time { return e.now },
	}
	for _, a := range args {
		switch a {
		case "--check":
			o.Check = true
		case "--force":
			o.Force = true
		case "--replace":
			o.Replace = true
		default:
			o.Src = a
		}
	}
	return o
}

// run is 'store_import <args>' (run: stdout and stderr in one stream);
// it returns the output and the exit status.
func (e *ienv) run(o store.ImportOptions) (string, int) {
	e.t.Helper()
	var out bytes.Buffer
	err := store.Import(ui.Output{Stdout: &out, Stderr: &out}, o)
	var st *store.ImportStatus
	switch {
	case err == nil:
		return out.String(), 0
	case errors.As(err, &st):
		return out.String(), st.Code
	}
	e.t.Fatalf("Import: unexpected error %v", err)
	return "", 0
}

func (e *ienv) imp(args ...string) (string, int) {
	e.t.Helper()
	return e.run(e.opts(args...))
}

func (e *ienv) mustImport(args ...string) string {
	e.t.Helper()
	out, rc := e.imp(args...)
	if rc != 0 {
		e.t.Fatalf("store import %v: status %d:\n%s", args, rc, out)
	}
	return out
}

func (e *ienv) storeExists() bool {
	_, err := os.Stat(e.path)
	return err == nil
}

// modeOf is model_mode.
func (e *ienv) modeOf() string { return model.Mode(e.path) }

// modelJSON is the model as 'json.tool --sort-keys' prints model_dump:
// store or legacy, whichever model_load reads.
func (e *ienv) modelJSON() string {
	e.t.Helper()
	s, _, _, err := model.Load(model.Paths{Store: e.path, Config: e.config, DatesDir: e.dates, DisabledDir: e.disabled})
	if err != nil {
		e.t.Fatal(err)
	}
	out, err := model.ShowJSON(s)
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func status(t *testing.T, rc, want int, out string) {
	t.Helper()
	if rc != want {
		t.Fatalf("status %d, want %d:\n%s", rc, want, out)
	}
}

// --- every existing tacquito fixture ------------------------------------------

func tacquitoFixtures(t *testing.T) []string {
	t.Helper()
	m, err := filepath.Glob(fixtures + "tacquito.*.yaml")
	if err != nil || len(m) == 0 {
		t.Fatal("no tacquito fixtures")
	}
	return m
}

func TestImportEveryFixtureMatchesItsGoldenModel(t *testing.T) {
	// "import: every tacquito.* fixture imports strictly, validates, and
	// matches its golden model"
	for _, f := range tacquitoFixtures(t) {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "tacquito."), ".yaml")
		e := newImportEnv(t)
		e.write(e.config, string(readFile(t, f)))
		out := e.mustImport()
		refute(t, out, "Cannot be represented")
		if msg, ok := validateFile(e.path); !ok {
			t.Errorf("%s: %s", name, msg)
		}
		if m := mode(t, e.path); m != 0o600 {
			t.Errorf("%s: mode %o", name, m)
		}
		equal(t, e.modelJSON(), string(readFile(t, fixtures+"model/"+name+".json")))
	}
}

func TestImportLegacyAndStoreLoaderAgree(t *testing.T) {
	// "import: legacy loader and store loader give the same model for
	// every fixture"
	for _, f := range tacquitoFixtures(t) {
		e := newImportEnv(t)
		e.write(e.config, string(readFile(t, f)))
		equal(t, e.modeOf(), "legacy")
		legacy := e.modelJSON()
		e.mustImport()
		equal(t, e.modeOf(), "store")
		equal(t, e.modelJSON(), legacy)
	}
}

func TestImportProducesTheStoreFixtures(t *testing.T) {
	// "import: tacquito.minimal / tacquito.multiscope produce the shipped
	// store fixtures" (the acceptance check of WP1.4b; legacy-exec gives
	// store.minimal too, see TestImportLegacyExecName)
	for _, name := range []string{"minimal", "multiscope"} {
		e := newImportEnv(t)
		e.place("tacquito." + name + ".yaml")
		e.mustImport()
		equal(t, string(readFile(t, e.path)), string(readFile(t, fixtures+"store."+name+".yaml")))
	}
}

func TestImportTwiceIsANoOp(t *testing.T) {
	// "import: re-importing the same file is a no-op"
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	e.mustImport()
	before := inode(t, e.path)
	e.mustImport("--replace")
	if inode(t, e.path) != before {
		t.Error("the store was rewritten")
	}
}

func TestImportLegacyExecName(t *testing.T) {
	// "import: legacy 'name: exec' service yields the same groups as 'name:
	// shell', with a note"
	e := newImportEnv(t)
	e.place("tacquito.legacy-exec.yaml")
	out := e.mustImport()
	contains(t, out, "group 'readonly': legacy service name 'exec'")
	equal(t, e.mustGet("groups", "superuser", "priv_lvl"), "15")
	equal(t, e.mustGet("groups", "readonly", "priv_lvl"), "1")
	equal(t, string(readFile(t, e.path)), string(readFile(t, fixtures+"store.minimal.yaml")))
}

// --- edge fixture: disabled users, sink, sidecars, multi-prefix ---------------

func TestImportEdgeFixture(t *testing.T) {
	// "import: edge fixture imports strictly and matches its golden model"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.edgeSidecars()
	out := e.mustImport()
	refute(t, out, "Cannot be represented")
	contains(t, out, "Users:    6 (3 disabled, 1 accounting sink)")
	if msg, ok := validateFile(e.path); !ok {
		t.Error(msg)
	}
	equal(t, e.modelJSON(), string(readFile(t, fixtures+"model/import-edge.json")))
}

func TestImportDisabledRestoresSidecarHash(t *testing.T) {
	// "import: disabled by marker restores the real hash from the sidecar"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.edgeSidecars()
	e.mustImport()
	equal(t, e.mustGet("users", "dave", "disabled"), "true")
	equal(t, e.mustGet("users", "dave", "hash"), hashD)
}

func TestImportDisabledWithoutSidecar(t *testing.T) {
	// "import: marker without a sidecar, and the DISABLED literal, give
	// hash null + disabled"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.mustImport()
	for _, u := range []string{"dave", "erin", "engineer"} {
		equal(t, e.mustGet("users", u, "disabled"), "true")
		equal(t, e.mustGet("users", u, "hash"), "")
	}
	refute(t, string(readFile(t, e.path)), hash.DisabledMarkerHex)
}

func TestImportBadSidecarBlocksStrictImport(t *testing.T) {
	// "import: a sidecar that is not a bcrypt hash blocks a strict import"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.write(filepath.Join(e.disabled, "dave.hash"), "garbage-sidecar-content\n")
	out, rc := e.imp()
	status(t, rc, 1, out)
	contains(t, out, "user 'dave': saved hash of the disabled account is not a bcrypt hash")
	refute(t, out, "garbage-sidecar-content")
	if e.storeExists() {
		t.Error("a store was written")
	}
}

func TestImportRootIsTheSink(t *testing.T) {
	// "import: root is the accounting sink (no hash, disabled, flagged)"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.mustImport()
	equal(t, e.mustGet("users", "root"),
		`{"accounting_sink": true, "disabled": true, "group": "readonly", "hash": null, "name": "root", "password_changed": null, "scopes": ["lab"]}`)
}

func TestImportRealHashOnRoot(t *testing.T) {
	// "import: a real hash on root is unrepresentable; --force stores the
	// sink without it"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.edit(func(s string) string {
		head, tail, _ := strings.Cut(s, "bcrypt_root: &bcrypt_root")
		return head + "bcrypt_root: &bcrypt_root" + strings.Replace(tail, hash.DisabledMarkerHex, hashD, 1)
	})
	out, rc := e.imp()
	status(t, rc, 1, out)
	contains(t, out, "user 'root': carries a real password hash")
	refute(t, out, hashD)
	if e.storeExists() {
		t.Fatal("a store was written")
	}
	e.mustImport("--force")
	equal(t, e.mustGet("users", "root", "hash"), "")
	equal(t, e.mustGet("users", "root", "disabled"), "true")
}

func TestImportPasswordDates(t *testing.T) {
	// "import: password dates come from the sidecar files; bad content is
	// noted and ignored"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.edgeSidecars()
	out := e.mustImport()
	contains(t, out, "user 'erin': password-date file does not hold a YYYY-MM-DD date")
	equal(t, e.mustGet("users", "alice", "password_changed"), "2026-08-15")
	equal(t, e.mustGet("users", "dave", "password_changed"), "2026-01-02")
	equal(t, e.mustGet("users", "erin", "password_changed"), "")
	equal(t, e.mustGet("users", "frank", "password_changed"), "")
}

func TestImportUnquotedDigitHash(t *testing.T) {
	// "import: an unquoted all-digit hash (YAML integer) is read exactly"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.mustImport()
	equal(t, e.mustGet("users", "alice", "hash"), hashA)
	equal(t, e.mustGet("users", "alice", "disabled"), "false")
}

func TestImportScopeOrderAndMissingScopes(t *testing.T) {
	// "import: user scope order is kept; a user with no scopes key gets []
	// and a note"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	out := e.mustImport()
	contains(t, out, "user 'frank': has no scopes")
	equal(t, e.mustGet("users", "alice", "scopes"), "prod\nlab")
	equal(t, e.mustGet("users", "frank", "scopes"), "")
}

func TestImportPrefixesUnioned(t *testing.T) {
	// "import: multi-prefix and repeated entries are unioned, canonicalised
	// and sorted"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.mustImport()
	equal(t, e.mustGet("scopes"), "lab\nprod\nv6")
	equal(t, e.mustGet("scopes", "lab", "prefixes"), "10.1.0.0/16\n172.16.0.0/12")
	equal(t, e.mustGet("scopes", "prod", "prefixes"), "10.0.0.0/8\n192.168.5.0/24")
	equal(t, e.mustGet("scopes", "v6", "prefixes"), "2001:db8::/32")
	equal(t, e.mustGet("scopes", "lab", "secret"), "edge-lab-secret-0123456789")
}

func TestImportGroupsAndOrphanAnchors(t *testing.T) {
	// "import: groups come from users and from unreferenced top-level
	// groups; orphan anchors are noted"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	out := e.mustImport()
	contains(t, out, "top-level 'bcrypt_user': authenticator anchor no user uses")
	contains(t, out, "top-level 'exec_retired': service anchor no group uses")
	equal(t, e.mustGet("groups"), "auditors\nhelpdesk\noperator\nreadonly\nsuperuser")
	equal(t, e.mustGet("groups", "auditors"), `{"builtin": false, "juniper_class": "AUDIT-CLASS", "name": "auditors", "priv_lvl": 3}`)
	equal(t, e.mustGet("groups", "helpdesk", "priv_lvl"), "5")
	equal(t, e.mustGet("groups", "superuser", "builtin"), "true")
}

func TestImportFilters(t *testing.T) {
	// "import: prefix_allow / prefix_deny become filters"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.mustImport()
	equal(t, e.mustGet("filters"), `{"allow": ["10.0.0.0/8", "192.168.0.0/16"], "deny": ["10.66.0.0/16"]}`)
}

// --- unrepresentable content ----------------------------------------------------

func TestImportUnrepresentableFails(t *testing.T) {
	// "import: unrepresentable content fails, lists every item, writes
	// nothing"
	e := newImportEnv(t)
	e.place("legacy.unrepresentable.yaml")
	out, rc := e.imp()
	status(t, rc, 1, out)
	for _, s := range []string{
		"Cannot be represented in the store",
		"group 'netops': service 'ppp'",
		"group 'netops': service 'shell': extra set_value 'idletime'",
		"user 'mallory': user-level commands override",
		"user 'sha': non-bcrypt authenticator",
		"user 'twogroups': 2 groups",
		"user 'syslogger': accounter other than the file accounter",
		"scope 'dnszone' (secrets[1]): non-prefix secret provider",
		"unknown top-level key 'custom_setting'",
		"8 item(s) cannot be represented",
		"Nothing was written",
	} {
		contains(t, out, s)
	}
	if e.storeExists() {
		t.Error("a store was written")
	}
	equal(t, e.modeOf(), "legacy")
	// No secret or hash in the report.
	for _, s := range []string{"unrep-lab-secret", "unrep-dns-secret", "0123456789abcdef"} {
		refute(t, out, s)
	}
}

func TestImportForceDropsUnrepresentable(t *testing.T) {
	// "import: --force drops the unrepresentable items, reports them, and
	// writes a valid store"
	e := newImportEnv(t)
	e.place("legacy.unrepresentable.yaml")
	out := e.mustImport("--force")
	contains(t, out, "Dropped (--force)")
	contains(t, out, "group 'netops': service 'ppp'")
	contains(t, out, "unknown top-level key 'custom_setting'")
	if msg, ok := validateFile(e.path); !ok {
		t.Error(msg)
	}
	equal(t, e.mustGet("groups", "netops"), `{"builtin": false, "juniper_class": "NETOPS-CLASS", "name": "netops", "priv_lvl": 15}`)
	equal(t, e.mustGet("users", "mallory", "group"), "netops")
	equal(t, e.mustGet("users", "sha"),
		`{"accounting_sink": false, "disabled": true, "group": "readonly", "hash": null, "name": "sha", "password_changed": null, "scopes": ["lab"]}`)
	equal(t, e.mustGet("users", "twogroups", "group"), "readonly")
	equal(t, e.mustGet("scopes"), "lab")
}

func TestImportLegacyModeServesUnrepresentable(t *testing.T) {
	// "import: legacy read-only mode still serves a file with
	// unrepresentable content"
	e := newImportEnv(t)
	e.place("legacy.unrepresentable.yaml")
	equal(t, e.modeOf(), "legacy")
	s, _, _, err := model.Load(model.Paths{Store: e.path, Config: e.config})
	if err != nil {
		t.Fatal(err)
	}
	lines, _, err := model.Get(s, "users")
	if err != nil {
		t.Fatal(err)
	}
	equal(t, strings.Join(lines, "\n"), "mallory\nsha\nsyslogger\ntwogroups")
}

func TestImportUserWithoutGroup(t *testing.T) {
	// "import: a user with no group cannot be stored; --force drops the
	// user"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.edit(func(s string) string {
		return strings.Replace(s, "  - name: frank\n    groups: [*readonly]", "  - name: frank\n    groups: []", 1)
	})
	out, rc := e.imp()
	status(t, rc, 1, out)
	contains(t, out, "user 'frank': no group")
	e.mustImport("--force")
	if _, code := e.get("users", "frank"); code == 0 {
		t.Error("frank was imported")
	}
}

// --- errors --force cannot override ---------------------------------------------

func TestImportScopeWithTwoKeys(t *testing.T) {
	// "import: same scope with different keys is refused even with --force,
	// keys not printed"
	e := newImportEnv(t)
	e.place("tacquito.minimal.yaml")
	e.appendSecret("lab", `"a-different-key-0123456789"`, "10.20.0.0/16")
	out, rc := e.imp()
	status(t, rc, 1, out)
	contains(t, out, "scope 'lab' has 2 entries but 2 distinct secret.key values")
	refute(t, out, "a-different-key")
	refute(t, out, "lab-secret-placeholder")
	out, rc = e.imp("--force")
	status(t, rc, 1, out)
	contains(t, out, "--force does not override these")
	if e.storeExists() {
		t.Error("a store was written")
	}
}

func TestImportNumericSecretKey(t *testing.T) {
	// "import: a secret key that YAML reads as a number is refused, not
	// guessed"
	e := newImportEnv(t)
	e.place("tacquito.minimal.yaml")
	e.appendSecret("branch", "1234567890123456", "10.20.0.0/16")
	out, rc := e.imp("--force")
	status(t, rc, 1, out)
	contains(t, out, "scope 'branch' (secrets[1]): secret.key is missing or not a YAML string")
	if e.storeExists() {
		t.Error("a store was written")
	}
}

func TestImportPrefixInTwoScopes(t *testing.T) {
	// "import: one prefix in two scopes is refused"
	e := newImportEnv(t)
	e.place("tacquito.minimal.yaml")
	e.appendSecret("other", `"other-secret-0123456789"`, "192.168.0.0/16")
	out, rc := e.imp("--force")
	status(t, rc, 1, out)
	contains(t, out, "prefix 192.168.0.0/16 is claimed by scopes 'lab' and 'other'")
	if e.storeExists() {
		t.Error("a store was written")
	}
}

func TestImportMissingScope(t *testing.T) {
	// "import: a user referencing a scope that does not exist is refused"
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	e.edit(func(s string) string { return strings.ReplaceAll(s, "\n      - dmz\n", "\n      - mars\n") })
	out, rc := e.imp("--force")
	status(t, rc, 1, out)
	contains(t, out, "user 'carol': scope 'mars' does not exist")
	if e.storeExists() {
		t.Error("a store was written")
	}
}

func TestImportMissingBuiltinGroup(t *testing.T) {
	// "import: a missing built-in group is refused"
	e := newImportEnv(t)
	e.place("tacquito.minimal.yaml")
	e.edit(func(s string) string {
		return regexp.MustCompile(`(?ms)^operator: &operator$.*?^  accounter:[^\n]*\n`).ReplaceAllString(s, "")
	})
	out, rc := e.imp("--force")
	status(t, rc, 1, out)
	contains(t, out, "built-in group 'operator' is missing")
}

func TestImportMalformedYAML(t *testing.T) {
	// "import: malformed YAML fails with a position and no file content"
	e := newImportEnv(t)
	e.write(e.config, "secrets:\n  - name: lab\n    secret: {key: \"leaky-secret-0123456789\"\n")
	out, rc := e.imp()
	status(t, rc, 1, out)
	contains(t, out, "tacquito.yaml")
	contains(t, out, "(line ")
	refute(t, out, "leaky-secret")
	if e.storeExists() {
		t.Error("a store was written")
	}
}

// --- flags, files, overwrite ----------------------------------------------------

func TestImportExplicitFile(t *testing.T) {
	// "import: explicit file argument is imported instead of $CONFIG"
	e := newImportEnv(t)
	e.place("tacquito.minimal.yaml")
	e.mustImport(fixtures + "tacquito.multiscope.yaml")
	equal(t, e.mustGet("users"), "alice\nbob\ncarol")
}

func TestImportMissingSource(t *testing.T) {
	// "import: missing source file and bad flags" (the missing file; the
	// flag errors, status 2, are the CLI's argument parsing: WP2.x)
	e := newImportEnv(t)
	absent := filepath.Join(e.dir, "absent.yaml")
	out, rc := e.imp(absent)
	status(t, rc, 1, out)
	equal(t, out, ui.Red+"[ERROR]"+ui.NC+" Cannot import: "+absent+" not found.\n")
	// No file named and no tacquito.yaml: the default source is missing.
	out, rc = e.imp()
	status(t, rc, 1, out)
	contains(t, out, "Cannot import: "+e.config+" not found.")
}

func TestImportRefusesToOverwrite(t *testing.T) {
	// "import: refuses to overwrite an existing store without --replace"
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	e.mustImport()
	before := string(readFile(t, e.path))
	e.place("tacquito.minimal.yaml")
	out, rc := e.imp()
	status(t, rc, 1, out)
	equal(t, out, ui.Red+"[ERROR]"+ui.NC+" A store already exists at "+e.path+"; importing would overwrite it.\n"+
		ui.Red+"[ERROR]"+ui.NC+" Use 'tacctl store import --check' to compare, or add --replace to overwrite.\n")
	equal(t, string(readFile(t, e.path)), before)
	e.mustImport("--replace")
	equal(t, e.mustGet("users"), "")
}

func TestImportReplaceCarriesOver(t *testing.T) {
	// "import: --replace keeps what tacquito.yaml cannot carry"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.edgeSidecars()
	e.mustImport()
	e.mustMutate(scopeSet("lab", "protocols=tacacs"))
	// After the flip the sidecars are gone; the store is the only holder
	// of dave's real hash and of the password dates.
	if err := os.RemoveAll(e.dates); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(e.disabled); err != nil {
		t.Fatal(err)
	}
	out := e.mustImport("--replace")
	contains(t, out, "kept the protocols filter of 1 scope(s)")
	contains(t, out, "kept the password date of 2 user(s)")
	contains(t, out, "kept the saved password of 1 disabled user(s)")
	equal(t, e.mustGet("scopes", "lab", "protocols"), "tacacs")
	equal(t, e.mustGet("users", "dave", "hash"), hashD)
	equal(t, e.mustGet("users", "alice", "password_changed"), "2026-08-15")
}

func TestImportReplaceSnapshotsFirst(t *testing.T) {
	// "import: --replace snapshots first when backup_snapshot exists"
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	e.mustImport()
	if e.snapshots != 0 {
		t.Fatal("the first import snapshotted")
	}
	e.place("tacquito.minimal.yaml")
	e.mustImport("--replace")
	if e.snapshots != 1 {
		t.Errorf("snapshots: %d", e.snapshots)
	}
	// A snapshot that fails stops the import; nothing is written.
	before := string(readFile(t, e.path))
	e.place("tacquito.multiscope.yaml")
	o := e.opts("--replace")
	o.Snapshot = func() error { return errors.New("Snapshot failed: disk full.") }
	out, rc := e.run(o)
	status(t, rc, 1, out)
	contains(t, out, "[ERROR]"+ui.NC+" Snapshot failed: disk full.\n")
	equal(t, string(readFile(t, e.path)), before)
}

func TestImportLeavesNoTempFiles(t *testing.T) {
	// "import: the model temp file is cleaned up": the Go import holds the
	// model in memory; --check renders into a temp dir it removes, whether
	// the check passes or not.
	e := newImportEnv(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	e.place("tacquito.multiscope.yaml")
	e.mustImport()
	for _, render := range []string{e.config, fixtures + "tacquito.minimal.yaml"} {
		o := e.opts("--check")
		o.TempDir = ""
		o.Render = func(*store.Store) ([]byte, error) { return readFile(t, render), nil }
		o.Equiv = model.EquivCheck
		e.run(o)
	}
	e.place("legacy.unrepresentable.yaml")
	out, rc := e.imp("--replace")
	status(t, rc, 1, out)
	left, _ := os.ReadDir(tmp)
	if len(left) != 0 {
		t.Errorf("left in TMPDIR: %v", left)
	}
}

// --- --check --------------------------------------------------------------------

func TestImportCheckWithoutRenderer(t *testing.T) {
	// "import --check: writes nothing; without a renderer it exits 3 and
	// says so"
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	out, rc := e.imp("--check")
	status(t, rc, 3, out)
	contains(t, out, "import + validate:   OK")
	contains(t, out, "render:              SKIPPED (no renderer available)")
	contains(t, out, "equivalence with "+e.config+" was not proven")
	if e.storeExists() {
		t.Error("a store was written")
	}
	// A renderer that says it is not available is the same.
	o := e.opts("--check")
	o.Render = func(*store.Store) ([]byte, error) { return nil, store.ErrNoRenderer }
	out2, rc := e.run(o)
	status(t, rc, 3, out2)
	equal(t, out2, out)
}

func TestImportCheckUnrepresentableBeforeRender(t *testing.T) {
	// "import --check: unrepresentable content fails before any render"
	e := newImportEnv(t)
	e.place("legacy.unrepresentable.yaml")
	o := e.opts("--check")
	called := false
	o.Render = func(*store.Store) ([]byte, error) { called = true; return nil, nil }
	out, rc := e.run(o)
	status(t, rc, 1, out)
	contains(t, out, "group 'netops': service 'ppp'")
	if called || e.storeExists() {
		t.Error("rendered or wrote")
	}
}

func checkWith(e *ienv, render func(*store.Store) ([]byte, error), smoke func(string) error) (string, int) {
	o := e.opts("--check")
	o.Render, o.Smoke, o.Equiv = render, smoke, model.EquivCheck
	o.TempDir = e.t.TempDir()
	return e.run(o)
}

func TestImportCheckEquivalent(t *testing.T) {
	// "import --check: the render hook receives the model and an output
	// path; EQUIVALENT passes"
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	out, rc := checkWith(e, func(s *store.Store) ([]byte, error) {
		lines, _, _ := model.Get(s, "users")
		if strings.Join(lines, " ") != "alice bob carol" {
			return nil, errors.New("wrong model")
		}
		return readFile(t, e.config), nil
	}, nil)
	status(t, rc, 0, out)
	contains(t, out, "render:              OK")
	contains(t, out, "EQUIVALENT")
	contains(t, out, "daemon load-smoke:   SKIPPED")
	contains(t, out, "Check passed. Nothing was written.")
	if e.storeExists() {
		t.Error("a store was written")
	}
}

func TestImportCheckNotEquivalent(t *testing.T) {
	// "import --check: a non-equivalent render fails with a redacted diff"
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	out, rc := checkWith(e, func(*store.Store) ([]byte, error) {
		return []byte(strings.ReplaceAll(string(readFile(t, e.config)), "dmz-secret-0123456789abcdef", "rotated-secret-0123456789abc")), nil
	}, nil)
	status(t, rc, 1, out)
	contains(t, out, "NOT EQUIVALENT")
	contains(t, out, "203.0.113.0/24")
	refute(t, out, "dmz-secret")
	refute(t, out, "rotated-secret")
	contains(t, out, "[ERROR]"+ui.NC+" Rendered config is not equivalent to "+e.config+".\n")
	if e.storeExists() {
		t.Error("a store was written")
	}
}

func TestImportCheckRenderAndSmokeFailures(t *testing.T) {
	// "import --check: render failure and smoke failure both fail the
	// check"
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	out, rc := checkWith(e, func(*store.Store) ([]byte, error) {
		return nil, &store.Error{Msg: "internal error: the rendered config does not read back as the model"}
	}, nil)
	status(t, rc, 1, out)
	contains(t, out, "tacctl store: internal error: the rendered config does not read back as the model\n  render:              FAILED\n")
	same := func(*store.Store) ([]byte, error) { return readFile(t, e.config), nil }
	var smoked string
	out, rc = checkWith(e, same, func(p string) error {
		smoked = string(readFile(t, p))
		return errors.New("Load-smoke: tacquito did not start serving within 1s.")
	})
	status(t, rc, 1, out)
	contains(t, out, "[ERROR]"+ui.NC+" Load-smoke: tacquito did not start serving within 1s.\n  daemon load-smoke:   FAILED\n")
	equal(t, smoked, string(readFile(t, e.config)))
	out, rc = checkWith(e, same, func(string) error { return nil })
	status(t, rc, 0, out)
	contains(t, out, "daemon load-smoke:   OK")
	out, rc = checkWith(e, same, func(string) error { return store.ErrSmokeSkipped })
	status(t, rc, 0, out)
	contains(t, out, "daemon load-smoke:   SKIPPED")
}

func TestImportCheckEquivError(t *testing.T) {
	// The rendered file does not parse: the check's error, an empty
	// equivalence block, and the failure.
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	out, rc := checkWith(e, func(*store.Store) ([]byte, error) { return []byte("a: [\n"), nil }, nil)
	status(t, rc, 1, out)
	contains(t, out, "  equivalence:\ntacctl store: ")
	contains(t, out, "\n    \n\n"+ui.Red+"[ERROR]"+ui.NC+" Rendered config is not equivalent to "+e.config+".\n")
}

// --- vendor fields --------------------------------------------------------------

func TestImportVendorFieldsCarryOver(t *testing.T) {
	// "import: never produces vendor fields; --replace keeps them, and
	// drops (with --force) a tag the imported prefixes no longer hold"
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.edgeSidecars()
	e.mustImport()
	if regexp.MustCompile(`vendor_attrs|devices`).Match(readFile(t, e.path)) {
		t.Fatal("the import wrote vendor fields")
	}
	labNet := strings.Split(e.mustGet("scopes", "lab", "prefixes"), "\n")[0]
	e.mustMutate(scopeSet("lab", "vendor_attrs=wti,cisco", "devices="+labNet+"=juniper"))
	if err := os.RemoveAll(e.dates); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(e.disabled); err != nil {
		t.Fatal(err)
	}
	out := e.mustImport("--replace")
	contains(t, out, "kept the RADIUS vendor attributes and tagged addresses of 1 scope(s)")
	equal(t, e.mustGet("scopes", "lab", "vendor_attrs"), "cisco\nwti")
	equal(t, e.mustGet("scopes", "lab", "devices"), labNet+" juniper")

	// The file to import no longer has that prefix: the tag cannot be kept.
	e.edit(func(s string) string { return strings.ReplaceAll(s, `"`+labNet+`"`, `"198.18.99.0/24"`) })
	out, rc := e.imp("--replace")
	status(t, rc, 1, out)
	contains(t, out, "scope 'lab': the vendor tag of "+labNet+" (no prefix of the scope in this file contains it any more)")
	equal(t, e.mustGet("scopes", "lab", "devices"), labNet+" juniper")
	e.mustImport("--replace", "--force")
	equal(t, e.mustGet("scopes", "lab", "devices"), "")
	equal(t, e.mustGet("scopes", "lab", "vendor_attrs"), "cisco\nwti")
}

// --- store_cli.bats: 'tacctl store import' ---------------------------------------

func TestImportCLIWritesStore(t *testing.T) {
	// store_cli.bats "store import: writes a 0600 store and leaves
	// tacquito.yaml untouched", plus the flip: the live file is kept as
	// the pre-store copy 'store rollback' returns to.
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	before := string(readFile(t, e.config))
	out := e.mustImport()
	pre := filepath.Join(e.legacyDir, "tacquito.yaml.pre-store.20261003_120000")
	equal(t, out, "\n"+
		"  Source:   "+e.config+"\n"+
		"  Groups:   3\n"+
		"  Users:    3 (0 disabled)\n"+
		"  Scopes:   4\n"+
		"  Filters:  allow 0, deny 0\n"+
		"\n"+
		"  Notes:\n"+
		"    - user 'alice': has no accounter of its own; the rendered config always attaches the file accounter\n"+
		"    - user 'bob': has no accounter of its own; the rendered config always attaches the file accounter\n"+
		"    - user 'carol': has no accounter of its own; the rendered config always attaches the file accounter\n"+
		"\n"+
		ui.Green+"[INFO]"+ui.NC+" Store written to "+e.path+".\n"+
		ui.Green+"[INFO]"+ui.NC+" Pre-store "+e.config+" kept as "+pre+" ('tacctl store rollback' returns to it).\n")
	if m := mode(t, e.path); m != 0o600 {
		t.Errorf("mode %o", m)
	}
	equal(t, string(readFile(t, e.path)), string(readFile(t, fixtures+"store.multiscope.yaml")))
	equal(t, string(readFile(t, e.config)), before)
	equal(t, string(readFile(t, pre)), before)
	if m := mode(t, pre); m != 0o600 {
		t.Errorf("pre-store mode %o", m)
	}
	if m := mode(t, e.legacyDir); m != 0o700 {
		t.Errorf("legacy dir mode %o", m)
	}
}

func TestImportCLIStrictThenForce(t *testing.T) {
	// store_cli.bats "store import: strict failure exits 1 and writes
	// nothing; --force succeeds"
	e := newImportEnv(t)
	e.place("legacy.unrepresentable.yaml")
	out, rc := e.imp()
	status(t, rc, 1, out)
	contains(t, out, "group 'netops': service 'ppp'")
	contains(t, out, "Nothing was written")
	if e.storeExists() {
		t.Fatal("a store was written")
	}
	out = e.mustImport("--force")
	contains(t, out, "Dropped (--force)")
	if !e.storeExists() {
		t.Error("no store")
	}
}

func TestImportCLICheckNothingWritten(t *testing.T) {
	// store_cli.bats "store import --check: a file the render would change
	// exits 1 and writes nothing" and "a file tacctl rendered exits 0 and
	// writes nothing" (the renders are internal/model's testdata: what
	// 0.1.16 rendered for them)
	for _, c := range []struct {
		src, render, want string
		rc                int
	}{
		{fixtures + "tacquito.multiscope.yaml", "../model/testdata/legacy/renders/multiscope.raw.yaml", "NOT EQUIVALENT", 1},
		{fixtures + "golden/tacquito.multiscope.rendered.yaml", fixtures + "golden/tacquito.multiscope.rendered.yaml", "    EQUIVALENT\n", 0},
	} {
		e := newImportEnv(t)
		e.write(e.config, string(readFile(t, c.src)))
		before := listTree(t, filepath.Dir(e.dir))
		out, rc := checkWith(e, func(*store.Store) ([]byte, error) { return readFile(t, c.render), nil }, nil)
		status(t, rc, c.rc, out)
		contains(t, out, "import + validate:   OK")
		contains(t, out, "render:              OK")
		contains(t, out, c.want)
		if after := listTree(t, filepath.Dir(e.dir)); after != before {
			t.Errorf("the check changed the tree:\n%s\n---\n%s", before, after)
		}
		equal(t, string(readFile(t, e.config)), string(readFile(t, c.src)))
	}
}

func listTree(t *testing.T, root string) string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		paths = append(paths, p)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(paths, "\n")
}

func TestImportCLINamedFile(t *testing.T) {
	// store_cli.bats "store import <file>: imports a named file, e.g. a
	// legacy backup" and "works with no tacquito.yaml in place when a file
	// is named". A named file that is not the live config is not the flip:
	// no pre-store copy.
	e := newImportEnv(t)
	e.place("tacquito.minimal.yaml")
	out := e.mustImport(fixtures + "tacquito.multiscope.yaml")
	refute(t, out, "Pre-store")
	equal(t, string(readFile(t, e.path)), string(readFile(t, fixtures+"store.multiscope.yaml")))
	if _, err := os.Stat(e.legacyDir); err == nil {
		t.Error("a pre-store copy was kept")
	}
	e = newImportEnv(t)
	e.mustImport(fixtures + "tacquito.minimal.yaml")
	equal(t, string(readFile(t, e.path)), string(readFile(t, fixtures+"store.minimal.yaml")))
}

func TestImportFlipKeepsOnePreStoreCopy(t *testing.T) {
	// store_keep_pre_store: a repeated import of the same live file reuses
	// the newest copy; a different file gets a new one, '.1' when the
	// second is taken.
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	e.mustImport()
	if err := os.Remove(e.path); err != nil {
		t.Fatal(err)
	}
	out := e.mustImport()
	contains(t, out, "kept as "+filepath.Join(e.legacyDir, "tacquito.yaml.pre-store.20261003_120000")+" (")
	if err := os.Remove(e.path); err != nil {
		t.Fatal(err)
	}
	e.place("tacquito.minimal.yaml")
	out = e.mustImport()
	contains(t, out, "kept as "+filepath.Join(e.legacyDir, "tacquito.yaml.pre-store.20261003_120000.1")+" (")
	entries, _ := os.ReadDir(e.legacyDir)
	if len(entries) != 2 {
		t.Errorf("copies: %v", entries)
	}
	latest, ok := store.PreStoreLatest(e.legacyDir)
	equal(t, latest, filepath.Join(e.legacyDir, "tacquito.yaml.pre-store.20261003_120000.1"))
	if !ok {
		t.Error("PreStoreLatest: none")
	}
}

func TestImportPreStoreFailure(t *testing.T) {
	// The flip cannot keep its copy: nothing is written.
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	e.write(e.legacyDir, "a file where the directory should be")
	out, rc := e.imp()
	status(t, rc, 1, out)
	contains(t, out, "[ERROR]"+ui.NC+" Import failed: could not keep a copy of "+e.config+" under "+e.legacyDir+"/. Nothing was written.\n")
	if e.storeExists() {
		t.Error("a store was written")
	}
}

func TestPreStoreLatest(t *testing.T) {
	dir := t.TempDir()
	if _, ok := store.PreStoreLatest(dir); ok {
		t.Error("found one in an empty dir")
	}
	if _, ok := store.PreStoreLatest(filepath.Join(dir, "absent")); ok {
		t.Error("found one in a missing dir")
	}
	for _, n := range []string{"tacquito.yaml.pre-store.20250101_000000", "tacquito.yaml.pre-store.20260101_000000"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Symlinks, directories and other names are not copies.
	if err := os.Symlink("x", filepath.Join(dir, "tacquito.yaml.pre-store.20270101_000000")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "tacquito.yaml.pre-store.20280101_000000"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tacquito.yaml.20290101"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := store.PreStoreLatest(dir)
	if !ok || got != filepath.Join(dir, "tacquito.yaml.pre-store.20260101_000000") {
		t.Errorf("got %q %v", got, ok)
	}
}

func TestImportWriteFailure(t *testing.T) {
	// import-write fails (here: the store's directory is not writable):
	// the error, then 'Import failed. Nothing was written.'
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	e.mustImport()
	if err := os.Chmod(e.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.dir, 0o700) })
	e.place("tacquito.minimal.yaml")
	out, rc := e.imp("--replace")
	status(t, rc, 1, out)
	contains(t, out, "tacctl store: "+e.dir)
	contains(t, out, ": Permission denied\n"+ui.Red+"[ERROR]"+ui.NC+" Import failed. Nothing was written.\n")
}

// A hook that printed its own message returns ui.ErrReported: the failure
// line follows, and nothing is printed for the error a second time.
func TestImportCheckAHookThatReportedItselfIsNotPrintedAgain(t *testing.T) {
	e := newImportEnv(t)
	e.place("tacquito.multiscope.yaml")
	out, rc := checkWith(e, func(*store.Store) ([]byte, error) { return nil, ui.ErrReported }, nil)
	status(t, rc, 1, out)
	contains(t, out, "  import + validate:   OK\n  render:              FAILED\n")
	refute(t, out, "[ERROR]")
	same := func(*store.Store) ([]byte, error) { return readFile(t, e.config), nil }
	out, rc = checkWith(e, same, func(string) error { return ui.ErrReported })
	status(t, rc, 1, out)
	contains(t, out, "    EQUIVALENT\n  daemon load-smoke:   FAILED\n")
	refute(t, out, "[ERROR]")
}
