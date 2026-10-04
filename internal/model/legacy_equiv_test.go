package model_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

const legacyData = "testdata/legacy/"

var reFingerprint = regexp.MustCompile(`<redacted:[0-9a-f]{10}>`)

// numberFingerprints writes each distinct fingerprint as <redacted:N>, N
// by first appearance, as gen.sh does with the python's: the key differs
// per run, which values share a fingerprint does not.
func numberFingerprints(s string) string {
	seen := map[string]int{}
	return reFingerprint.ReplaceAllStringFunc(s, func(m string) string {
		if _, ok := seen[m]; !ok {
			seen[m] = len(seen) + 1
		}
		return "<redacted:" + strconv.Itoa(seen[m]) + ">"
	})
}

func legacyPath(p string) string {
	if rest, ok := strings.CutPrefix(p, "FIXTURES/"); ok {
		return fixtures + rest
	}
	return legacyData + p
}

func unpath(s string) string {
	s = strings.ReplaceAll(s, fixtures, "FIXTURES/")
	return strings.ReplaceAll(s, legacyData, "")
}

func equiv(t *testing.T, a, b string) (string, bool) {
	t.Helper()
	var out bytes.Buffer
	ok, err := model.EquivCheck(a, b, &out)
	if err != nil {
		t.Fatalf("EquivCheck(%s, %s): %v", a, b, err)
	}
	return out.String(), ok
}

func sameLines(t *testing.T, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(gl) && i < len(wl); i++ {
		if gl[i] != wl[i] {
			t.Fatalf("first difference at line %d:\n got: %q\nwant: %q", i+1, gl[i], wl[i])
		}
	}
	t.Fatalf("length differs: %d vs %d lines:\n%s", len(gl), len(wl), got)
}

// TestEquivGoldens runs EquivCheck on every pair of testdata/legacy/pairs
// and compares with what equiv_check of the 0.1.16 tag printed (gen.sh):
// the variants of store_import.bats, the README's 'store import --check'
// verdicts (each tacquito.* fixture, raw and after upgrade's migrations,
// against its render), and large files that exercise difflib's autojunk.
func TestEquivGoldens(t *testing.T) {
	for _, line := range strings.Split(string(readFile(t, legacyData+"pairs")), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		t.Run(f[0], func(t *testing.T) {
			out, ok := equiv(t, legacyPath(f[1]), legacyPath(f[2]))
			rc := 1
			if ok {
				rc = 0
			}
			got := numberFingerprints(unpath(out)) + "rc=" + strconv.Itoa(rc) + "\n"
			sameLines(t, got, string(readFile(t, legacyData+"expected/equiv."+f[0]+".out")))
		})
	}
}

// importEnv is the part of tmpenv 'store import' reads.
type importEnv struct {
	t                                         *testing.T
	store, config, dates, disabled, legacyDir string
}

func newImportEnv(t *testing.T) *importEnv {
	t.Helper()
	root := t.TempDir()
	e := &importEnv{t: t,
		store:     filepath.Join(root, "state", "store.yaml"),
		config:    filepath.Join(root, "etc", "tacquito.yaml"),
		dates:     filepath.Join(root, "state", "backups", "password-dates"),
		disabled:  filepath.Join(root, "state", "backups", "disabled"),
		legacyDir: filepath.Join(root, "state", "backups", "legacy"),
	}
	for _, d := range []string{filepath.Dir(e.store), filepath.Dir(e.config), e.dates} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *importEnv) place(src string) {
	e.t.Helper()
	if err := os.WriteFile(e.config, readFile(e.t, src), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *importEnv) paths() model.Paths {
	return model.Paths{Store: e.store, Config: e.config, DatesDir: e.dates, DisabledDir: e.disabled}
}

// check runs 'store import --check' with render as the render hook's
// output; stdout and stderr in one stream, then 'rc='.
func (e *importEnv) check(render []byte) string {
	var out bytes.Buffer
	err := store.Import(ui.Output{Stdout: &out, Stderr: &out}, store.ImportOptions{
		Check: true, StorePath: e.store, ConfigPath: e.config, DatesDir: e.dates,
		DisabledDir: e.disabled, LegacyDir: e.legacyDir,
		Render: func(*store.Store) ([]byte, error) { return render, nil },
		Equiv:  model.EquivCheck, TempDir: e.t.TempDir(),
	})
	rc := 0
	var st *store.ImportStatus
	if errors.As(err, &st) {
		rc = st.Code
	} else if err != nil {
		e.t.Fatal(err)
	}
	return out.String() + "rc=" + strconv.Itoa(rc) + "\n"
}

// TestImportCheckGoldens is 'store import --check' end to end on each
// tacquito.* fixture, raw and migrated, with the render 0.1.16 made of it
// as the render hook's output: the whole output, byte for byte, against
// the bash of the 0.1.16 tag (gen.sh). The verdicts are those of
// tests/README.md "Which fixtures pass 'store import --check'": every raw
// fixture is NOT EQUIVALENT; minimal, legacy-exec and dead-matches are
// EQUIVALENT once upgrade's migrations have run, multiscope is not; a
// rendered file is EQUIVALENT to itself.
func TestImportCheckGoldens(t *testing.T) {
	verdicts := map[string]int{}
	for _, f := range []string{"minimal", "legacy-exec", "dead-matches", "multiscope"} {
		verdicts[f+".raw"] = 1
		verdicts[f+".migrated"] = 0
	}
	verdicts["multiscope.migrated"] = 1
	verdicts["golden-multiscope"] = 0
	for name, rc := range verdicts {
		t.Run(name, func(t *testing.T) {
			src, render := legacyData+"migrated/"+strings.TrimSuffix(name, ".migrated")+".yaml", ""
			switch {
			case name == "golden-multiscope":
				src = fixtures + "golden/tacquito.multiscope.rendered.yaml"
				render = src
			case strings.HasSuffix(name, ".raw"):
				src = fixtures + "tacquito." + strings.TrimSuffix(name, ".raw") + ".yaml"
				render = legacyData + "renders/" + name + ".yaml"
			default:
				render = legacyData + "renders/" + name + ".yaml"
			}
			e := newImportEnv(t)
			e.place(src)
			got := numberFingerprints(strings.ReplaceAll(e.check(readFile(t, render)), e.config, "SRC"))
			sameLines(t, got, string(readFile(t, legacyData+"expected/check."+name+".out")))
			if !strings.HasSuffix(got, "rc="+strconv.Itoa(rc)+"\n") {
				t.Errorf("verdict: want rc=%d", rc)
			}
			if _, err := os.Stat(e.store); err == nil {
				t.Error("--check wrote a store")
			}
		})
	}
}

// --- store_import.bats: store_equiv_check ---------------------------------------

func contains(t *testing.T, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

func lacks(t *testing.T, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(out, s) {
			t.Errorf("output has %q:\n%s", s, out)
		}
	}
}

func hasLine(t *testing.T, out, line string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if l == line {
			return
		}
	}
	t.Errorf("no line %q in:\n%s", line, out)
}

const ms = fixtures + "tacquito.multiscope.yaml"

func v(name string) string { return legacyData + "variants/" + name + ".yaml" }

func TestEquivSelf(t *testing.T) {
	// "equiv: a file is equivalent to itself"
	out, ok := equiv(t, ms, ms)
	if !ok {
		t.Fatal(out)
	}
	hasLine(t, out, "EQUIVALENT")
}

func TestEquivSpellingDoesNotMatter(t *testing.T) {
	// "equiv: comments, anchors-vs-inline and user scope order do not matter"
	out, ok := equiv(t, ms, v("noalias-reversed"))
	if !ok {
		t.Fatal(out)
	}
	hasLine(t, out, "EQUIVALENT")
	// "equiv: one multi-prefix entry equals one entry per prefix in any
	// harmless order"
	out, ok = equiv(t, v("minimal-multi"), v("minimal-split"))
	if !ok {
		t.Fatal(out)
	}
	hasLine(t, out, "EQUIVALENT")
}

func TestEquivReroute(t *testing.T) {
	// "equiv: an order change that re-routes clients is NOT equivalent"
	a := v("reroute-a")
	out, ok := equiv(t, a, v("reroute-b"))
	if ok {
		t.Fatal(out)
	}
	contains(t, out, "NOT EQUIVALENT",
		"note: "+a+": secrets[1] 'prod-inner': 10.10.99.0/24 never matches a client (an earlier entry already covers it with 10.0.0.0/8)")
	lacks(t, out, "differ only in groups without users", "once every scope has a user")
}

func TestEquivLatent(t *testing.T) {
	// "equiv: the same order change on a scope without users is reported
	// as latent, and still fails"
	out, ok := equiv(t, ms, v("swapped"))
	if ok {
		t.Fatal(out)
	}
	contains(t, out, "note: "+ms+": scope 'prod-inner' has no users; tacquito does not load it",
		"differ only in groups without users or scopes without users", "NOT EQUIVALENT")
}

func TestEquivSpareScopeShadowsNothing(t *testing.T) {
	// "equiv: an entry for a scope without users shadows nothing"
	out, ok := equiv(t, v("spare-a"), v("spare-b"))
	if ok {
		t.Fatal(out)
	}
	contains(t, out, "NOT EQUIVALENT", `"prefix": "192.168.7.0/24"`)
	lacks(t, out, "differ only in groups without users")
}

func TestEquivAccounterInherited(t *testing.T) {
	// "equiv: a user without an accounter inherits its group's, so adding
	// the same one changes nothing"
	out, ok := equiv(t, ms, v("user-accounter"))
	if !ok {
		t.Fatal(out)
	}
	contains(t, out, "EQUIVALENT")
	out, ok = equiv(t, v("no-accounter"), v("user-accounter"))
	if ok {
		t.Fatal(out)
	}
	contains(t, out, `"accounter": null`)
}

func TestEquivUnparseablePrefixes(t *testing.T) {
	// "equiv: prefixes tacquito cannot parse are not treated as the CIDR
	// tacctl would write"
	a := v("bare-address")
	out, ok := equiv(t, a, v("bare-address-32"))
	if ok {
		t.Fatal(out)
	}
	contains(t, out,
		"note: "+a+": secrets[3] 'dmz': prefix '203.0.113.9' is not a CIDR tacquito can parse; it is skipped",
		"note: "+a+": prefix_deny: '10.1.1.1' is not a CIDR tacquito can parse; it is ignored",
		`+    "10.1.1.1/32"`, `"prefix": "203.0.113.9/32"`)
	// "equiv: a prefixes block that is not strict JSON yields no provider"
	out, ok = equiv(t, v("trailing-comma"), ms)
	if ok {
		t.Fatal(out)
	}
	contains(t, out, "secrets[3] 'dmz': prefixes is not a non-empty JSON list of strings; tacquito builds nothing for it",
		`"prefix": "203.0.113.0/24"`)
}

func TestEquivScalarsAreText(t *testing.T) {
	// "equiv: scalars compare as the text the daemon decodes, not as YAML
	// types"
	if out, ok := equiv(t, ms, v("quoted-15")); !ok {
		t.Fatal(out)
	}
	out, ok := equiv(t, ms, v("octal-15"))
	if ok {
		t.Fatal(out)
	}
	contains(t, out, `"015"`)
}

func TestEquivNeverPrintsSecrets(t *testing.T) {
	// "equiv: no hash or key is printed, wherever it sits"
	out, ok := equiv(t, v("secrets-everywhere"), ms)
	if ok {
		t.Fatal(out)
	}
	contains(t, out, "<redacted:")
	lacks(t, out, "2432deadbeef", "grpkey", "side-secret", "prod-secret")
	// "equiv: a changed user hash or group is reported without printing
	// hashes"
	out, ok = equiv(t, ms, v("changed-hash"))
	if ok {
		t.Fatal(out)
	}
	contains(t, out, "NOT EQUIVALENT", "<redacted:")
	lacks(t, out, "646f6e74636172")
}

func TestEquivDisabledAndExec(t *testing.T) {
	// "equiv: the 'DISABLED' literal equals the disabled marker; service
	// 'exec' does not equal 'shell'"
	edge := fixtures + "legacy.import-edge.yaml"
	if bytes.Equal(readFile(t, edge), readFile(t, v("edge-marker"))) {
		t.Fatal("variant equals the fixture")
	}
	out, ok := equiv(t, edge, v("edge-marker"))
	if !ok {
		t.Fatal(out)
	}
	contains(t, out, "EQUIVALENT")
	out, ok = equiv(t, edge, v("edge-shell"))
	if ok {
		t.Fatal(out)
	}
	contains(t, out, `"name": "exec"`)
	out, ok = equiv(t, fixtures+"tacquito.legacy-exec.yaml", fixtures+"tacquito.minimal.yaml")
	if ok {
		t.Fatal(out)
	}
	contains(t, out, "differ only in groups without users or scopes without users")
}

func TestEquivFiltersAreSets(t *testing.T) {
	// "equiv: prefix filters compare as sets"
	edge := fixtures + "legacy.import-edge.yaml"
	if out, ok := equiv(t, edge, v("edge-allow")); !ok {
		t.Fatal(out)
	}
	out, ok := equiv(t, edge, v("edge-deny"))
	if ok {
		t.Fatal(out)
	}
	contains(t, out, "10.67.0.0/16")
}

func TestEquivErrors(t *testing.T) {
	// A file that cannot be read or parsed is a store error naming it,
	// never quoting it.
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("secrets:\n  - name: lab\n    secret: {key: \"leaky-secret-0123456789\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{bad, ms}, {ms, bad}, {filepath.Join(dir, "absent.yaml"), ms}} {
		var out bytes.Buffer
		_, err := model.EquivCheck(pair[0], pair[1], &out)
		var se *store.Error
		if !errors.As(err, &se) {
			t.Fatalf("%v: want a *store.Error, got %v", pair, err)
		}
		msg := store.Report(err)
		if !strings.HasPrefix(msg, "tacctl store: "+dir) || strings.Contains(msg, "leaky") || out.Len() != 0 {
			t.Errorf("%v: %q (output %q)", pair, msg, out.String())
		}
	}
	var out bytes.Buffer
	_, err := model.EquivCheck(filepath.Join(dir, "absent.yaml"), ms, &out)
	if msg := store.Report(err); msg != "tacctl store: "+filepath.Join(dir, "absent.yaml")+": No such file or directory" {
		t.Errorf("missing file: %q", msg)
	}
}

// EquivCheckRand takes its fingerprint key from the source it is given:
// the same bytes give the same fingerprints (the differential runner fixes
// them on both sides), HMAC-SHA256 keyed with the first 16 bytes as the
// python keys it with os.urandom(16); the verdict is EquivCheck's.
func TestEquivCheckRandKeysTheFingerprints(t *testing.T) {
	a, b := ms, v("changed-hash")
	run := func(src string) (string, bool) {
		var out bytes.Buffer
		ok, err := model.EquivCheckRand(strings.NewReader(src))(a, b, &out)
		if err != nil {
			t.Fatal(err)
		}
		return out.String(), ok
	}
	key := strings.Repeat("k", 16)
	one, ok1 := run(key + "ignored")
	two, ok2 := run(key)
	if one != two || ok1 || ok2 {
		t.Fatalf("same key, different reports:\n%s\n%s", one, two)
	}
	other, _ := run(strings.Repeat("o", 16))
	if other == one || numberFingerprints(other) != numberFingerprints(one) {
		t.Fatalf("another key must change the fingerprints only:\n%s\n%s", one, other)
	}
	plain, okPlain := equiv(t, a, b)
	if okPlain != ok1 || numberFingerprints(plain) != numberFingerprints(one) {
		t.Fatalf("EquivCheckRand and EquivCheck disagree:\n%s\n%s", plain, one)
	}
	// A source that runs dry falls back to crypto/rand.
	if short, ok := run("short"); ok || numberFingerprints(short) != numberFingerprints(one) {
		t.Fatalf("short source: %s", short)
	}
}
