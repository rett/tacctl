package store_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Ports of tests/unit/store.bats: constants, store_init / legacy mode, the
// writer, store_mutate; plus the WP1.4a acceptance checks (fixture
// round-trips, the inode-preserving no-op write, the lock).

func TestDisabledMarkerIsTheHashPackages(t *testing.T) {
	// store.bats: "python disabled marker equals DISABLED_MARKER_HEX". The
	// store has no copy of its own: it refuses hash.DisabledMarkerHex.
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	msg := e.mutate(userSet("alice", "group=readonly", "hash="+hash.DisabledMarkerHex))
	contains(t, msg, "use disabled=true")
	if hash.DisabledMarkerHex != "24326224313224"+strings.Repeat("2e", 53) {
		t.Error("DISABLED_MARKER_HEX changed")
	}
}

func TestKnownVendorsAndProtocols(t *testing.T) {
	// store.bats "KNOWN_VENDORS equals SCOPE_VENDORS (lib/scopes.sh)" and
	// yaml.bats "SCOPE_PROTOCOLS matches KNOWN_PROTOCOLS": one list each
	// in Go (internal/names); pinned to the 0.1.16 values.
	equal(t, strings.Join(names.KnownVendors, " "), "cisco juniper wti")
	equal(t, strings.Join(names.KnownProtocols, " "), "tacacs radius")
}

func TestInit(t *testing.T) {
	e := newEnv(t)
	if err := store.Init(e.path); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, e.path); m != 0o600 {
		t.Errorf("mode %o", m)
	}
	if out, ok := validateFile(e.path); !ok {
		t.Error(out)
	}
	equal(t, e.mustGet("groups"), "operator\nreadonly\nsuperuser")
	equal(t, e.mustGet("users"), "")
	equal(t, string(readFile(t, e.path)), store.Header+`version: 1
groups:
  operator: {priv_lvl: 7, juniper_class: OP-CLASS, builtin: true}
  readonly: {priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}
  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}
users: {}
scopes: {}
filters:
  allow: []
  deny: []
`)
}

func TestInitRefusesExisting(t *testing.T) {
	e := newEnv(t)
	if err := store.Init(e.path); err != nil {
		t.Fatal(err)
	}
	err := store.Init(e.path)
	var ee *store.ExistsError
	if !errors.As(err, &ee) {
		t.Fatalf("got %v", err)
	}
	contains(t, err.Error(), "already exists")
}

func TestWriterUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	err := store.Init("/proc/1/no-such-dir/store.yaml")
	if err == nil {
		t.Fatal("no error")
	}
	out := store.Report(err)
	contains(t, out, "tacctl store: ")
	contains(t, out, "/proc/1/no-such-dir")
	refute(t, out, "Traceback")
	if strings.Count(out, "\n") != 0 {
		t.Errorf("not one line: %q", out)
	}
}

func TestMutationsRefusedInLegacyMode(t *testing.T) {
	e := newEnv(t)
	_, err := store.Mutate(e.path, store.MutateOptions{}, userSet("alice", "group=readonly"))
	if !errors.Is(err, store.ErrNotInitialised) {
		t.Fatalf("got %v", err)
	}
	contains(t, err.Error(), "store not initialised")
	contains(t, err.Error(), "tacctl store import")
	if _, err := os.Stat(e.path); !os.IsNotExist(err) {
		t.Error("a store was created")
	}
}

func TestWriterModeAndNoTempFiles(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	if err := os.Chmod(e.path, 0o644); err != nil {
		t.Fatal(err)
	}
	e.mustMutate(scopeSet("lab", "secret=another-secret-0123456789"))
	if m := mode(t, e.path); m != 0o600 {
		t.Errorf("mode %o", m)
	}
	if tf := tempFiles(t, e.dir); len(tf) != 0 {
		t.Errorf("temp files left: %v", tf)
	}
}

func TestWriterFailedValidationLeavesStore(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	before := readFile(t, e.path)
	msg := e.mutate(userSet("alice", "group=wizards"))
	contains(t, msg, "user 'alice': group 'wizards' does not exist")
	equal(t, msg, "tacctl store: store validation failed:\n  - user 'alice': group 'wizards' does not exist")
	if !bytes.Equal(readFile(t, e.path), before) {
		t.Error("store changed")
	}
	if tf := tempFiles(t, e.dir); len(tf) != 0 {
		t.Errorf("temp files left: %v", tf)
	}
}

func TestWriterNoOpKeepsInode(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	before := inode(t, e.path)
	changed, err := store.Mutate(e.path, store.MutateOptions{}, userSet("alice", "group=superuser"))
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if inode(t, e.path) != before {
		t.Error("the file was replaced")
	}
}

func TestWriterSnapshotHook(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	snap := filepath.Join(e.dir, "..", "snap.yaml")
	opts := store.MutateOptions{Snapshot: func() error {
		return os.WriteFile(snap, readFile(t, e.path), 0o600)
	}}
	if _, err := store.Mutate(e.path, opts, scopeSet("lab", "secret=another-secret-0123456789")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, snap), readFile(t, fixtures+"store.minimal.yaml")) {
		t.Error("snapshot is not the store before the write")
	}
	equal(t, e.mustGet("scopes", "lab", "secret"), "another-secret-0123456789")
}

func TestWriterFailingSnapshotBlocks(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	boom := errors.New("snapshot failed")
	_, err := store.Mutate(e.path, store.MutateOptions{Snapshot: func() error { return boom }},
		scopeSet("lab", "secret=another-secret-0123456789"))
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if !bytes.Equal(readFile(t, e.path), readFile(t, fixtures+"store.minimal.yaml")) {
		t.Error("store changed")
	}
}

func TestMutateCustomFunction(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	e.mustMutate(func(s *store.Store) error {
		groups, _ := s.Doc().Get("groups")
		groups.(*yamlpy.Map).Set("netops", yamlpy.NewMap("priv_lvl", 9, "juniper_class", "NETOPS"))
		return nil
	})
	equal(t, e.mustGet("groups", "netops", "priv_lvl"), "9")
	msg := e.mutate(func(s *store.Store) error {
		groups, _ := s.Doc().Get("groups")
		groups.(*yamlpy.Map).Set("x", yamlpy.NewMap("priv_lvl", 99, "juniper_class", "X"))
		return nil
	})
	contains(t, msg, "group 'x': priv_lvl must be 0-15")
}

func TestMutateValuesSurviveQuoting(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	secret := `it's a "quoted" $ecret, with = and spaces`
	e.mustMutate(scopeSet("lab", "secret="+secret))
	equal(t, e.mustGet("scopes", "lab", "secret"), secret)
	msg := e.mutate(scopeSet("lab", "secret=two\nlines"))
	contains(t, msg, "scope 'lab': secret contains control characters")
}

// --- acceptance: round-trips, lock ------------------------------------------

func TestFixtureRoundTrip(t *testing.T) {
	for _, name := range []string{"minimal", "multiscope", "radius"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			src := fixtures + "store." + name + ".yaml"
			s, err := store.Load(src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Write(e.path, s); err != nil {
				t.Fatal(err)
			}
			got := readFile(t, e.path)
			want := readFile(t, src)
			if name == "radius" {
				// Hand-written fixture (longer header, one secret quoted
				// where PyYAML writes it plain): the reference is PyYAML's
				// re-emit of it under the store header.
				want = append([]byte(store.Header), readFile(t, "../yamlpy/testdata/fixtures/store.radius.yaml")...)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("written store differs:\n--- got\n%s\n--- want\n%s", got, want)
			}
			if name != "radius" {
				// And a no-op write onto the fixture itself keeps the inode.
				e.useFixture("store." + name + ".yaml")
				ino := inode(t, e.path)
				s, _ := store.Load(e.path)
				changed, err := store.Write(e.path, s)
				if err != nil || changed || inode(t, e.path) != ino {
					t.Errorf("no-op write: changed=%v err=%v", changed, err)
				}
			}
		})
	}
}

func TestLockSerialises(t *testing.T) {
	e := newEnv(t)
	unlock, err := store.Lock(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, store.LockName)); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(e.dir, store.LockName)); m != 0o600 {
		t.Errorf("lock mode %o", m)
	}
	got := make(chan struct{})
	go func() {
		u2, err := store.Lock(e.path)
		if err == nil {
			u2()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second lock acquired while the first is held")
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("second lock never acquired")
	}
}

func TestConcurrentMutationsLoseNothing(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := "g" + string(rune('a'+i))
			if msg := e.mutate(groupSet(name, "priv_lvl=5", "juniper_class=C")); msg != "" {
				errs <- msg
			}
		}()
	}
	wg.Wait()
	close(errs)
	for m := range errs {
		t.Error(m)
	}
	groups := strings.Split(e.mustGet("groups"), "\n")
	if len(groups) != n+3 {
		t.Errorf("%d groups: %v", len(groups), groups)
	}
}

func TestLoadUnparseableNamesFileNotContent(t *testing.T) {
	// model.bats: "unparseable store fails the read and names the file".
	e := newEnv(t)
	if err := os.WriteFile(e.path, []byte("version: 1\nscopes: {lab: {secret: \"leaky-secret-0123456789\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load(e.path)
	if err == nil {
		t.Fatal("loaded")
	}
	out := store.Report(err)
	contains(t, out, "store.yaml")
	refute(t, out, "leaky-secret")
}

func TestLoadRefusesWhatYamlpyRefuses(t *testing.T) {
	// 0.1.16 (PyYAML) would load aliases; yamlpy refuses them, which the
	// store reports as a load error naming the place, never the value.
	e := newEnv(t)
	body := "version: 1\nscopes:\n  lab: &x {prefixes: [10.0.0.0/8], secret: s3cret-value}\n  lab2: *x\n"
	if err := os.WriteFile(e.path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load(e.path)
	if err == nil {
		t.Fatal("loaded")
	}
	out := store.Report(err)
	equal(t, out, "tacctl store: "+e.path+": not supported by tacctl: scopes.lab2: unsupported value: an alias")
	refute(t, out, "s3cret")
}

func TestLoadDates(t *testing.T) {
	e := newEnv(t)
	body := "version: 1\n" + builtins + "\nusers:\n  alice: {group: readonly, scopes: [], hash: null, disabled: true, password_changed: 2026-10-01}\n"
	if err := os.WriteFile(e.path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	equal(t, e.mustGet("users", "alice", "password_changed"), "2026-10-01")
	// The next write stores it as PyYAML writes a string date: quoted.
	e.mustMutate(userSet("alice", "disabled=true"))
	contains(t, string(readFile(t, e.path)), "    password_changed: '2026-10-01'\n")
}

func TestLoadNeverShowsAValue(t *testing.T) {
	// An unquoted all-digit hex hash is an integer to YAML 1.1, too big
	// for yamlpy; the message must not quote it.
	e := newEnv(t)
	digits := "2432622431322441414141414141414141414141414141414141414141414141"
	body := "version: 1\nusers:\n  bob: {group: readonly, scopes: [], hash: " + digits + digits + ", disabled: false}\n"
	if err := os.WriteFile(e.path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load(e.path)
	if err == nil {
		t.Fatal("loaded")
	}
	out := store.Report(err)
	contains(t, out, "users.bob.hash")
	refute(t, out, digits)
}

func TestWriteRefusesNonASCII(t *testing.T) {
	// 0.1.16 wrote a non-ASCII secret with PyYAML's "\xFC" escapes; the
	// yamlpy emitter refuses it, so the write is refused, cleanly.
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	before := readFile(t, e.path)
	msg := e.mutate(scopeSet("lab", "secret=s\u00fcper-secret-0123456789"))
	equal(t, msg, "tacctl store: cannot write scopes.lab.secret: only printable ASCII can be stored; nothing was written")
	if !bytes.Equal(readFile(t, e.path), before) {
		t.Error("store changed")
	}
}
