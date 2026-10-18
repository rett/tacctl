package hosts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// RememberNew refuses a name equal to an enrolled one in any case, under the
// lock and after the registry is read again.
func TestRememberNewRefusesAFoldEqualLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "linux-hosts")
	writeFile(t, p, "web1|root@w||lab|192.0.2.1|\n")
	// A registry loaded before the line was written: the check is made on
	// the file as it is under the lock.
	stale := &Registry{Path: p}
	if err := stale.Load(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "web1|root@w||lab|192.0.2.1|\nDB2|root@d||lab|192.0.2.1|\n")

	for _, name := range []string{"Web1", "WEB1", "web1", "db2"} {
		err := stale.RememberNew(Entry{Name: name, Target: "t", Scope: "lab", Server: "s"})
		var taken *NameTakenError
		if !errors.Is(err, ErrNameTaken) || !errors.As(err, &taken) || !strings.EqualFold(taken.Holder, name) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := stale.RememberNew(Entry{Name: "web3", Target: "t", Scope: "lab", Server: "s"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); got != "web1|root@w||lab|192.0.2.1|\nDB2|root@d||lab|192.0.2.1|\nweb3|t||lab|s|\n" {
		t.Errorf("registry %q", got)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
}

// Two enrolments of one name in two cases, started together: one is
// written, the other is refused, never both.
func TestRememberNewConcurrentCases(t *testing.T) {
	for round := 0; round < 20; round++ {
		p := filepath.Join(t.TempDir(), "linux-hosts")
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, name := range []string{"Web1", "web1"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := &Registry{Path: p}
				_ = r.Load()
				errs[i] = r.RememberNew(Entry{Name: name, Target: "t", Scope: "lab", Server: "s"})
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, ErrNameTaken):
				t.Fatalf("round %d: %v", round, err)
			}
		}
		r, _ := LoadRegistry(p)
		if ok != 1 || len(r.Entries()) != 1 {
			t.Fatalf("round %d: %d written, registry %q", round, ok, readFile(t, p))
		}
	}
}

func TestRegistryRename(t *testing.T) {
	p := filepath.Join(t.TempDir(), "linux-hosts")
	writeFile(t, p, "web1|root@w|2222|linux-web1|192.0.2.1|/k|radius\nweb2|web2||lab|192.0.2.1|\nweb1|dup|||\n")
	r, err := LoadRegistry(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Rename("web1", "web9"); err != nil {
		t.Fatal(err)
	}
	// In place, every other field as written, a second line of the old name
	// dropped as Replace drops it.
	if got := readFile(t, p); got != "web9|root@w|2222|linux-web1|192.0.2.1|/k|radius\nweb2|web2||lab|192.0.2.1|\n" {
		t.Errorf("registry %q", got)
	}
	if _, ok := r.Find("web9"); !ok {
		t.Error("the loaded registry is stale")
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".linux-hosts.*")); len(m) != 0 {
		t.Errorf("left behind: %v", m)
	}

	// Refusals change nothing.
	before := readFile(t, p)
	for _, c := range []struct {
		old, new string
		err      error
	}{
		{"ghost", "x", ErrNotEnrolled},
		{"web9", "web2", ErrNameTaken},
		{"web9", "WEB2", ErrNameTaken},
	} {
		if err := r.Rename(c.old, c.new); !errors.Is(err, c.err) {
			t.Errorf("%s -> %s: %v, want %v", c.old, c.new, err, c.err)
		}
	}
	if readFile(t, p) != before {
		t.Error("a refusal changed the registry")
	}

	// A change of spelling is a rename of the host itself, and back.
	if err := r.Rename("web9", "Web9"); err != nil {
		t.Fatal(err)
	}
	if err := r.Rename("Web9", "web9"); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != before {
		t.Errorf("registry %q", readFile(t, p))
	}

	// The registry is read again under the lock: a line added since the load
	// is kept, and a name taken since it refuses.
	stale := &Registry{Path: p}
	_ = stale.Load()
	writeFile(t, p, before+"Web4|w4||lab|192.0.2.1|\n")
	if err := stale.Rename("web9", "web4"); !errors.Is(err, ErrNameTaken) {
		t.Errorf("a name taken since the load: %v", err)
	}
	if err := stale.Rename("web9", "web5"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); !strings.Contains(got, "Web4|w4") || !strings.HasPrefix(got, "web5|") {
		t.Errorf("registry %q", got)
	}
}
