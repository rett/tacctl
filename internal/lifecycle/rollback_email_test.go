package lifecycle

import (
	"errors"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/store"
)

// rbStoreEmail writes a store with three users, two of them with an address.
func rbStoreEmail(t *testing.T, s *rbSandbox) {
	t.Helper()
	st := store.Empty()
	if err := st.ScopeSet("lab", "prefixes=192.0.2.0/24", "secret=example-secret-example-secret"); err != nil {
		t.Fatal(err)
	}
	for _, f := range [][]string{
		{"alice", "group=superuser", "scopes=lab", "hash=" + rbHash, "disabled=false", "email=alice@example.net"},
		{"bob", "group=operator", "scopes=lab", "hash=" + rbHash, "disabled=false"},
		{"carol", "group=readonly", "scopes=lab", "hash=" + rbHash, "disabled=false", "email=Carol.Jones@Example.NET"},
	} {
		if err := st.UserSet(f[0], f[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Write(s.p.StoreFile, st); err != nil {
		t.Fatal(err)
	}
}

const emailWarningTitle = "Email addresses are removed from the store"

// The email address of a user (0.2.23) is a store key every older release
// refuses, so every target, the ones that return early (0.2.22, 0.2.21,
// 0.2.20) included, removes it after the snapshot, names the users (never an
// address) in a warning that --apply needs --yes for, and keeps the rest.
func TestPlanRollbackEveryTargetRemovesTheEmail(t *testing.T) {
	for _, target := range allRollbackTargets {
		t.Run(target, func(t *testing.T) {
			s := newRBSandbox(t)
			s.oldSyntaxKey()
			rbStoreEmail(t, s)
			s.in.Target = target
			before := s.snapshotOf()
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if !p.PendingFiles() || !p.Pending() || !p.NeedsYes() {
				t.Errorf("files %v pending %v needs yes %v", p.PendingFiles(), p.Pending(), p.NeedsYes())
			}
			if got := strings.Join(p.EmailUsers(), ","); got != "alice,carol" {
				t.Errorf("email users %q", got)
			}
			var w string
			for _, x := range p.Warnings {
				if x.Title == emailWarningTitle {
					w = strings.Join(x.Lines, "\n")
				}
			}
			for _, want := range []string{target + " has no email address of a user (0.2.23): alice, carol have one each", "stay in the snapshot --apply takes first",
				"tacctl backup recover <snapshot> --only email"} {
				if !strings.Contains(w, want) {
					t.Errorf("the warning lacks %q:\n%s", want, w)
				}
			}
			st := stepText(p)
			for _, want := range []string{s.p.StoreFile + ": remove the email addresses " + target + " does not know", "remove email of alice\n", "remove email of carol\n",
				"unknown field 'email'"} {
				if !strings.Contains(st, want) {
					t.Errorf("the steps lack %q:\n%s", want, st)
				}
			}
			if strings.Contains(st, "remove email of bob") || strings.Contains(st, "leave "+s.p.StoreFile+" untouched") {
				t.Errorf("the steps:\n%s", st)
			}
			if i := strings.Index(st, "leave every other file untouched"); i >= 0 && strings.Contains(st[i:], s.p.StoreFile) {
				t.Errorf("the store is said to be left alone:\n%s", st)
			}
			// no address anywhere in the plan
			if all := st + w + strings.Join(p.Notes, "\n"); strings.Contains(strings.ToLower(all), "example.net") {
				t.Errorf("the plan shows an address:\n%s", all)
			}
			if after := s.snapshotOf(); !equalFiles(before, after) {
				t.Error("the plan wrote a file")
			}

			done, err := ApplyRollback(p)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(done, "\n"), s.p.StoreFile+": removed the email address of 2 users") {
				t.Errorf("done %q", done)
			}
			after := string(mustRead(t, s.p.StoreFile))
			if strings.Contains(after, "email") || strings.Contains(after, "example.net") || strings.Contains(strings.ToLower(after), "example.net") {
				t.Errorf("the store after:\n%s", after)
			}
			for _, name := range []string{"alice:", "bob:", "carol:"} {
				if !strings.Contains(after, name) {
					t.Errorf("%s is gone:\n%s", name, after)
				}
			}
			if errs, err := store.ValidateFile(s.p.StoreFile); err != nil || len(errs) != 0 {
				t.Errorf("the store does not validate: %v %v", errs, err)
			}
			// the second plan has nothing to remove and nothing to warn of
			s.reload()
			s.in.Target = target
			p, err = PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(stepText(p), "email") || strings.Contains(warnText(p), emailWarningTitle) || len(p.EmailUsers()) != 0 {
				t.Errorf("second plan:\n%s\n%s", stepText(p), warnText(p))
			}
		})
	}
}

// Because the 0.2.22 target converts a file now, it has files to convert and
// takes the snapshot when an address stands, and only then.
func TestPlanRollback0222ConvertsOnlyWhenAnAddressStands(t *testing.T) {
	s := newRBSandbox(t)
	rbStoreEmail(t, s)
	s.in.Target = RollbackTarget0222
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if !p.PendingFiles() || !p.NeedsYes() {
		t.Errorf("an address stands: files %v yes %v", p.PendingFiles(), p.NeedsYes())
	}
	if len(p.Keys()) != 0 {
		t.Errorf("keys %q", p.Keys())
	}
	todo := 0
	for _, step := range p.Steps {
		if step.Todo {
			todo++
		}
	}
	if todo != 1 {
		t.Errorf("%d steps do something:\n%s", todo, stepText(p))
	}
	// no address: as before
	s = newRBSandbox(t)
	s.in.Target = RollbackTarget0222
	if p, err = PlanRollback(s.in); err != nil || p.PendingFiles() || p.Pending() || p.NeedsYes() || len(p.EmailUsers()) != 0 {
		t.Errorf("no address: %v %v", p, err)
	}
	// a store of users with none, or no store at all
	st := store.Empty()
	if _, err := store.Write(s.p.StoreFile, st); err != nil {
		t.Fatal(err)
	}
	s.in.HasStore = false
	if p, err = PlanRollback(s.in); err != nil || p.PendingFiles() {
		t.Errorf("no store: %v %v", p, err)
	}
}

// A store that cannot be read refuses the rollback of every target: an
// address that cannot be seen must not be hidden.
func TestPlanRollbackRefusesAnUnreadableStoreForTheEmail(t *testing.T) {
	for _, target := range allRollbackTargets {
		s := newRBSandbox(t)
		s.write(s.p.StoreFile, "version: 1\nusers: [\n", 0o600)
		s.in.Target = target
		_, err := PlanRollback(s.in)
		if err == nil {
			t.Fatalf("%s: planned", target)
		}
		var ref *RollbackRefusal
		if !errors.As(err, &ref) && !strings.Contains(err.Error(), s.p.StoreFile) {
			t.Errorf("%s: %v", target, err)
		}
	}
}

// An address is not a shape the dotted-name or pending-apply checks hide: the
// plan of 0.2.22 and 0.2.21 does not refuse for the older targets' reasons.
func TestPlanRollbackEmailDoesNotChangeWhatRefuses(t *testing.T) {
	s := newRBSandbox(t)
	rbStoreEmail(t, s)
	for _, target := range []string{RollbackTarget0222, RollbackTarget0221, RollbackTarget0220} {
		s.in.Target = target
		if _, err := PlanRollback(s.in); err != nil {
			t.Errorf("%s: %v", target, err)
		}
	}
}
