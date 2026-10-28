package lifecycle

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/store"
)

// rbHash is a bcrypt-shaped hash (hex of '$2b$12$' and 53 letters).
var rbHash = hex.EncodeToString([]byte("$2b$12$" + strings.Repeat("A", 53)))

// rbStoreFlagged writes a store with three flagged users, one of them a
// superuser, and one that is not flagged.
func rbStoreFlagged(t *testing.T, s *rbSandbox) {
	t.Helper()
	st := store.Empty()
	if err := st.ScopeSet("lab", "prefixes=192.0.2.0/24", "secret=example-secret-example-secret"); err != nil {
		t.Fatal(err)
	}
	for _, f := range [][]string{
		{"alice", "group=readonly", "scopes=lab", "hash=" + rbHash, "disabled=false", "password_change_required=true"},
		{"bob", "group=operator", "scopes=lab", "hash=" + rbHash, "disabled=false"},
		{"carol", "group=superuser", "scopes=lab", "hash=" + rbHash, "disabled=false", "password_change_required=true"},
		{"dave", "group=operator", "scopes=lab", "hash=" + rbHash, "disabled=false", "password_change_required=true"},
	} {
		if err := st.UserSet(f[0], f[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Write(s.p.StoreFile, st); err != nil {
		t.Fatal(err)
	}
}

// pwChangeWarningTitle is the warning of the users who regain device access;
// the warning of the users who gain the password cache is another one.
const pwChangeWarningTitle = "Users who must change their password get their device access back"

// The required password change (0.2.20) is a user key every older release
// refuses: every target removes it from the store after the snapshot, names
// the users who regain device access in a warning that --apply needs --yes
// for, leaves a flagged superuser out of the warning (the flag never bound
// one), and keeps every other field.
func TestPlanRollbackRemovesThePasswordChangeAndWarns(t *testing.T) {
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		rbStoreFlagged(t, s)
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: refused: %v", target, err)
		}
		if !p.PendingFiles() || !p.NeedsYes() {
			t.Errorf("%s: files %v, needs yes %v", target, p.PendingFiles(), p.NeedsYes())
		}
		var w string
		for _, x := range p.Warnings {
			if x.Title == pwChangeWarningTitle {
				w = strings.Join(x.Lines, "\n")
			}
		}
		for _, want := range []string{target + " has no required password change (0.2.20): alice, dave are flagged", "off every device", "can log in to the devices with the password",
			"The rendered files are not touched here", "Have them change it first", "stay in the snapshot --apply takes first"} {
			if !strings.Contains(w, want) {
				t.Errorf("%s: the warning lacks %q:\n%s", target, want, w)
			}
		}
		if strings.Contains(w, "carol") || strings.Contains(w, "bob") {
			t.Errorf("%s: the warning names a superuser or an unflagged user:\n%s", target, w)
		}
		st := stepText(p)
		for _, want := range []string{s.p.StoreFile + ": remove the required password change " + target + " does not know",
			"remove password_change_required of alice\n", "remove password_change_required of carol (a superuser: the flag never bound one)", "remove password_change_required of dave\n",
			"unknown field 'password_change_required'"} {
			if !strings.Contains(st, want) {
				t.Errorf("%s: the steps lack %q:\n%s", target, want, st)
			}
		}
		if strings.Contains(st, "remove password_change_required of bob") || strings.Contains(st, "leave "+s.p.StoreFile+" untouched") {
			t.Errorf("%s: the steps:\n%s", target, st)
		}
		if i := strings.Index(st, "leave every other file untouched"); i >= 0 && strings.Contains(st[i:], s.p.StoreFile) {
			t.Errorf("%s: the store is said to be left alone:\n%s", target, st)
		}

		// the dry run changed nothing
		before, _ := os.ReadFile(s.p.StoreFile)
		if !strings.Contains(string(before), "password_change_required: true") {
			t.Fatalf("%s: the dry run touched the store", target)
		}
		done, err := ApplyRollback(p)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if !strings.Contains(strings.Join(done, "\n"), s.p.StoreFile+": removed the required password change of 3 users") {
			t.Errorf("%s: done %q", target, done)
		}
		after, _ := os.ReadFile(s.p.StoreFile)
		for _, name := range []string{"alice:", "bob:", "carol:", "dave:"} {
			if !strings.Contains(string(after), name) {
				t.Errorf("%s: %s is gone:\n%s", target, name, after)
			}
		}
		if strings.Contains(string(after), "password_change_required") || strings.Count(string(after), "group: operator") != 2 {
			t.Errorf("%s: the store after the apply:\n%s", target, after)
		}
		if errs, err := store.ValidateFile(s.p.StoreFile); err != nil || len(errs) != 0 {
			t.Errorf("%s: the store does not validate: %v %v", target, errs, err)
		}
		// the second plan has nothing to remove and nothing to warn of
		s.reload()
		s.in.Target = target
		p, err = PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(stepText(p), "password_change_required") || strings.Contains(warnText(p), pwChangeWarningTitle) {
			t.Errorf("%s: second plan:\n%s\n%s", target, stepText(p), warnText(p))
		}
	}
}

// Only flagged superusers: the key is removed, nothing is warned of.
func TestPlanRollbackWarnsOfNoSuperuserFlag(t *testing.T) {
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget} {
		s := newRBSandbox(t)
		st := store.Empty()
		if err := st.ScopeSet("lab", "prefixes=192.0.2.0/24", "secret=example-secret-example-secret"); err != nil {
			t.Fatal(err)
		}
		if err := st.UserSet("carol", "group=superuser", "scopes=lab", "hash="+rbHash, "disabled=false", "password_change_required=true"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Write(s.p.StoreFile, st); err != nil {
			t.Fatal(err)
		}
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		if !p.PendingFiles() || !strings.Contains(stepText(p), "carol (a superuser") {
			t.Errorf("%s: %s", target, stepText(p))
		}
		for _, x := range p.Warnings {
			if x.Title == pwChangeWarningTitle {
				t.Errorf("%s: %v", target, x)
			}
		}
	}
}

// A store without the key, and an install without a store, add nothing.
func TestPlanRollbackWithoutAPasswordChange(t *testing.T) {
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(stepText(p), "password_change_required") || strings.Contains(warnText(p), "password change") {
			t.Errorf("%s: %s%s", target, stepText(p), warnText(p))
		}
		s.in.HasStore = false
		if p, err = PlanRollback(s.in); err != nil || strings.Contains(stepText(p), "password_change_required") {
			t.Errorf("%s: no store: %v", target, err)
		}
	}
}

// A store that cannot be read refuses the rollback: a flag that cannot be
// seen must not be hidden.
func TestPlanRollbackRefusesAnUnreadableStoreForThePasswordChange(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.StoreFile, "version: 1\nusers: [\n", 0o600)
	s.in.Target = RollbackTarget0218
	_, err := PlanRollback(s.in)
	var ref *RollbackRefusal
	if err == nil {
		t.Fatal("planned")
	}
	// the dotted-name check reads the store first and says so; either word
	// names the file
	if !errors.As(err, &ref) && !strings.Contains(err.Error(), s.p.StoreFile) {
		t.Errorf("%v", err)
	}
}
