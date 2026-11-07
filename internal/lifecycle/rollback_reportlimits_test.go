package lifecycle

import (
	"errors"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/store"
)

// rbStoreLimits writes a store with three users, two of them with limits of
// the stored reports of their own (carol's is no cap).
func rbStoreLimits(t *testing.T, s *rbSandbox, withEmail bool) {
	t.Helper()
	st := store.Empty()
	if err := st.ScopeSet("lab", "prefixes=192.0.2.0/24", "secret=example-secret-example-secret"); err != nil {
		t.Fatal(err)
	}
	rows := [][]string{
		{"alice", "group=superuser", "scopes=lab", "hash=" + rbHash, "disabled=false", "reports_max_size=20971520", "reports_max_count=50"},
		{"bob", "group=operator", "scopes=lab", "hash=" + rbHash, "disabled=false"},
		{"carol", "group=readonly", "scopes=lab", "hash=" + rbHash, "disabled=false", "reports_max_count=0"},
	}
	if withEmail {
		rows[1] = append(rows[1], "email=bob@example.net")
	}
	for _, f := range rows {
		if err := st.UserSet(f[0], f[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Write(s.p.StoreFile, st); err != nil {
		t.Fatal(err)
	}
}

const limitsWarningTitle = "Limits of the stored reports are removed from the store"

// The users' own limits (0.2.26) are store keys every older release refuses,
// so every target removes them after the snapshot, names each user with the
// values in a warning that --apply needs --yes for, and keeps the rest.
func TestPlanRollbackEveryTargetRemovesTheUsersReportLimits(t *testing.T) {
	for _, target := range targetsBefore0226 {
		t.Run(target, func(t *testing.T) {
			s := newRBSandbox(t)
			s.oldSyntaxKey()
			rbStoreLimits(t, s, false)
			s.in.Target = target
			before := s.snapshotOf()
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if !p.PendingFiles() || !p.Pending() || !p.NeedsYes() {
				t.Errorf("files %v pending %v needs yes %v", p.PendingFiles(), p.Pending(), p.NeedsYes())
			}
			if got := strings.Join(p.ReportLimitUsers(), "; "); got != "alice: max-size 20 MiB, max-count 50 reports; carol: max-count no cap" {
				t.Errorf("limit users %q", got)
			}
			if got := strings.Join(p.ReportLimitUserNames(), ","); got != "alice,carol" {
				t.Errorf("limit user names %q", got)
			}
			var w string
			for _, x := range p.Warnings {
				if x.Title == limitsWarningTitle {
					w = strings.Join(x.Lines, "\n")
				}
			}
			for _, want := range []string{target + " has no limit of the stored reports (0.2.26): alice (max-size 20 MiB, max-count 50 reports), carol (max-count no cap) have an own limit",
				"The values stay in the snapshot --apply takes first", "tacctl user reports-limit <user> max-size|max-count <value>"} {
				if !strings.Contains(w, want) {
					t.Errorf("the warning lacks %q:\n%s", want, w)
				}
			}
			st := stepText(p)
			for _, want := range []string{s.p.StoreFile + ": remove the limits of the stored reports " + target + " does not know",
				"remove the report limits of alice (max-size 20 MiB, max-count 50 reports)\n", "remove the report limits of carol (max-count no cap)\n",
				"unknown field 'reports_max_size'"} {
				if !strings.Contains(st, want) {
					t.Errorf("the steps lack %q:\n%s", want, st)
				}
			}
			if strings.Contains(st, "limits of bob") || strings.Contains(st, "leave "+s.p.StoreFile+" untouched") {
				t.Errorf("the steps:\n%s", st)
			}
			if i := strings.Index(st, "leave every other file untouched"); i >= 0 && strings.Contains(st[i:], s.p.StoreFile) {
				t.Errorf("the store is said to be left alone:\n%s", st)
			}
			if after := s.snapshotOf(); !equalFiles(before, after) {
				t.Error("the plan wrote a file")
			}

			done, err := ApplyRollback(p)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(done, "\n"), s.p.StoreFile+": removed the report limits of 2 users") {
				t.Errorf("done %q", done)
			}
			after := string(mustRead(t, s.p.StoreFile))
			if strings.Contains(after, "reports_max") {
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
			if strings.Contains(stepText(p), "report limits") || strings.Contains(warnText(p), limitsWarningTitle) || len(p.ReportLimitUsers()) != 0 {
				t.Errorf("second plan:\n%s\n%s", stepText(p), warnText(p))
			}
		})
	}
}

// Without an own limit nothing is added: the 0.2.24 and 0.2.23 targets
// convert no file, and no --yes is needed (the settings of the file are a note
// at most, not a warning).
func TestPlanRollbackWithoutUsersReportLimitsAddsNothing(t *testing.T) {
	for _, target := range targetsBefore0226 {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		rbStoreEmail(t, s) // a store whose users have other keys
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if len(p.ReportLimitUsers()) != 0 || strings.Contains(warnText(p), limitsWarningTitle) || strings.Contains(stepText(p), "report limits") {
			t.Errorf("%s: the plan names limits:\n%s\n%s", target, stepText(p), warnText(p))
		}
	}
	for _, target := range []string{RollbackTarget0224, RollbackTarget0223} {
		s := newRBSandbox(t)
		s.in.Target = target
		if p, err := PlanRollback(s.in); err != nil || p.PendingFiles() || p.NeedsYes() {
			t.Errorf("%s: nothing set: %v %v", target, p, err)
		}
	}
}

// The limits and the addresses together: both steps are there, in the order of
// the plan, and one apply removes both from the store.
func TestPlanRollbackReportLimitsAndEmailTogether(t *testing.T) {
	for _, target := range []string{RollbackTarget0224, RollbackTarget0222, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		rbStoreLimits(t, s, true)
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		st := stepText(p)
		hasEmail := target != RollbackTarget0224 // 0.2.24 has the address
		if hasEmail != strings.Contains(st, "remove the email addresses") || !strings.Contains(st, "remove the report limits of alice") {
			t.Errorf("%s: steps:\n%s", target, st)
		}
		if strings.Count(st, s.p.StoreFile+": remove ") != map[bool]int{true: 2, false: 1}[hasEmail] {
			t.Errorf("%s: the store is converted by the wrong number of steps:\n%s", target, st)
		}
		if _, err := ApplyRollback(p); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		after := string(mustRead(t, s.p.StoreFile))
		if strings.Contains(after, "reports_max") || (hasEmail && strings.Contains(after, "email")) || (!hasEmail && !strings.Contains(after, "email")) {
			t.Errorf("%s: store after:\n%s", target, after)
		}
	}
}

// A store that cannot be read refuses the rollback of every target.
func TestPlanRollbackRefusesAnUnreadableStoreForTheReportLimits(t *testing.T) {
	for _, target := range targetsBefore0226 {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
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
