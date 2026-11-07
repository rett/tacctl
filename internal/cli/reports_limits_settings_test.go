package cli

import (
	"os"
	"testing"

	"github.com/rett/tacctl/internal/reports"
)

// effective is effectiveReportLimits of user on a fresh invocation of the
// sandbox's state.
func effective(sb *sandbox, user string) (int64, int) {
	sb.t.Helper()
	inv, _ := sb.auditInv([]string{"user", "list"}, "SUDO_USER=alice", "SUDO_UID=1001")
	return inv.effectiveReportLimits(user)
}

// The user's own limit wins over the global setting, which wins over the
// default; each limit is decided on its own, and 0 is a value.
func TestEffectiveReportLimits(t *testing.T) {
	const mib = 1 << 20
	steps := []struct {
		name string
		do   [][]string
		// the limits of alice (no override), bob (size and count), carol (count
		// only) and a user the store does not have
		alice, bob, carol, nobody [2]int64
	}{
		{"defaults", nil,
			[2]int64{reports.DefaultMaxSize, reports.DefaultMaxCount}, [2]int64{reports.DefaultMaxSize, reports.DefaultMaxCount},
			[2]int64{reports.DefaultMaxSize, reports.DefaultMaxCount}, [2]int64{reports.DefaultMaxSize, reports.DefaultMaxCount}},
		{"global settings", [][]string{{"config", "reports", "max-size", "5Mi"}, {"config", "reports", "max-count", "30"}},
			[2]int64{5 * mib, 30}, [2]int64{5 * mib, 30}, [2]int64{5 * mib, 30}, [2]int64{5 * mib, 30}},
		{"overrides win", [][]string{{"user", "reports-limit", "bob", "max-size", "1Ki"}, {"user", "reports-limit", "bob", "max-count", "7"},
			{"user", "reports-limit", "carol", "max-count", "0"}},
			[2]int64{5 * mib, 30}, [2]int64{1024, 7}, [2]int64{5 * mib, 0}, [2]int64{5 * mib, 30}},
		{"global no cap, an override still caps", [][]string{{"config", "reports", "max-size", "0"}, {"config", "reports", "max-count", "0"}},
			[2]int64{0, 0}, [2]int64{1024, 7}, [2]int64{0, 0}, [2]int64{0, 0}},
		{"an override of no cap under a global cap", [][]string{{"config", "reports", "max-size", "2Mi"}, {"config", "reports", "max-count", "9"},
			{"user", "reports-limit", "alice", "max-size", "0"}},
			[2]int64{0, 9}, [2]int64{1024, 7}, [2]int64{2 * mib, 0}, [2]int64{2 * mib, 9}},
		{"clear returns to the global value", [][]string{{"user", "reports-limit", "bob", "max-size", "clear"}, {"user", "reports-limit", "carol", "clear"}},
			[2]int64{0, 9}, [2]int64{2 * mib, 7}, [2]int64{2 * mib, 9}, [2]int64{2 * mib, 9}},
		{"clear both", [][]string{{"user", "reports-limit", "bob", "clear"}, {"user", "reports-limit", "alice", "clear"}},
			[2]int64{2 * mib, 9}, [2]int64{2 * mib, 9}, [2]int64{2 * mib, 9}, [2]int64{2 * mib, 9}},
	}
	sb := newSandbox(t, true)
	for _, st := range steps {
		for _, args := range st.do {
			sb.asAlice("", args...)
			sb.expect(0, "", "")
		}
		for user, want := range map[string][2]int64{"alice": st.alice, "bob": st.bob, "carol": st.carol, "nobody": st.nobody} {
			if size, count := effective(sb, user); size != want[0] || int64(count) != want[1] {
				t.Errorf("%s: %s = %d, %d; want %d, %d", st.name, user, size, count, want[0], want[1])
			}
		}
	}
}

// A hand-edited setting the schema refuses reads as the default, and a store
// that is not there leaves the global value.
func TestEffectiveReportLimitsFallBack(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "reports:\n  max_size: -5\n  max_count: 999999\n", 0o600)
	if size, count := effective(sb, "alice"); size != reports.DefaultMaxSize || count != reports.DefaultMaxCount {
		t.Errorf("bad settings: %d, %d", size, count)
	}
	sb.write("state/tacctl.yaml", "reports:\n  max_size: 3145728\n  max_count: 12\n", 0o600)
	sb = withoutStore(t, sb)
	if size, count := effective(sb, "alice"); size != 3<<20 || count != 12 {
		t.Errorf("no store: %d, %d", size, count)
	}
}

// withoutStore removes the sandbox's store file.
func withoutStore(t *testing.T, sb *sandbox) *sandbox {
	t.Helper()
	if err := os.Remove(sb.path("state", "store.yaml")); err != nil {
		t.Fatal(err)
	}
	return sb
}
