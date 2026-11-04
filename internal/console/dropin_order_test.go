package console

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// lockdownDropIn is the text of the drop-in the client script writes while a
// scope is locked down (config/linux/client-install.sh, lockdown_text): the
// test holds that file's order against the two the server writes, not the
// script's text, which the bats suite runs.
const lockdownDropIn = `Match Group tac-users,!tac-superuser
    PubkeyAuthentication no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    AllowAgentForwarding no
`

// S1 of the review of WP10.2g: sshd reads the files of sshd_config.d in name
// order and takes the first value of a keyword, across Match blocks. The
// engineer drop-in has to come first, or a console forwarding tier beats the
// engineer lockdown for an account that is in both groups (a failed
// 'gpasswd -d' from tac-superuser, an NSS group).

// patternList is sshd's pattern-list for Match Group: the comma-separated
// patterns match when one positive pattern names a group of the account and
// no negated one does.
func patternList(list string, groups []string) bool {
	has := func(g string) bool {
		for _, x := range groups {
			if x == g {
				return true
			}
		}
		return false
	}
	matched := false
	for _, p := range strings.Split(list, ",") {
		if g, neg := strings.CutPrefix(p, "!"); neg {
			if has(g) {
				return false
			}
		} else if has(p) {
			matched = true
		}
	}
	return matched
}

// firstWins evaluates the drop-ins the way sshd does for an account in
// groups: the files in name order, the blocks whose Match lines all hold,
// the first value of each keyword. It knows only the shapes tacctl writes
// (Match Group g [Group h]... and Match User u, and keyword value lines). A
// member of groups written "user=name" is not a group but the account's
// name, which Match User compares.
func firstWins(files map[string]string, groups ...string) map[string]string {
	account := ""
	for i := 0; i < len(groups); i++ {
		if n, ok := strings.CutPrefix(groups[i], "user="); ok {
			account = n
			groups = append(groups[:i:i], groups[i+1:]...)
			i--
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	got := map[string]string{}
	for _, n := range names {
		active := true
		for _, l := range strings.Split(files[n], "\n") {
			f := strings.Fields(l)
			if len(f) == 0 || strings.HasPrefix(f[0], "#") {
				continue
			}
			if strings.EqualFold(f[0], "Match") {
				active = true
				for i := 1; i+1 < len(f); i += 2 {
					switch {
					case strings.EqualFold(f[i], "Group"):
						active = active && patternList(f[i+1], groups)
					case strings.EqualFold(f[i], "User"):
						active = active && account != "" && patternList(f[i+1], []string{account})
					default:
						active = false
					}
				}
				continue
			}
			if !active || len(f) < 2 {
				continue
			}
			k := strings.ToLower(f[0])
			if _, ok := got[k]; !ok {
				got[k] = strings.Join(f[1:], " ")
			}
		}
	}
	return got
}

func TestDropInsSortEngineerFirst(t *testing.T) {
	p := paths.Resolve(paths.NewEnv(nil), "", nil)
	cn, en := filepath.Base(p.SSHDDropIn), filepath.Base(p.SSHDEngineerDropIn)
	if filepath.Dir(p.SSHDDropIn) != filepath.Dir(p.SSHDEngineerDropIn) {
		t.Fatalf("the two drop-ins are in different directories: %s %s", p.SSHDDropIn, p.SSHDEngineerDropIn)
	}
	if en >= cn {
		t.Fatalf("sshd reads %s before %s: the engineer drop-in must sort first", cn, en)
	}
	names := []string{cn, en}
	sort.Strings(names)
	if names[0] != en {
		t.Fatalf("sorted: %v", names)
	}
	for _, agent := range []bool{false, true} {
		files := map[string]string{
			cn: DropIn(testConsole, agent, true, []tier.Tier{tier.Superuser, tier.Operator}, nil),
			en: EngineerDropIn(agent),
		}
		// An engineer with the console that is also still in tac-superuser.
		got := firstWins(files, Group, tier.EngineerGroup, tier.SuperuserGroup)
		for k, want := range map[string]string{
			"allowtcpforwarding": "no", "x11forwarding": "no", "allowstreamlocalforwarding": "no",
			"permittunnel": "no", "gatewayports": "no", "forcecommand": testConsole,
		} {
			if got[k] != want {
				t.Errorf("agent=%v: %s = %q, want %q (engineer and tac-superuser together)", agent, k, got[k], want)
			}
		}
		if !agent && got["disableforwarding"] != "yes" {
			t.Errorf("disableforwarding = %q", got["disableforwarding"])
		}
		// A superuser who is not an engineer still gets the forwarding tier.
		if got := firstWins(files, Group, tier.SuperuserGroup); got["allowtcpforwarding"] != "yes" {
			t.Errorf("agent=%v: the superuser's console forwarding is gone: %v", agent, got)
		}
		// The control: under the old name the console's block wins.
		old := map[string]string{cn: files[cn], filepath.Base(p.SSHDEngineerDropInOld): files[en]}
		if firstWins(old, Group, tier.EngineerGroup, tier.SuperuserGroup)["allowtcpforwarding"] != "yes" {
			t.Errorf("agent=%v: the evaluator does not show the old name losing", agent)
		}
	}
}

// sshdHas reports whether the output of 'sshd -T' holds the line "keyword
// value": the keyword is compared without regard to case (OpenSSH 10.6 prints
// AllowTcpForwarding where earlier releases printed allowtcpforwarding), the
// value exactly.
func sshdHas(out, line string) bool {
	kw, val, _ := strings.Cut(line, " ")
	for _, l := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(l, " ")
		if strings.EqualFold(k, kw) && v == val {
			return true
		}
	}
	return false
}

// The same with sshd itself ('sshd -T -f ... -C'), where the machine has
// one: the three group names are replaced by a group of the account running
// the test, because a Match Group needs a group sshd can resolve for a real
// account.
func TestDropInsSortEngineerFirstInSshd(t *testing.T) {
	run := execx.Real{}
	sshd, err := run.LookPath("sshd")
	if err != nil {
		sshd = "/usr/sbin/sshd"
		if _, serr := os.Stat(sshd); serr != nil {
			t.Skip("no sshd on this machine")
		}
	}
	keygen, err := run.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no ssh-keygen on this machine")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skip("no primary group")
	}
	dir := t.TempDir()
	if res, err := run.Run(context.Background(), execx.Cmd{Name: keygen, Args: []string{"-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "hostkey")}}); err != nil || res.Code != 0 {
		t.Skipf("ssh-keygen: %v %d %s", err, res.Code, res.Stderr)
	}
	p := paths.Resolve(paths.NewEnv(nil), "", nil)
	d := filepath.Join(dir, "sshd_config.d")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	own := strings.NewReplacer(Group, g.Name, tier.EngineerGroup, g.Name, tier.SuperuserGroup, g.Name)
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(d, name), []byte(own.Replace(text)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfg, []byte("HostKey "+filepath.Join(dir, "hostkey")+"\nInclude "+d+"/*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eval := func() (string, bool) {
		res, err := run.Run(context.Background(), execx.Cmd{Name: sshd, Args: []string{"-T", "-f", cfg, "-C", "user=" + u.Username + ",host=h,addr=127.0.0.1"}})
		out := string(res.Stdout) + string(res.Stderr)
		return out, err == nil && res.Code == 0
	}
	write(filepath.Base(p.SSHDDropIn), DropIn(testConsole, false, false, []tier.Tier{tier.Superuser}, nil))
	write(filepath.Base(p.SSHDEngineerDropIn), EngineerDropIn(false))
	out, ok := eval()
	if !ok {
		t.Skipf("sshd -T cannot run here: %s", out)
	}
	for _, want := range []string{"allowtcpforwarding no", "x11forwarding no", "permittunnel no", "gatewayports no"} {
		if !sshdHas(out, want) {
			t.Errorf("sshd -T lacks %q with the engineer drop-in first:\n%s", want, out)
		}
	}
	// The control: under the old name the console's tier block wins, which
	// is what the rename fixes.
	if err := os.Remove(filepath.Join(d, filepath.Base(p.SSHDEngineerDropIn))); err != nil {
		t.Fatal(err)
	}
	write(filepath.Base(p.SSHDEngineerDropInOld), EngineerDropIn(false))
	if out, _ := eval(); !sshdHas(out, "allowtcpforwarding yes") {
		t.Errorf("under the old name the console's forwarding tier was expected to win (the control):\n%s", out)
	}
}

// The lockdown drop-in of an enrolled host is the first file sshd reads,
// before the engineer tier's and the console's: the first value of a keyword
// wins across Match blocks, so an engineer whose drop-in lets agent
// forwarding through (console agent-forwarding) still has it closed, and so
// has an account of a tier the console lets forward. A name that began 000-
// would sort after 00-tacctl-engineer.conf in the byte order.
func TestLockdownDropInSortsFirst(t *testing.T) {
	p := paths.Resolve(paths.NewEnv(nil), "", nil)
	cn, en, ld := filepath.Base(p.SSHDDropIn), filepath.Base(p.SSHDEngineerDropIn), paths.SSHDLockdownDropInName
	if ld >= en || ld >= cn {
		t.Fatalf("the lockdown drop-in %s must sort before %s and %s", ld, en, cn)
	}
	if "000-tacctl-lockdown.conf" < en {
		t.Fatal("the control: a 000- name was expected to sort after the engineer's")
	}
	for _, agent := range []bool{false, true} {
		files := map[string]string{
			cn: DropIn(testConsole, agent, true, []tier.Tier{tier.Superuser, tier.Operator, tier.Readonly}, nil),
			en: EngineerDropIn(agent),
			ld: lockdownDropIn,
		}
		// A non-superuser of a tier the console lets forward, and an engineer.
		for _, member := range [][]string{{Group, "tac-users", tier.OperatorGroup}, {Group, "tac-users", tier.EngineerGroup}} {
			got := firstWins(files, member...)
			for _, k := range []string{"allowtcpforwarding", "x11forwarding", "allowstreamlocalforwarding", "allowagentforwarding", "pubkeyauthentication"} {
				if got[k] != "no" {
					t.Errorf("agent=%v %v: %s = %q, want no with the lockdown", agent, member, k, got[k])
				}
			}
		}
		// Without the lockdown file the same account is as before.
		delete(files, ld)
		if got := firstWins(files, Group, "tac-users", tier.OperatorGroup); got["allowtcpforwarding"] != "yes" {
			t.Errorf("agent=%v: the control: without the lockdown the operator tier forwards: %v", agent, got)
		}
	}
}

// The same with sshd itself where the machine has one: the lockdown drop-in
// is read first, so the account it matches has agent forwarding and the other
// keywords closed although the engineer's drop-in (agent forwarding on) and
// the console's tier block (forwarding on) come after it, and the keys of an
// account it does not match (a member of the negated group) are as before.
func TestLockdownDropInInSshd(t *testing.T) {
	run := execx.Real{}
	sshd, err := run.LookPath("sshd")
	if err != nil {
		sshd = "/usr/sbin/sshd"
		if _, serr := os.Stat(sshd); serr != nil {
			t.Skip("no sshd on this machine")
		}
	}
	keygen, err := run.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no ssh-keygen on this machine")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skip("no primary group")
	}
	dir := t.TempDir()
	if res, err := run.Run(context.Background(), execx.Cmd{Name: keygen, Args: []string{"-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "hostkey")}}); err != nil || res.Code != 0 {
		t.Skipf("ssh-keygen: %v %d %s", err, res.Code, res.Stderr)
	}
	p := paths.Resolve(paths.NewEnv(nil), "", nil)
	d := filepath.Join(dir, "sshd_config.d")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	// The account's own group stands for tac-users, tac-engineer and
	// tac-console; tac-superuser stays a group the account is not in.
	own := strings.NewReplacer(Group, g.Name, tier.EngineerGroup, g.Name, "tac-users", g.Name)
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(d, name), []byte(own.Replace(text)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfg, []byte("HostKey "+filepath.Join(dir, "hostkey")+"\nInclude "+d+"/*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eval := func() (string, bool) {
		res, err := run.Run(context.Background(), execx.Cmd{Name: sshd, Args: []string{"-T", "-f", cfg, "-C", "user=" + u.Username + ",host=h,addr=127.0.0.1"}})
		return string(res.Stdout) + string(res.Stderr), err == nil && res.Code == 0
	}
	write(filepath.Base(p.SSHDDropIn), DropIn(testConsole, true, false, []tier.Tier{tier.Superuser, tier.Engineer}, nil))
	write(filepath.Base(p.SSHDEngineerDropIn), EngineerDropIn(true))
	before, ok := eval()
	if !ok {
		t.Skipf("sshd -T cannot run here: %s", before)
	}
	if !sshdHas(before, "allowagentforwarding yes") {
		t.Fatalf("the control: agent forwarding should be on before the lockdown:\n%s", before)
	}
	write(paths.SSHDLockdownDropInName, lockdownDropIn)
	out, _ := eval()
	for _, want := range []string{"pubkeyauthentication no", "allowtcpforwarding no", "allowstreamlocalforwarding no", "x11forwarding no", "allowagentforwarding no"} {
		if !sshdHas(out, want) {
			t.Errorf("sshd -T lacks %q with the lockdown drop-in:\n%s", want, out)
		}
	}
	// A member of tac-superuser (the negated group) is as before.
	su := strings.NewReplacer("tac-superuser", g.Name)
	if err := os.WriteFile(filepath.Join(d, paths.SSHDLockdownDropInName), []byte(own.Replace(su.Replace(lockdownDropIn))), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, _ := eval(); out != before {
		t.Errorf("an account of the negated group changed under the lockdown:\n%s\nwas\n%s", out, before)
	}
}

// A user held to a password change forwards nothing although the tier they are
// in may: the console's own file lists them in a block before the tier blocks,
// and the engineer's and the lockdown's files come before that, so neither can
// open what it closes. An account that is not listed is as before, and so is
// the list when it is empty.
func TestHeldBeatsForwardingTiers(t *testing.T) {
	p := paths.Resolve(paths.NewEnv(nil), "", nil)
	cn, en, ld := filepath.Base(p.SSHDDropIn), filepath.Base(p.SSHDEngineerDropIn), paths.SSHDLockdownDropInName
	for _, agent := range []bool{false, true} {
		for _, gateway := range []bool{false, true} {
			files := map[string]string{
				cn: DropIn(testConsole, agent, gateway, []tier.Tier{tier.Superuser, tier.Operator, tier.Engineer}, []string{"alice", "carol"}),
				en: EngineerDropIn(agent),
				ld: lockdownDropIn,
			}
			// The lockdown file belongs to an enrolled host and matches tac-users
			// but for tac-superuser; it is read first, and the held block still
			// closes what it leaves open. The server has the file when it is
			// enrolled as a host of its own: the last two members.
			for _, member := range [][]string{
				{Group, tier.OperatorGroup, "user=alice"},              // a forwarding tier, held
				{Group, tier.SuperuserGroup, "user=alice"},             // the default tier, held
				{Group, tier.EngineerGroup, "user=carol"},              // an engineer, held
				{Group, "tac-users", tier.OperatorGroup, "user=alice"}, // held, and matched by the lockdown file
				{Group, "tac-users", tier.EngineerGroup, "user=carol"},
			} {
				got := firstWins(files, member...)
				for k, want := range map[string]string{
					"disableforwarding": "yes", "allowtcpforwarding": "no", "x11forwarding": "no", "allowstreamlocalforwarding": "no",
					"allowagentforwarding": "no", "permittunnel": "no", "gatewayports": "no", "forcecommand": testConsole,
				} {
					if agent && member[1] == tier.EngineerGroup && k == "allowagentforwarding" {
						// the engineer's file, read first, sets AllowAgentForwarding
						// yes and no DisableForwarding: the held block's
						// DisableForwarding yes is what closes the agent
						continue
					}
					if got[k] != want {
						t.Errorf("agent=%v gateway=%v %v: %s = %q, want %q", agent, gateway, member, k, got[k], want)
					}
				}
			}
			// not listed: as before
			for _, member := range [][]string{{Group, tier.OperatorGroup, "user=bob"}, {Group, tier.SuperuserGroup, "user=bob"}} {
				if got := firstWins(files, member...); got["allowtcpforwarding"] != "yes" || got["x11forwarding"] != "yes" || got["disableforwarding"] != "no" {
					t.Errorf("agent=%v gateway=%v %v: an unlisted user lost the tier's forwarding: %v", agent, gateway, member, got)
				}
			}
		}
	}
	// the control: with no held user a listed name is an ordinary one
	files := map[string]string{cn: DropIn(testConsole, false, false, []tier.Tier{tier.Operator}, nil), en: EngineerDropIn(false)}
	if got := firstWins(files, Group, tier.OperatorGroup, "user=alice"); got["allowtcpforwarding"] != "yes" {
		t.Errorf("the control: without the block the operator tier forwards: %v", got)
	}
}

// The same with sshd itself where the machine has one ('sshd -T -C user=...'):
// a user in the drop-in's list has DisableForwarding yes and every forwarding
// closed although the account's own group is in a forwarding tier; a user
// that is not listed (a name sshd does not know, but for the Match User line
// that is all there is to compare) keeps what the tier gives; and an empty
// list writes no block.
func TestHeldForwardingInSshd(t *testing.T) {
	run := execx.Real{}
	sshd, err := run.LookPath("sshd")
	if err != nil {
		sshd = "/usr/sbin/sshd"
		if _, serr := os.Stat(sshd); serr != nil {
			t.Skip("no sshd on this machine")
		}
	}
	keygen, err := run.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no ssh-keygen on this machine")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skip("no primary group")
	}
	dir := t.TempDir()
	if res, err := run.Run(context.Background(), execx.Cmd{Name: keygen, Args: []string{"-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "hostkey")}}); err != nil || res.Code != 0 {
		t.Skipf("ssh-keygen: %v %d %s", err, res.Code, res.Stderr)
	}
	p := paths.Resolve(paths.NewEnv(nil), "", nil)
	d := filepath.Join(dir, "sshd_config.d")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	// The account's own group stands for tac-console and tac-superuser (the
	// account is no engineer); the example name alice stands for the
	// account's name.
	own := strings.NewReplacer(Group, g.Name, tier.SuperuserGroup, g.Name, "alice", u.Username)
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(d, name), []byte(own.Replace(text)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfg, []byte("HostKey "+filepath.Join(dir, "hostkey")+"\nInclude "+d+"/*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eval := func() (string, bool) {
		res, err := run.Run(context.Background(), execx.Cmd{Name: sshd, Args: []string{"-T", "-f", cfg, "-C", "user=" + u.Username + ",host=h,addr=127.0.0.1"}})
		return string(res.Stdout) + string(res.Stderr), err == nil && res.Code == 0
	}
	cn := filepath.Base(p.SSHDDropIn)
	for _, agent := range []bool{false, true} {
		fwd := []tier.Tier{tier.Superuser}
		write(cn, DropIn(testConsole, agent, false, fwd, nil))
		write(filepath.Base(p.SSHDEngineerDropIn), EngineerDropIn(agent))
		none, ok := eval()
		if !ok {
			t.Skipf("sshd -T cannot run here: %s", none)
		}
		// the control: nobody held, the account forwards through its tier
		for _, want := range []string{"allowtcpforwarding yes", "x11forwarding yes", "disableforwarding no"} {
			if !sshdHas(none, want) {
				t.Errorf("agent=%v: the control lacks %q with nobody held:\n%s", agent, want, none)
			}
		}
		// listed: closed, ahead of the tier block
		write(cn, DropIn(testConsole, agent, false, fwd, []string{"alice", "bob"}))
		out, ok := eval()
		if !ok {
			t.Fatalf("sshd refuses the drop-in with a held block:\n%s", out)
		}
		for _, want := range []string{"disableforwarding yes", "allowtcpforwarding no", "allowstreamlocalforwarding no", "x11forwarding no",
			"allowagentforwarding no", "permittunnel no", "gatewayports no", "forcecommand " + testConsole} {
			if !sshdHas(out, want) {
				t.Errorf("agent=%v: sshd -T lacks %q for a held user:\n%s", agent, want, out)
			}
		}
		// listed, but another name: as the control
		write(cn, DropIn(testConsole, agent, false, fwd, []string{"bob", "carol"}))
		if out, _ := eval(); !sshdHas(out, "allowtcpforwarding yes") || !sshdHas(out, "disableforwarding no") {
			t.Errorf("agent=%v: a user that is not held lost the tier's forwarding:\n%s", agent, out)
		}
	}
}
