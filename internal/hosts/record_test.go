package hosts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// A record is written whole (0600, its directory 0700), read back,
// renamed with its host and removed; a missing one is the empty record.
func TestRecords(t *testing.T) {
	rs := Records{Dir: filepath.Join(t.TempDir(), "hosts")}
	if r, err := rs.Load("web1"); err != nil || r.LastSync != nil || r.Facts != nil {
		t.Fatalf("missing: %+v %v", r, err)
	}
	f := ParseFacts([]byte("login_defs=present\nUID_MAX 60000\nos_PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nsshd=OpenSSH_9.2p1\npam=pam_radius_auth /lib/x86_64-linux-gnu/security/pam_radius_auth.so 2.0.0-1\n"))
	want := Record{
		LastSync: &SyncRecord{At: "2026-10-07T10:00:00Z", By: "alice", Command: "sync", OK: true, Protocol: ScriptProtocol,
			Created: []string{"bob"}, Updated: []string{}, Removed: []string{"carol"}},
		Facts: RecordOfFacts(f, "2026-10-07T10:00:00Z"),
	}
	if err := rs.Save("web1", want); err != nil {
		t.Fatal(err)
	}
	for p, mode := range map[string]os.FileMode{rs.Dir: 0o700, filepath.Join(rs.Dir, "web1.json"): 0o600} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	got, err := rs.Load("web1")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("load: %+v %v", got, err)
	}
	if ff := got.Facts.Facts(); ff.OS() != "Debian GNU/Linux 12 (bookworm)" || ff.Module("pam_radius_auth").Version != "2.0.0-1" || ff.Module("pam_tacplus") != nil {
		t.Errorf("facts: %+v", ff)
	}
	// Update keeps what fn leaves alone; an unreadable record is replaced.
	if err := rs.Update("web1", func(r *Record) { r.LastSync = &SyncRecord{Command: "enroll", Reason: "x"} }); err != nil {
		t.Fatal(err)
	}
	if got, _ := rs.Load("web1"); got.Facts == nil || got.LastSync.Command != "enroll" {
		t.Errorf("update: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(rs.Dir, "web2.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Load("web2"); err == nil {
		t.Error("a broken record loaded")
	}
	if err := rs.Update("web2", func(r *Record) { r.LastSync = &SyncRecord{OK: true} }); err != nil {
		t.Fatal(err)
	}
	if got, err := rs.Load("web2"); err != nil || !got.LastSync.OK {
		t.Errorf("replaced: %+v %v", got, err)
	}
	if err := rs.Rename("web1", "web3"); err != nil {
		t.Fatal(err)
	}
	if got, _ := rs.Load("web3"); got.Facts == nil {
		t.Error("not renamed")
	}
	if err := rs.Rename("ghost", "web4"); err != nil {
		t.Errorf("renaming nothing: %v", err)
	}
	if err := rs.Forget("web3"); err != nil {
		t.Fatal(err)
	}
	if err := rs.Forget("web3"); err != nil {
		t.Errorf("forgetting twice: %v", err)
	}
	entries, _ := os.ReadDir(rs.Dir)
	if len(entries) != 1 || entries[0].Name() != "web2.json" {
		t.Errorf("left: %v", entries)
	}
}

// The facts only shown: os-release, sshd and the PAM modules.
func TestParseSystemFacts(t *testing.T) {
	f := ParseFacts([]byte("ssh_connection=1 2 192.0.2.50 22\nos_NAME=\"AlmaLinux\"\nos_VERSION_ID='9.4'\nsshd=\n" +
		"pam=pam_tacplus /usr/lib64/security/pam_tacplus.so \npam=pam_tacplus /lib/security/pam_tacplus.so 1.6\n"))
	if f.Address != "192.0.2.50" || f.OS() != "AlmaLinux 9.4" || f.SSHD != "" || len(f.PAM) != 1 ||
		f.PAM[0] != (PAMModule{Name: "pam_tacplus", Path: "/usr/lib64/security/pam_tacplus.so"}) {
		t.Errorf("%+v", f)
	}
	if ModuleOf(Radius) != "pam_radius_auth" || ModuleOf(Tacplus) != "pam_tacplus" || ModuleOf("") != "pam_tacplus" {
		t.Error("ModuleOf")
	}
	if !strings.HasSuffix(FactsCommand, SystemFactsCommand) {
		t.Error("FactsCommand does not read the system facts")
	}
}

// The accounts a run reported changing, each once; a created or deleted
// account is not also changed.
func TestAccountChanges(t *testing.T) {
	var b bytes.Buffer
	sw := &summaryWriter{w: &b}
	out := "[INFO] 'alice': home /home/alice is now 0700 (its primary group is shared).\n" +
		"[INFO] Created account 'alice' (superuser).\n" +
		"[INFO] 'bob': renumbered 70001 -> 80001 (files followed)\r\n" +
		"[INFO] 'bob': primary group is now tac-users (was GID 1001).\n" +
		"[INFO] Re-activated account 'dave'.\n" +
		"[INFO] 'erin' has no TACACS+ login here now (disabled): account expired, files kept.\n" +
		"[INFO] Deleted account 'carol': no longer a TACACS+ user here (its UID 80002 stays reserved on the tacctl server, never reused).\n" +
		"[INFO] 'frank': removed from tacctl's groups (tac-users); it is a plain local account again.\n" +
		"[INFO] Accounts: 3 managed by tacctl here.\n"
	if _, err := sw.Write([]byte(out)); err != nil {
		t.Fatal(err)
	}
	want := AccountChanges{Created: []string{"alice"}, Updated: []string{"bob", "dave", "erin"}, Removed: []string{"carol"}}
	if !reflect.DeepEqual(sw.changes, want) || b.String() != out || sw.sum == nil || sw.sum.Managed != 3 {
		t.Errorf("%+v %v", sw.changes, sw.sum)
	}
}

// Only the check's own lines are kept; everything else goes through as it
// comes, a prompt without a newline at once.
func TestCheckWriter(t *testing.T) {
	var b bytes.Buffer
	cw := &checkWriter{w: &b}
	for _, chunk := range []string{"[sudo] password for admin on web1: ", "\r\n", "tacctl-ch", "eck group tac-users 80000\r\n", "tac", "tic\n", "tacctl-check protocol 5\n", "bye"} {
		if _, err := cw.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(chunk, "[sudo]") && b.String() != chunk {
			t.Errorf("prompt held back: %q", b.String())
		}
	}
	cw.flush()
	if b.String() != "[sudo] password for admin on web1: \r\ntactic\nbye" || !reflect.DeepEqual(cw.lines, []string{"group tac-users 80000", "protocol 5"}) {
		t.Errorf("passed %q, kept %q", b.String(), cw.lines)
	}
}

// The check script itself, run here against a sandboxed client state: it
// changes nothing and reports what it finds.
func TestCheckScriptRuns(t *testing.T) {
	r := execx.Real{}
	if _, err := r.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	state, pam, ssh := filepath.Join(dir, "state"), filepath.Join(dir, "pam.d"), filepath.Join(dir, "ssh")
	for _, d := range []string{state, pam, ssh} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(pam, "tacctl-auth"), "auth\n")
	write(filepath.Join(pam, "tacctl-account"), "account\n")
	write(filepath.Join(state, "protocol"), ScriptProtocol+"\n")
	write(filepath.Join(state, "pam.sha256"), "abc  tacctl-auth\ndef  tacctl-account\n")
	write(filepath.Join(ssh, "ssh_host_ed25519_key.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB root@web1\n")
	res, err := r.Run(context.Background(), execx.Cmd{Name: "env", Args: []string{"TACCTL_CLIENT_STATE=" + state, "TACCTL_CLIENT_PAM_DIR=" + pam,
		"TACCTL_CLIENT_SSH_DIR=" + ssh, "bash", "-c", CheckScript([]string{"tacctl-no-such-user"})}})
	out := res.Stdout
	if err != nil || res.Code != 0 {
		t.Fatalf("%v %d: %s%s", err, res.Code, out, res.Stderr)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		rest, ok := strings.CutPrefix(l, checkPrefix)
		if !ok {
			t.Errorf("a line not the check's: %q", l)
		}
		lines = append(lines, rest)
	}
	st := ParseCheck(lines)
	sum := sha256.Sum256([]byte("auth\n"))
	if st.Accounts["tacctl-no-such-user"].Exists || st.Protocol != ScriptProtocol ||
		st.PAM["tacctl-auth"] != hex.EncodeToString(sum[:]) || st.PAM["tacctl-session"] != "" || st.PAMWritten["tacctl-account"] != "def" ||
		string(st.Keys) != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB root@web1\n" {
		t.Errorf("%+v\n%s", st, out)
	}
}

// ParseCheck: an account line with a home holding spaces, a missing one.
func TestParseCheck(t *testing.T) {
	st := ParseCheck([]string{"account alice 80000 80000 700 /home/a b", "account bob", "group tac-users 80000", "pam tacctl-session -", "protocol "})
	if st.Accounts["alice"] != (AccountState{Exists: true, UID: "80000", GID: "80000", HomeMode: "700", Home: "/home/a b"}) ||
		st.Accounts["bob"].Exists || st.Groups["tac-users"] != "80000" || st.PAM["tacctl-session"] != "" || st.Protocol != "" {
		t.Errorf("%+v", st)
	}
	if GroupGID("tac-superuser", DefaultRange) != 80002 || GroupGID("wheel", DefaultRange) != 0 ||
		!reflect.DeepEqual(HostGroups(false), []string{"tac-users", "tac-superuser"}) || len(HostGroups(true)) != len(TacGroups) {
		t.Error("groups")
	}
}
