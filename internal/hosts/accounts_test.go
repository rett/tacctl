package hosts

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/assets"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/ui"
)

// What 'getent passwd' prints on the host of these tests: dave and erin
// are tacctl's accounts of removed users; fred is a current user; gus has a
// tacctl full name but no UID from this server; carl is a local account;
// olaf has a UID outside the range; hank's home is not under /home; ivy was
// named by a release before 0.1.16 and still has the legacy UID it was
// given (the script renumbers it, then deletes it).
const hostPasswd = `root:x:0:0:root:/root:/bin/bash
dave:x:80001:80001:dave (TACACS+):/home/dave:/bin/bash
erin:x:80002:80002:erin (RADIUS):/home/erin:/bin/bash
fred:x:80003:80003:fred (TACACS+):/home/fred:/bin/bash
gus:x:80009:80009:gus (TACACS+):/home/gus:/bin/bash
carl:x:1001:1001:Carl:/home/carl:/bin/bash
olaf:x:1500:1500:olaf (TACACS+):/home/olaf:/bin/bash
hank:x:80004:80004:hank (TACACS+):/srv/hank:/bin/bash
ivy:x:20005:20005:TACACS+ user (tacctl):/home/ivy:/bin/bash
not a passwd line
`

func accountsEnv(t *testing.T) (*Env, *fake.Runner) {
	t.Helper()
	e, _, _ := testEnv(t)
	writeFile(t, e.Paths.UIDs, "dave:80001\nerin:80002\nfred:80003\nolaf:1500\nhank:80004\nivy:80005\n")
	f := &fake.Runner{}
	f.Func(func(c execx.Cmd) bool {
		return strings.HasSuffix(strings.Join(c.Args, " "), "getent passwd") || c.Name == "getent"
	},
		func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(hostPasswd)}, nil })
	e.Runner = f
	return e, f
}

func TestParsePasswdAndRemoved(t *testing.T) {
	accts := ParsePasswd(hostPasswd)
	if len(accts) != 9 || accts[1] != (Account{Name: "dave", UID: "80001", GECOS: "dave (TACACS+)", Home: "/home/dave"}) {
		t.Fatalf("parsed %+v", accts)
	}
	e, _ := accountsEnv(t)
	got, err := Removed(accts, UIDs{Path: e.Paths.UIDs}, map[string]bool{"fred": true})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range got {
		names = append(names, a.Name)
	}
	if strings.Join(names, ",") != "dave,erin,ivy" {
		t.Errorf("removed %q", names)
	}
}

func TestHomesToDelete(t *testing.T) {
	e, f := accountsEnv(t)
	current := map[string]bool{"fred": true}
	var asked []string
	answers := map[string]string{"dave": "y", "erin": "no", "ivy": " YES "}
	ask := func(p string) string {
		asked = append(asked, p)
		for n, a := range answers {
			if strings.Contains(p, "'"+n+"'") {
				return a
			}
		}
		return ""
	}
	got, err := e.HomesToDelete(context.Background(), "web1", "admin@web1", "2222", "", current, ask)
	if err != nil || strings.Join(got, " ") != "dave ivy" {
		t.Fatalf("homes %q %v", got, err)
	}
	if strings.Join(asked, "|") != "Delete /home/dave of removed user 'dave'? [y/N] |Delete /home/erin of removed user 'erin'? [y/N] |Delete /home/ivy of removed user 'ivy'? [y/N] " {
		t.Errorf("asked %q", asked)
	}
	want := "ssh -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=~/.ssh/tacctl-%C -o ControlPersist=60 -o BatchMode=yes -p 2222 -T admin@web1 getent passwd"
	if a := f.Argvs(); len(a) != 1 || a[0] != want {
		t.Errorf("calls %q", a)
	}
	if out := e.Out.Stdout.(interface{ String() string }).String(); !strings.Contains(out, "web1: removed users with an account there (deleted by this run): dave, erin, ivy") {
		t.Errorf("out %q", out)
	}

	// No terminal: nothing read, nothing asked, no home deleted.
	f.Reset()
	if got, err := e.HomesToDelete(context.Background(), "web1", "admin@web1", "", "", current, nil); got != nil || err != nil || len(f.Argvs()) != 0 {
		t.Errorf("no terminal: %q %v %q", got, err, f.Argvs())
	}
	// A --local host is read here.
	f.Reset()
	if _, err := e.HomesToDelete(context.Background(), "me", Local, "", "", current, func(string) string { return "" }); err != nil || strings.Join(f.Argvs(), "|") != "getent passwd" {
		t.Errorf("local: %v %q", err, f.Argvs())
	}
	// A host whose accounts cannot be listed: reported, homes kept.
	f2 := &fake.Runner{}
	f2.On([]string{"ssh"}, execx.Result{Code: 255})
	e.Runner = f2
	got, err = e.HomesToDelete(context.Background(), "web1", "web1", "", "", current, ask)
	if got != nil || err != nil {
		t.Errorf("unlisted: %q %v", got, err)
	}
	if errs := e.Out.Stdout.(interface{ String() string }).String(); !strings.Contains(errs, "web1: could not list the host's accounts; the home directories of removed users are kept.") {
		t.Errorf("stderr %q", errs)
	}
	// An interrupt ends the command.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.HomesToDelete(ctx, "web1", "web1", "", "", current, ask); !errors.Is(err, ui.ErrInterrupted) {
		t.Errorf("interrupted: %v", err)
	}
}

func TestWriteScriptLifecycleHeader(t *testing.T) {
	e, _, _ := testEnv(t)
	out := t.TempDir() + "/x.sh"
	req := ScriptRequest{Scope: "lab", Server: "192.0.2.10", Method: Radius, Output: out, Temp: true,
		Secret: "0123456789abcdef0123456789abcdef", Rows: []string{"alice|15", "nopriv|"},
		Inactive: []string{"bob", "Bad", "bob"}, RemoveHomes: []string{"dave", "erin"}}
	if _, err := e.WriteScript(req); err != nil {
		t.Fatal(err)
	}
	head := strings.SplitN(readFile(t, out), "# --- tacctl", 2)[0]
	if !strings.HasSuffix(head, "TAC_USERS=alice:superuser:80000\nTAC_INACTIVE=$'bob\\nnopriv'\nTAC_REMOVE_HOMES=dave\\ erin\nTAC_PROTOCOL=3\n") {
		t.Errorf("header\n%s", head)
	}
	req.RemoveAllHomes = true
	if _, err := e.WriteScript(req); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, out), "\nTAC_REMOVE_HOMES=\\*\n") {
		t.Error("--remove-home is not '*'")
	}
}

// The client script's range and protocol are this package's.
func TestScriptBodyAgreesOnRangeAndProtocol(t *testing.T) {
	body := string(assets.LinuxInstallScript)
	for _, w := range []string{
		"TAC_UID_FIRST=" + strconv.Itoa(UIDBase) + "\n", "TAC_UID_LAST=" + strconv.Itoa(UIDMax) + "\n",
		"TAC_LEGACY_FIRST=" + strconv.Itoa(LegacyUIDBase) + "\n", "TAC_LEGACY_LAST=" + strconv.Itoa(LegacyUIDMax) + "\n",
		`if [[ "${TAC_PROTOCOL:-1}" != "` + ScriptProtocol + `" ]]; then`,
	} {
		if !strings.Contains(body, w) {
			t.Errorf("client-install.sh lacks %q", w)
		}
	}
}

func TestAccountSummary(t *testing.T) {
	for line, want := range map[string]string{
		"[INFO] Accounts: 4 managed by tacctl here; refused: carl.":               "4 users; 1 refused: carl",
		"[INFO] Accounts: 2 managed by tacctl here; refused: carl, olaf.\r":       "2 users; 2 refused: carl, olaf",
		"[INFO] Accounts: 0 managed by tacctl here.":                              "0 users",
		"[INFO] Accounts: 1 managed by tacctl here.":                              "1 user",
		"[INFO] Accounts: 3 managed by tacctl here; 1 renumbered.":                "3 users; 1 renumbered",
		"[INFO] Accounts: 3 managed by tacctl here; 2 renumbered; refused: carl.": "3 users; 2 renumbered; 1 refused: carl",
	} {
		s, ok := ParseAccountSummary(line)
		if !ok || s.Counts() != want {
			t.Errorf("%q: %+v %v", line, s, ok)
		}
	}
	for _, bad := range []string{"[INFO] Accounts: x managed by tacctl here.", "Accounts: 4 managed by tacctl here.", "[INFO] Created account 'a' (readonly)."} {
		if _, ok := ParseAccountSummary(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
	// Passed through as it comes; a line split across writes is read whole,
	// the last summary wins.
	var out strings.Builder
	w := &summaryWriter{w: &out}
	for _, chunk := range []string{"[INFO] Created account 'a'.\n[INFO] Accounts: 1 man", "aged by tacctl here.\r\n", "[INFO] Accounts: 3 managed by tacctl here; refused: x.\n"} {
		if n, err := w.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatal(n, err)
		}
	}
	if !strings.HasPrefix(out.String(), "[INFO] Created account 'a'.\n[INFO] Accounts: 1 managed") || w.sum == nil || w.sum.Counts() != "3 users; 1 refused: x" {
		t.Errorf("out %q sum %+v", out.String(), w.sum)
	}
}

func TestRunScriptKeepsTheSummary(t *testing.T) {
	e, out, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	f.On([]string{"bash"}, execx.Result{Stdout: []byte("[INFO] Accounts: 2 managed by tacctl here; refused: carl.\n")})
	if code, err := e.RunScript(context.Background(), Local, "", "", "/x.sh", nil); code != 0 || err != nil {
		t.Fatal(code, err)
	}
	if e.Summary == nil || e.Summary.Counts() != "2 users; 1 refused: carl" || !strings.Contains(out.String(), "refused: carl.") {
		t.Errorf("summary %+v out %q", e.Summary, out.String())
	}
	f.On([]string{"bash"}, execx.Result{})
	if _, err := e.RunScript(context.Background(), Local, "", "", "/x.sh", nil); err != nil || e.Summary != nil {
		t.Errorf("a run without a summary kept the last one: %+v", e.Summary)
	}
}
