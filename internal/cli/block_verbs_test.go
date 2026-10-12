package cli

// The verbs of the configuration blocks (0.2.7, B4) at the scope level:
// list, show, check, set and remove, their refusals, tiers, the snapshot and
// the log line each takes, and what they never print.

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

const (
	verbSNMPFile = "# the NMS\nset snmp community nms-ro-secret authorization read-only\nset snmp community nms-ro-secret clients 192.0.2.50/32\n" +
		"set snmp trap-group nms-traps-secret version v2\nset snmp trap-group nms-traps-secret targets 198.51.100.7\n"
	verbSystemFile = "set system login message <<'EOF'\nAuthorized use of js1.lab.example.net only.\n  *** keep out ***\nEOF\n" +
		"set system domain-name lab.example.net\nset system name-server 192.0.2.53\n" +
		"set system ntp server 192.0.2.123 prefer\nset system ntp authentication-key 1 type md5 value ntp-key-0123456789\n"
)

// blk runs 'tacctl scope block <args>' as the superuser.
func (sb *sandbox) blk(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun(stdin, append([]string{"scope", "block"}, args...), nil))
}

// logged is the number of log lines that hold s.
func (sb *sandbox) logged(s string) int {
	n := 0
	for _, c := range sb.runner.Records() {
		if c.Cmd.Name == "logger" && strings.Contains(strings.Join(c.Cmd.Args, " "), s) {
			n++
		}
	}
	return n
}

// blockFile writes text to a file of the sandbox's tmp and returns its path.
func (sb *sandbox) blockFile(name, text string) string {
	sb.t.Helper()
	sb.write("tmp/"+name, text, 0o600)
	return sb.path("tmp", name)
}

// noneOf fails when out holds any of the strings.
func noneOf(t *testing.T, what, out string, bad ...string) {
	t.Helper()
	for _, s := range bad {
		if strings.Contains(out, s) {
			t.Errorf("%s holds %q:\n%s", what, s, out)
		}
	}
}

func TestScopeBlockSetShowCheckListRemove(t *testing.T) {
	sb := newSandbox(t, true)
	const secret, group = "nms-ro-secret", "nms-traps-secret"
	f := sb.blockFile("snmp.txt", verbSNMPFile)

	// Nothing yet.
	out := sb.blk("", "lab", "juniper", "list")
	if sb.code != 0 || !strings.Contains(out, "none: scope 'lab' has no juniper block.") {
		t.Errorf("list of nothing: %d\n%s", sb.code, out)
	}
	sb.blk("", "lab", "juniper", "show", "snmp")
	sb.expect(1, "", "Scope 'lab' has no snmp block.")
	sb.blk("", "lab", "juniper", "remove", "snmp", "-y")
	sb.expect(1, "", "Scope 'lab' has no snmp block to remove.")

	// check of a file: findings with lines, the owned objects, the secrets
	// as a count, and no string.
	out = sb.blk("", "lab", "juniper", "check", "snmp", "--file", f)
	for _, want := range []string{"Owned by tacctl once in force: 1 community, 1 trap group",
		"Statements that carry a secret: 4", "No file in force: every statement is new.", "ok."} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("check lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	noneOf(t, "check", out+sb.stderr(), secret, group)
	if _, err := os.Stat(sb.path("state", "blocks")); !os.IsNotExist(err) {
		t.Errorf("check wrote the store: %v", err)
	}

	// set: asks; no answer is no change.
	before := sb.snapshots()
	out = sb.blk("n\n", "lab", "juniper", "set", "snmp", "--file", f)
	if sb.code != 0 || !strings.Contains(out, "Aborted.") || sb.snapshots() != before {
		t.Errorf("a no: %d %d\n%s", sb.code, sb.snapshots(), out)
	}
	if _, err := os.Stat(sb.path("state", "blocks")); !os.IsNotExist(err) {
		t.Errorf("an aborted set wrote the store: %v", err)
	}
	out = sb.blk("y\n", "lab", "juniper", "set", "snmp", "--file", f)
	if sb.code != 0 || !strings.Contains(out, "The snmp block of scope 'lab' is set (") {
		t.Fatalf("set: %d\n%s%s", sb.code, out, sb.stderr())
	}
	noneOf(t, "set", out+sb.stderr(), secret, group)
	if sb.snapshots() != before+1 {
		t.Errorf("snapshots: %d -> %d", before, sb.snapshots())
	}
	if got := sb.read("state/blocks/lab/juniper/snmp"); got != verbSNMPFile {
		t.Errorf("the file is not the text as given:\n%q", got)
	}
	for rel, mode := range map[string]os.FileMode{"state/blocks": 0o700, "state/blocks/lab": 0o700, "state/blocks/lab/juniper": 0o700, "state/blocks/lab/juniper/snmp": 0o600} {
		if st, err := os.Stat(sb.path(rel)); err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v (want %v)", rel, st, err, mode)
		}
	}
	if o := sb.overrides(); !strings.Contains(o, "blocks:\n  lab:\n    juniper:\n    - snmp\n") {
		t.Errorf("the manifest:\n%s", o)
	}
	if n := sb.logged("block-set name=lab/juniper/snmp bytes="); n != 1 {
		t.Errorf("block-set logged %d times: %q", n, sb.runner.Argvs())
	}
	noneOf(t, "the log", strings.Join(sb.runner.Argvs(), "\n"), secret, group)
	// the snapshot holds the store as it was (no block yet) and is taken
	// before the write
	snaps := sb.leftovers("backups/*")
	if len(snaps) == 0 {
		t.Fatal("no snapshot")
	}

	// the same text again is no change, and takes no snapshot
	n := sb.snapshots()
	sb.blk("", "lab", "juniper", "set", "snmp", "--file", f, "-y")
	sb.expect(0, "is this text already; nothing was changed", "")
	if sb.snapshots() != n {
		t.Errorf("a no-change set took a snapshot")
	}

	// show: elided, by marks, comments never; --reveal: the file
	out = sb.blk("", "lab", "juniper", "show", "snmp")
	want := "set snmp community <secret:1> authorization read-only\nset snmp community <secret:1> clients 192.0.2.50/32\n" +
		"set snmp trap-group <group:1> version v2\nset snmp trap-group <group:1> targets 198.51.100.7\n"
	if sb.code != 0 || !strings.Contains(out, want) {
		t.Errorf("show:\n%s", out)
	}
	noneOf(t, "show", out, secret, group, "the NMS")
	out = sb.blk("", "lab", "juniper", "show", "snmp", "--reveal")
	if sb.code != 0 || !strings.Contains(out, verbSNMPFile) {
		t.Errorf("show --reveal:\n%s", out)
	}
	// the superuser's reveal is not an engineer's: not logged as one
	if sb.logged("secret-read") != 0 {
		t.Errorf("a superuser's reveal was logged: %q", sb.runner.Argvs())
	}

	// list
	out = sb.blk("", "lab", "juniper", "list")
	for _, want := range []string{"Configuration blocks of scope 'lab' (juniper)", "snmp     in force", "1 community, 1 trap group"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	noneOf(t, "list", out, secret, group)
	if out2 := sb.blk("", "lab", "juniper"); out2 != out {
		t.Errorf("no verb is list:\n%s", out2)
	}

	// check against the file in force: a second client and no more trap group
	f2 := sb.blockFile("snmp2.txt", strings.Replace(verbSNMPFile, "set snmp trap-group nms-traps-secret targets 198.51.100.7\n",
		"set snmp trap-group nms-traps-secret targets 198.51.100.8\n", 1)+"set snmp community nms-ro-secret clients 198.51.100.0/24\n")
	out = sb.blk("", "lab", "juniper", "check", "snmp", "--file", f2)
	for _, want := range []string{"3 unchanged", "- set snmp trap-group <group:1> targets 198.51.100.7",
		"+ set snmp trap-group <group:1> targets 198.51.100.8", "+ set snmp community <secret:1> clients 198.51.100.0/24"} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("check diff lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	noneOf(t, "check diff", out, secret, group)
	// check of the file in force says so
	out = sb.blk("", "lab", "juniper", "check", "snmp")
	if sb.code != 0 || !strings.Contains(out, "the file in force") || !strings.Contains(out, "No change against the file in force (4 statements).") {
		t.Errorf("check of the file in force: %d\n%s", sb.code, out)
	}
	// standard input
	out = sb.blk(verbSNMPFile, "lab", "juniper", "check", "snmp", "-")
	if sb.code != 0 || !strings.Contains(out, "standard input") {
		t.Errorf("check -: %d\n%s", sb.code, out)
	}

	// remove: asks, snapshots, takes the entry and the file
	n = sb.snapshots()
	out = sb.blk("n\n", "lab", "juniper", "remove", "snmp")
	if !strings.Contains(out, "Aborted.") || sb.snapshots() != n {
		t.Errorf("remove no: %q", out)
	}
	if _, err := os.Stat(sb.path("state/blocks/lab/juniper/snmp")); err != nil {
		t.Errorf("an aborted remove removed the file: %v", err)
	}
	out = sb.blk("y\n", "lab", "juniper", "remove", "snmp")
	if sb.code != 0 || !strings.Contains(out, "The snmp block of scope 'lab' is removed.") || sb.snapshots() != n+1 {
		t.Errorf("remove: %d %d\n%s", sb.code, sb.snapshots(), out)
	}
	if _, err := os.Stat(sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("the store is left: %v", err)
	}
	if strings.Contains(sb.overrides(), "blocks") {
		t.Errorf("the manifest is left:\n%s", sb.overrides())
	}
	if sb.logged("block-remove name=lab/juniper/snmp by=") != 1 {
		t.Errorf("block-remove not logged: %q", sb.runner.Argvs())
	}
}

func TestScopeBlockSystemIsElidedAndRevealed(t *testing.T) {
	sb := newSandbox(t, true)
	f := sb.blockFile("system.txt", verbSystemFile)
	out := sb.blk("", "lab", "juniper", "set", "system", "--file", f, "-y")
	if sb.code != 0 {
		t.Fatalf("set: %d\n%s%s", sb.code, out, sb.stderr())
	}
	noneOf(t, "set", out+sb.stderr(), "Authorized", "keep out", "ntp-key-0123456789")
	if !strings.Contains(out, "Statements that carry a secret: 1") {
		t.Errorf("set:\n%s", out)
	}
	out = sb.blk("", "lab", "juniper", "show", "system")
	for _, want := range []string{"set system login message <<'EOF'\n<message: 2 lines, ", " characters>\nEOF\n",
		"set system domain-name lab.example.net", "set system ntp authentication-key 1 type md5 value <secret>"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	noneOf(t, "show", out, "Authorized", "keep out", "ntp-key-0123456789", "js1.lab")
	out = sb.blk("", "lab", "juniper", "show", "system", "--reveal")
	if !strings.Contains(out, verbSystemFile) {
		t.Errorf("show --reveal:\n%s", out)
	}
	out = sb.blk("", "lab", "juniper", "list")
	if !strings.Contains(out, "system   in force") || !strings.Contains(out, "5 statements, a login message of 2 lines") {
		t.Errorf("list:\n%s", out)
	}
	// a changed message shows in the diff without its text
	f2 := sb.blockFile("system2.txt", strings.Replace(verbSystemFile, "keep out", "keep far", 1))
	out = sb.blk("", "lab", "juniper", "check", "system", "--file", f2)
	if sb.code != 0 || !strings.Contains(out, "    - <message: 2 lines,") || !strings.Contains(out, "    + <message: 2 lines,") {
		t.Errorf("check:\n%s", out)
	}
	noneOf(t, "check", out, "keep far", "keep out")
}

func TestScopeBlockSetRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	good := sb.blockFile("snmp.txt", verbSNMPFile)
	nothing := func() {
		t.Helper()
		if _, err := os.Stat(sb.path("state/blocks")); !os.IsNotExist(err) {
			t.Errorf("a refusal wrote the store: %v", err)
		}
		if sb.overrides() != "" {
			t.Errorf("a refusal wrote tacctl.yaml:\n%s", sb.overrides())
		}
		if sb.snapshots() != 0 {
			t.Errorf("a refusal took a snapshot")
		}
	}
	for _, c := range []struct {
		name  string
		stdin string
		args  []string
		err   string
	}{
		{"unknown scope", "", []string{"nowhere", "juniper", "set", "snmp", "--file", good, "-y"}, "Scope 'nowhere' does not exist."},
		{"cisco", "", []string{"lab", "cisco", "set", "snmp", "--file", good, "-y"}, "IOS blocks come in the release after"},
		{"another vendor", "", []string{"lab", "wti", "list"}, "Unknown vendor 'wti' for a block: juniper."},
		{"vendor missing", "", []string{"lab", "set", "snmp", "--file", good}, "The vendor comes before the verb"},
		{"unknown block", "", []string{"lab", "juniper", "set", "banner", "--file", good, "-y"}, "Unknown block 'banner'"},
		{"bad block name", "", []string{"lab", "juniper", "set", "../x", "--file", good, "-y"}, "Invalid block name"},
		{"no source", "", []string{"lab", "juniper", "set", "snmp", "-y"}, "Give the block's text with --file <path>, or - for standard input."},
		{"two sources", "x", []string{"lab", "juniper", "set", "snmp", "--file", good, "-", "-y"}, "two sources"},
		{"no such file", "", []string{"lab", "juniper", "set", "snmp", "--file", "/nonexistent/snmp.txt", "-y"}, "Cannot read the file"},
		{"a directory", "", []string{"lab", "juniper", "set", "snmp", "--file", "/", "-y"}, "is not a regular file"},
		{"empty", "", []string{"lab", "juniper", "set", "snmp", "--file", sb.blockFile("empty", ""), "-y"}, "The text is empty. To take a block away"},
		{"comments only", "", []string{"lab", "juniper", "set", "snmp", "--file", sb.blockFile("c", "# nothing\n\n"), "-y"}, "states nothing"},
		{"stdin needs -y", "set snmp community x-community authorization read-only\nset snmp community x-community clients 192.0.2.1/32\n",
			[]string{"lab", "juniper", "set", "snmp", "-"}, "add -y to set it"},
		{"errors", "", []string{"lab", "juniper", "set", "snmp", "--file", sb.blockFile("bad", "set snmp community short authorization read-only\n"), "-y"}, "Nothing was written."},
		{"tacctl's own name", "", []string{"lab", "juniper", "set", "snmp", "--file", sb.blockFile("own", "set snmp community TACCTL-SNMP authorization read-only\nset snmp community TACCTL-SNMP clients 192.0.2.1/32\n"), "-y"}, "Nothing was written."},
		{"too big", "", []string{"lab", "juniper", "set", "snmp", "--file", sb.blockFile("big", strings.Repeat("# x\n", 70000)), "-y"}, "is at most"},
	} {
		sb.blk(c.stdin, c.args...)
		if sb.code != 1 || !strings.Contains(sb.stderr()+plain(sb.out.String()), c.err) {
			t.Errorf("%s: exit %d\nstdout %s\nstderr %s", c.name, sb.code, plain(sb.out.String()), sb.stderr())
		}
		nothing()
	}
	// a block with errors shows the lines and no string
	bad := "set snmp community short-c authorization read-only\n"
	sb.blk("", "lab", "juniper", "set", "snmp", "--file", sb.blockFile("bad2", bad), "-y")
	if all := plain(sb.out.String()); !strings.Contains(all, "line 1: error:") || strings.Contains(all, "short-c") {
		t.Errorf("errors:\n%s", all)
	}
	// check says the same and exits 1
	sb.blk("", "lab", "juniper", "check", "snmp", "--file", sb.blockFile("bad3", bad))
	if all := plain(sb.out.String()); sb.code != 1 || !strings.Contains(all, "line 1: error:") || strings.Contains(all, "short-c") {
		t.Errorf("check errors: %d\n%s", sb.code, all)
	}
	// a word that is no verb
	sb.blk("", "lab", "juniper", "frobnicate", "snmp")
	sb.expect(1, "", "Unknown subcommand: 'frobnicate'")
}

// tacctl.yaml that cannot be written refuses every write before it starts.
func TestScopeBlockRefusesWhenTacctlYAMLCannotBeWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	sb := newSandbox(t, true)
	good := sb.blockFile("snmp.txt", verbSNMPFile)
	if err := os.Chmod(sb.path("state"), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sb.path("state"), 0o700) })
	sb.blk("", "lab", "juniper", "set", "snmp", "--file", good, "-y")
	sb.expect(1, "", "tacctl.yaml cannot be written")
	if _, err := os.Stat(sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("a refused set wrote the store: %v", err)
	}
	// and a damaged tacctl.yaml
	if err := os.Chmod(sb.path("state"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.write("state/tacctl.yaml", "blocks: [unclosed\n", 0o640)
	sb.blk("", "lab", "juniper", "set", "snmp", "--file", good, "-y")
	sb.expect(1, "", "tacctl.yaml cannot be read")
}

// A block community that is the scope's own community is refused by check and
// set, by position and without a string.
func TestScopeBlockRefusesTheScopesOwnCommunity(t *testing.T) {
	sb := newSandbox(t, true)
	sb.scopeSNMP("lab-community-9\n", "lab", "community", "--stdin")
	f := sb.blockFile("own.txt", "set snmp community lab-community-9 authorization read-only\nset snmp community lab-community-9 clients 192.0.2.50/32\n")
	out := sb.blk("", "lab", "juniper", "check", "snmp", "--file", f)
	if sb.code != 1 || !strings.Contains(out, "Community 1 of the SNMP block of scope 'lab' is the community the scope's own SNMP settings render") {
		t.Errorf("check: %d\n%s", sb.code, out)
	}
	noneOf(t, "check", out+sb.stderr(), "lab-community-9")
	sb.blk("", "lab", "juniper", "set", "snmp", "--file", f, "-y")
	if sb.code != 1 {
		t.Errorf("set: %d", sb.code)
	}
	if _, err := os.Stat(sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("a refused set wrote the store: %v", err)
	}
}

// A file no list names is ignored and a name with no file is a finding; show
// and check say which, list names both.
func TestScopeBlockUnlistedAndMissing(t *testing.T) {
	sb := newSandbox(t, true)
	sb.putBlock("lab", verbSNMPFile)
	// the manifest names snmp and system; only snmp has a file, and there is
	// an unlisted file for a manifest that lacks it
	sb.write("state/tacctl.yaml", "blocks:\n  lab:\n    juniper:\n    - system\n", 0o640)
	out := sb.blk("", "lab", "juniper", "list")
	for _, want := range []string{"snmp     ignored (not in tacctl.yaml)", "system   no file",
		"the file of block 'snmp' is not in tacctl.yaml (blocks); it is ignored",
		"the block 'system' is in tacctl.yaml (blocks) but has no file; it renders nothing"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	out = sb.blk("", "lab", "juniper", "show", "snmp")
	if sb.code != 0 || !strings.Contains(out, "not in force: tacctl.yaml does not name it") {
		t.Errorf("show of an unlisted file: %d\n%s", sb.code, out)
	}
	sb.blk("", "lab", "juniper", "show", "system")
	sb.expect(1, "", "named in tacctl.yaml but has no file")
	out = sb.blk("", "lab", "juniper", "check", "snmp")
	if sb.code != 0 || !strings.Contains(out, "the file, which is not in force") {
		t.Errorf("check of an unlisted file: %d\n%s", sb.code, out)
	}
	// remove takes either
	sb.blk("", "lab", "juniper", "remove", "snmp", "-y")
	sb.expect(0, "The snmp block of scope 'lab' is removed.", "")
	if _, err := os.Stat(sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("the unlisted file is left: %v", err)
	}
	sb.blk("", "lab", "juniper", "remove", "system", "-y")
	sb.expect(0, "The system block of scope 'lab' is removed.", "")
	if strings.Contains(sb.overrides(), "blocks") {
		t.Errorf("the manifest is left:\n%s", sb.overrides())
	}
}

// The engineer reads the blocks of their own scopes, elided; a reveal is
// logged; setting and removing are the superuser's; another scope's blocks
// are not there.
func TestScopeBlockEngineer(t *testing.T) {
	sb := engineerSandbox(t)
	head := "tier:\n  operator: engineer\n"
	sb.putBlockSet(head, "lab", map[string]string{"snmp": verbSNMPFile, "system": verbSystemFile})
	// another scope's block, which bob must not see
	sb.putBlockSet(head, "prod", map[string]string{"snmp": verbSNMPFile})
	sb.write("state/tacctl.yaml", head+"blocks:\n  lab:\n    juniper:\n    - snmp\n    - system\n  prod:\n    juniper:\n    - snmp\n", 0o640)
	sb.write("state/blocks/lab/juniper/snmp", verbSNMPFile, 0o600)
	sb.write("state/blocks/lab/juniper/system", verbSystemFile, 0o600)
	if err := os.MkdirAll(sb.path("state/blocks/prod/juniper"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.write("state/blocks/prod/juniper/snmp", verbSNMPFile, 0o600)

	out := sb.asEngineer("", "scope", "block", "lab", "juniper", "list")
	if sb.code != 0 || !strings.Contains(out, "snmp     in force") || !strings.Contains(out, "system   in force") {
		t.Errorf("list: %d %q\n%s", sb.code, out, sb.stderr())
	}
	noneOf(t, "list", out, "nms-ro-secret", "Authorized")
	out = sb.asEngineer("", "scope", "block", "lab", "juniper", "show", "snmp")
	if sb.code != 0 || !strings.Contains(out, "<secret:1>") {
		t.Errorf("show: %d\n%s", sb.code, out)
	}
	noneOf(t, "show", out, "nms-ro-secret", "nms-traps-secret")
	if sb.logged("secret-read") != 0 {
		t.Errorf("an elided read was logged: %q", sb.runner.Argvs())
	}
	out = sb.asEngineer("", "scope", "block", "lab", "juniper", "show", "snmp", "--reveal")
	if sb.code != 0 || !strings.Contains(out, "nms-ro-secret") {
		t.Errorf("show --reveal: %d\n%s", sb.code, out)
	}
	if sb.logged("secret-read kind=block name=lab/juniper/snmp by=bob") != 1 {
		t.Errorf("the reveal was not logged once: %q", sb.runner.Argvs())
	}
	noneOf(t, "the log", strings.Join(sb.runner.Argvs(), "\n"), "nms-ro-secret")
	out = sb.asEngineer("", "scope", "block", "lab", "juniper", "check", "system")
	if sb.code != 0 || !strings.Contains(out, "ok.") {
		t.Errorf("check: %d\n%s", sb.code, out)
	}
	noneOf(t, "check", out, "ntp-key-0123456789", "Authorized")
	// a file, read as the caller; and standard input
	f := sb.blockFile("e.txt", verbSNMPFile)
	if out = sb.asEngineer("", "scope", "block", "lab", "juniper", "check", "snmp", "--file", f); sb.code != 0 {
		t.Errorf("check --file: %d %s\n%s", sb.code, sb.stderr(), out)
	}
	if out = sb.asEngineer(verbSNMPFile, "scope", "block", "lab", "juniper", "check", "snmp", "-"); sb.code != 0 {
		t.Errorf("check -: %d %s\n%s", sb.code, sb.stderr(), out)
	}

	before, snaps := sb.read("state/blocks/lab/juniper/snmp")+sb.overrides(), sb.snapshots()
	for _, args := range [][]string{
		{"lab", "juniper", "set", "snmp", "--file", f, "-y"},
		{"lab", "juniper", "set", "snmp", "-", "-y"},
		{"lab", "juniper", "remove", "snmp", "-y"},
	} {
		sb.asEngineer(verbSNMPFile, append([]string{"scope", "block"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads the configuration blocks of scope 'lab' (list, show, check); ") ||
			!strings.Contains(sb.stderr(), " is the superuser's. Nothing was changed.") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if sb.read("state/blocks/lab/juniper/snmp")+sb.overrides() != before || sb.snapshots() != snaps {
		t.Error("an engineer changed something")
	}
	for _, args := range [][]string{
		{"prod", "juniper", "list"}, {"prod", "juniper", "show", "snmp"}, {"prod", "juniper", "show", "snmp", "--reveal"},
		{"prod", "juniper", "check", "snmp"}, {"prod", "juniper", "set", "snmp", "--file", f, "-y"}, {"prod", "juniper", "remove", "snmp", "-y"},
	} {
		out = sb.asEngineer("", append([]string{"scope", "block"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Scope 'prod' does not exist.") || out != "" {
			t.Errorf("%v: %d %q %q", args, sb.code, sb.stderr(), out)
		}
	}
	// the gate: an operator is not permitted
	sb.write("state/tacctl.yaml", "blocks:\n  lab:\n    juniper:\n    - snmp\n", 0o640)
	sb.cfgRun("", []string{"scope", "block", "lab", "juniper", "list"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-operator\n")})
	}, "SUDO_USER=bob")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the operator tier") {
		t.Errorf("an operator: %d %q", sb.code, sb.stderr())
	}
}

// 'config validate' names the blocks' disagreements with tacctl.yaml: a name
// with no file and a block with errors are errors, a file no list names is a
// warning, and nothing is printed for an installation without blocks.
func TestConfigValidateReportsBlocks(t *testing.T) {
	sb := renderedSandbox(t)
	out := plain(sb.run("", []string{"config", "validate"}))
	if sb.code != 0 || strings.Contains(out, "Config blocks:") {
		t.Fatalf("no blocks: %d\n%s", sb.code, out)
	}
	sb.run("", []string{"scope", "block", "lab", "juniper", "set", "snmp", "--file", sb.blockFile("s.txt", verbSNMPFile), "-y"})
	sb.expect(0, "is set", "")
	out = plain(sb.run("", []string{"config", "validate"}))
	if sb.code != 0 || !strings.Contains(out, "Config blocks:        valid") {
		t.Errorf("valid: %d\n%s", sb.code, out)
	}
	// a name with no file; a file no list names; a block with errors
	sb.write("state/tacctl.yaml", sb.overrides()+"blocks_device:\n  js1~lab~example~net:\n    juniper:\n    - system\n", 0o640)
	sb.write("state/blocks/lab/juniper/system", verbSystemFile, 0o600)
	sb.write("state/blocks/lab/juniper/snmp", "set snmp community short authorization read-only\n", 0o600)
	out = plain(sb.run("", []string{"config", "validate"}))
	for _, want := range []string{
		"Config blocks:        scope lab juniper: the file of block 'system' is not in tacctl.yaml (blocks); it is ignored",
		"Config blocks:        the snmp block of scope lab has 1 error and is not rendered, so every Junos device it reaches is refused: tacctl scope block lab juniper check snmp",
		"Config blocks:        device js1.lab.example.net: the device is not in the registry; its configuration blocks and their tacctl.yaml (blocks_device) entries are ignored",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate lacks %q:\n%s", want, out)
		}
	}
	if sb.code != 1 {
		t.Errorf("exit %d", sb.code)
	}
	noneOf(t, "validate", out, "Authorized", "ntp-key", "short")
	// a name with no file is an error
	sb.write("state/tacctl.yaml", "blocks:\n  lab:\n    juniper:\n    - snmp\n    - system\n", 0o640)
	if err := os.Remove(sb.path("state/blocks/lab/juniper/system")); err != nil {
		t.Fatal(err)
	}
	sb.write("state/blocks/lab/juniper/snmp", verbSNMPFile, 0o600)
	out = plain(sb.run("", []string{"config", "validate"}))
	if sb.code != 1 || !strings.Contains(out, "Config blocks:        scope lab juniper: the block 'system' is in tacctl.yaml (blocks) but has no file; it renders nothing") {
		t.Errorf("missing: %d\n%s", sb.code, out)
	}
}
