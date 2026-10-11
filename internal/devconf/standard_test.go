package devconf

// The standard Cisco block in the comparison (plan §13, D116-D118, D107): the
// lines it adds are ordinary managed statements, the console's login list is
// never implicit, and the forms an older walkthrough left on a device are
// extras, not satisfied lines.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// standardModern is the aaa section of the standard block, modern syntax,
// for a TACACS+ scope that sets a source interface.
func standardModern(sourceInterface bool) devices.Section {
	lines := []string{
		"aaa new-model",
		"tacacs server TACACS", "  address ipv4 192.0.2.10", "  key lab-secret", "  single-connection", "  timeout 5",
		"aaa group server tacacs+ TACACS-GROUP", "  server name TACACS",
	}
	if sourceInterface {
		lines = append(lines, "ip tacacs source-interface Loopback0")
	}
	lines = append(lines,
		"aaa authentication login default group TACACS-GROUP local",
		"aaa authentication login CONSOLE local",
		"aaa authorization exec default group TACACS-GROUP local if-authenticated",
		"aaa authentication enable default group TACACS-GROUP enable",
		"aaa accounting exec default start-stop group TACACS-GROUP",
		"aaa session-id common",
		"line con 0", "  login authentication CONSOLE",
		"line vty 0 15", "  login authentication default",
		"aaa authorization commands 15 default group TACACS-GROUP local",
		"aaa authorization config-commands")
	s := devices.Section{Name: SectionAAA, Lines: lines, Secret: make([]bool, len(lines))}
	s.Secret[3] = true
	return s
}

// standardRadius is the aaa section of a RADIUS device: no enable list (lab
// item E2) and no command authorization.
func standardRadius() devices.Section {
	lines := []string{
		"aaa new-model",
		"radius server RADIUS", "  address ipv4 192.0.2.10 auth-port 1812 acct-port 1813", "  key lab-secret", "  timeout 5", "  retransmit 2",
		"aaa group server radius RADIUS-GROUP", "  server name RADIUS",
		"aaa authentication login default group RADIUS-GROUP local",
		"aaa authentication login CONSOLE local",
		"aaa authorization exec default group RADIUS-GROUP local if-authenticated",
		"aaa accounting exec default start-stop group RADIUS-GROUP",
		"aaa session-id common",
		"line con 0", "  login authentication CONSOLE",
		"line vty 0 15", "  login authentication default",
	}
	s := devices.Section{Name: SectionAAA, Lines: lines, Secret: make([]bool, len(lines))}
	s.Secret[3] = true
	return s
}

const standardRadiusDevice = `version 15.6
aaa new-model
aaa group server radius RADIUS-GROUP
 server name RADIUS
!
aaa authentication login default group RADIUS-GROUP local
aaa authentication login CONSOLE local
aaa authorization exec default group RADIUS-GROUP local if-authenticated
aaa accounting exec default start-stop group RADIUS-GROUP
aaa session-id common
radius server RADIUS
 address ipv4 192.0.2.10 auth-port 1812 acct-port 1813
 key 7 0822455D0A16
 timeout 5
 retransmit 2
!
line con 0
 login authentication CONSOLE
line vty 0 15
 login authentication default
end
`

// S3: the remark of the management ACL is ASCII now ('-' for the dash an
// earlier release rendered): a remark is never compared, so a device that
// carries the old text, or any other, is equal to the rendering.
func TestStandardAclRemarkTextIsNotCompared(t *testing.T) {
	lines := []string{"ip access-list standard VTY-ACL",
		"  remark Managed by tacctl - edit with 'tacctl config mgmt-acl'",
		"  permit 192.0.2.10 0.0.0.0", "  deny   any log"}
	exp := devices.Section{Name: SectionMgmtACL, Lines: lines, Secret: make([]bool, len(lines))}
	for _, remark := range []string{"Managed by tacctl — edit with 'tacctl config mgmt-acl'",
		"Managed by tacctl - edit with 'tacctl config mgmt-acl'", "somebody else's note"} {
		device := "version 15.6\nip access-list standard VTY-ACL\n remark " + remark + "\n permit 192.0.2.10\n deny   any log\nend\n"
		ex, err := Extract("ios", device, exp)
		if err != nil {
			t.Fatal(err)
		}
		if r := resultOf(t, "ios", exp, ex.Sections[SectionMgmtACL], true); r.State != StateOK {
			t.Errorf("remark %q: %s %v", remark, r.State, linesOf(r))
		}
	}
}

// S4: the enable list of a RADIUS device is not rendered (lab item E2): a
// device that lacks it is not missing a line, and one that has it, under any
// group, carries no extra. The TACACS+ rendering keeps it as a statement.
func TestStandardRadiusEnableListIsTolerated(t *testing.T) {
	r := standardResult(t, standardRadiusDevice, standardRadius())
	if r.State != StateOK {
		t.Fatalf("without the enable list: %s %v", r.State, linesOf(r))
	}
	for _, list := range []string{"aaa authentication enable default group RADIUS-GROUP enable",
		"aaa authentication enable default enable"} {
		with := replaceOnce(t, standardRadiusDevice, "aaa session-id common\n", "aaa session-id common\n"+list+"\n")
		r = standardResult(t, with, standardRadius())
		if r.State != StateOK {
			t.Errorf("with %q: %s %v", list, r.State, linesOf(r))
		}
		for _, l := range linesOf(r) {
			if strings.Contains(l, "authentication enable") {
				t.Errorf("with %q: %q is listed", list, l)
			}
		}
	}
	// TACACS+: the enable list is a statement, missing when the device lacks it
	r = standardResult(t, replaceOnce(t, standardDevice, "aaa authentication enable default group TACACS-GROUP enable\n", ""), standardModern(true))
	if !slices.Contains(linesOf(r), "- aaa authentication enable default group TACACS-GROUP enable") {
		t.Errorf("TACACS+ enable list not compared: %v", linesOf(r))
	}
}

// the standard as a device prints it.
const standardDevice = `version 15.6
aaa new-model
aaa group server tacacs+ TACACS-GROUP
 server name TACACS
!
aaa authentication login default group TACACS-GROUP local
aaa authentication login CONSOLE local
aaa authentication enable default group TACACS-GROUP enable
aaa authorization config-commands
aaa authorization exec default group TACACS-GROUP local if-authenticated
aaa authorization commands 15 default group TACACS-GROUP local
aaa accounting exec default start-stop group TACACS-GROUP
aaa session-id common
ip tacacs source-interface Loopback0
tacacs server TACACS
 address ipv4 192.0.2.10
 key 7 0822455D0A16
 single-connection
 timeout 5
!
line con 0
 login authentication CONSOLE
line vty 0 4
 login authentication default
line vty 5 15
 login authentication default
end
`

func standardResult(t *testing.T, device string, exp devices.Section) SectionResult {
	t.Helper()
	ex, err := Extract("ios", device, exp)
	if err != nil {
		t.Fatal(err)
	}
	return resultOf(t, "ios", exp, ex.Sections[SectionAAA], true)
}

// The standard, read back, is ok: every new line is an ordinary statement,
// the console's leaf included, and nothing of it is extra.
func TestStandardBlockReadsOK(t *testing.T) {
	r := standardResult(t, standardDevice, standardModern(true))
	if r.State != StateOK {
		t.Fatalf("%s %v", r.State, linesOf(r))
	}
	for _, want := range []string{
		"= aaa authentication login CONSOLE local",
		"= aaa authentication enable default group TACACS-GROUP enable",
		"= aaa session-id common",
		"= ip tacacs source-interface Loopback0",
		"= line con 0 > login authentication CONSOLE",
		"= line vty 0 15 > login authentication default",
	} {
		if !slices.Contains(linesOf(r), want) {
			t.Errorf("no %q in %v", want, linesOf(r))
		}
	}
}

// Each added line is compared: take any one away and it is the one missing.
func TestStandardBlockLinesAreCompared(t *testing.T) {
	for _, tc := range []struct{ drop, keep, want string }{
		{"aaa authentication login CONSOLE local\n", "", "- aaa authentication login CONSOLE local"},
		{"aaa authentication enable default group TACACS-GROUP enable\n", "", "- aaa authentication enable default group TACACS-GROUP enable"},
		{"aaa session-id common\n", "", "- aaa session-id common"},
		{"ip tacacs source-interface Loopback0\n", "", "- ip tacacs source-interface Loopback0"},
		{"line con 0\n login authentication CONSOLE\n", "line con 0\n", "- line con 0 > login authentication CONSOLE"},
	} {
		r := standardResult(t, replaceOnce(t, standardDevice, tc.drop, tc.keep), standardModern(true))
		if r.State != StateDiffers || !slices.Contains(linesOf(r), tc.want) {
			t.Errorf("without %q: %s %v", tc.drop, r.State, linesOf(r))
		}
	}
}

// D107: the console is not implicit. With 'aaa new-model' and no explicit
// leaf it is on the default list, which is not the standard's CONSOLE list:
// the leaf is missing, and the list the console is on is said. The vty lines
// on the default list with no leaf stay what they were.
func TestStandardConsoleIsNeverImplicit(t *testing.T) {
	noLeaf := replaceOnce(t, standardDevice, "line con 0\n login authentication CONSOLE\n", "line con 0\n exec-timeout 0 0\n")
	noLeaf = replaceOnce(t, noLeaf, "line vty 0 4\n login authentication default\nline vty 5 15\n login authentication default\n",
		"line vty 0 4\n transport input ssh\nline vty 5 15\n transport input ssh\n")
	r := standardResult(t, noLeaf, standardModern(true))
	if r.State != StateDiffers {
		t.Fatalf("%s %v", r.State, linesOf(r))
	}
	for _, want := range []string{
		"- line con 0 > login authentication CONSOLE",
		"+ line con 0 > login authentication default",
		"= line vty 0 15 > login authentication default", // implicit, as before
	} {
		if !slices.Contains(linesOf(r), want) {
			t.Errorf("no %q in %v", want, linesOf(r))
		}
	}
	// the same with an explicit default list on the console
	explicit := replaceOnce(t, standardDevice, "line con 0\n login authentication CONSOLE\n", "line con 0\n login authentication default\n")
	r = standardResult(t, explicit, standardModern(true))
	if !slices.Contains(linesOf(r), "- line con 0 > login authentication CONSOLE") || !slices.Contains(linesOf(r), "+ line con 0 > login authentication default") {
		t.Errorf("explicit default on the console: %v", linesOf(r))
	}
}

// D117: the forms of an older walkthrough are extras, never satisfied
// statements, whatever the image: a global server line on a modern image, a
// group of another name, and the lists that name it.
func TestStandardOldFormsAreExtras(t *testing.T) {
	const old = `version 15.6
aaa new-model
aaa group server tacacs+ LAB-TACACS
 server 192.0.2.10
!
aaa authentication login default group LAB-TACACS local
aaa authorization exec default group LAB-TACACS local if-authenticated
aaa accounting exec default start-stop group LAB-TACACS
tacacs-server host 192.0.2.10 single-connection timeout 5 key 7 0822455D0A16
!
line con 0
line vty 0 15
 login authentication default
end
`
	r := standardResult(t, old, standardModern(false))
	if r.State != StateDiffers {
		t.Fatalf("%s %v", r.State, linesOf(r))
	}
	for _, want := range []string{
		"+ tacacs-server host 192.0.2.10 single-connection timeout 5 key (present, not compared)",
		"+ aaa group server tacacs+ LAB-TACACS > server 192.0.2.10",
		"+ aaa authentication login default group LAB-TACACS local",
		"+ aaa authorization exec default group LAB-TACACS local if-authenticated",
		"+ aaa accounting exec default start-stop group LAB-TACACS",
		"- tacacs server TACACS > address ipv4 192.0.2.10",
		"- aaa group server tacacs+ TACACS-GROUP > server name TACACS",
		"- aaa authentication login default group TACACS-GROUP local",
	} {
		if !slices.Contains(linesOf(r), want) {
			t.Errorf("no %q in %v", want, linesOf(r))
		}
	}
	for _, l := range r.Lines {
		if l.Op == OpSame && l.Text != "aaa new-model" && !strings.HasPrefix(l.Text, "line vty 0 15 >") {
			t.Errorf("the old forms satisfied %q", l.Text)
		}
	}
}

// A source interface of the device is nobody's where the scope sets none,
// and another one than the scope's is a difference.
func TestStandardSourceInterface(t *testing.T) {
	// unset: neither compared nor claimed, the value is not in the section
	r := standardResult(t, standardDevice, standardModern(false))
	if r.State != StateOK {
		t.Errorf("unset: %s %v", r.State, linesOf(r))
	}
	ex, _ := Extract("ios", standardDevice, standardModern(false))
	if slices.Contains(ex.Sections[SectionAAA].Lines, "ip tacacs source-interface Loopback0") {
		t.Errorf("an unrendered source interface is in the section: %q", ex.Sections[SectionAAA].Lines)
	}
	// set to another interface: the rendered one is missing, the device's extra
	other := replaceOnce(t, standardDevice, "ip tacacs source-interface Loopback0\n", "ip tacacs source-interface Loopback9\n")
	r = standardResult(t, other, standardModern(true))
	if !slices.Contains(linesOf(r), "- ip tacacs source-interface Loopback0") || !slices.Contains(linesOf(r), "+ ip tacacs source-interface Loopback9") {
		t.Errorf("another interface: %v", linesOf(r))
	}
}

func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("%q is not in the text", old)
	}
	return strings.Replace(s, old, new, 1)
}
