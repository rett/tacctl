package devapply

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// Answers as real devices print them (names are made up, as docs/development
// § Examples says).

// An EX4200 on Junos 12.3 prints no 'Junos:' line.
const ex4200v123 = `fpc0:
--------------------------------------------------------------------------
Hostname: sw1.example.net
Model: ex4200-24t
JUNOS Base OS boot [12.3R9.4]
JUNOS Base OS Software Suite [12.3R9.4]
JUNOS Kernel Software Suite [12.3R9.4]
JUNOS Crypto Software Suite [12.3R9.4]
JUNOS Online Documentation [12.3R9.4]
JUNOS Enterprise Software Suite [12.3R9.4]
JUNOS Packet Forwarding Engine Enterprise Software Suite [12.3R9.4]
JUNOS Routing Software Suite [12.3R9.4]
JUNOS Web Management [12.3R9.4]
JUNOS FIPS mode utilities [12.3R9.4]

{master:0}
`

func TestParseVersionEX4200Junos123(t *testing.T) {
	id, err := parseVersion(ex4200v123)
	if err != nil || id.Hostname != "sw1.example.net" || id.Model != "ex4200-24t" || id.Release != "12.3R9.4" {
		t.Errorf("%+v %v", id, err)
	}
}

// Junos 15.1 prints the 'Junos:' line and the permissions as 'name -- text'
// with no blank before the dashes of a long name.
func TestParseAuthorizationJunos151(t *testing.T) {
	const out = `Current user: 'ops-rw' login: 'alice' class 'ops-rw'
Permissions:
    admin       -- Can view user accounts
    admin-control-- Can modify user accounts
    configure   -- Can enter configuration mode
    pgcp-session-mirroring-control-- Can modify pgcp session mirroring configuration
    all-control -- Can modify any configuration
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
`
	lg, err := parseAuthorization(out)
	if err != nil || lg.Class != "ops-rw" || lg.User != "ops-rw" || lg.Name != "alice" {
		t.Fatalf("%+v %v", lg, err)
	}
	for _, p := range []string{"admin", "admin-control", "configure", "pgcp-session-mirroring-control", "all-control"} {
		if !slices.Contains(lg.Permissions, p) {
			t.Errorf("no permission %q in %q", p, lg.Permissions)
		}
	}
	for _, w := range []string{"Can", "all", "modify", "--"} {
		if slices.Contains(lg.Permissions, w) {
			t.Errorf("a description word %q is a permission: %q", w, lg.Permissions)
		}
	}
	if !lg.CanCommit() {
		t.Errorf("all-control with configure cannot commit: %q", lg.Permissions)
	}
	// 'all' in a description is no permission: a class with 'view-configuration'
	// ('Can view all configuration') and not the rest cannot commit
	lg, err = parseAuthorization("Current user: 'V' login: 'bob' class 'V'\nPermissions:\n    view       -- Can view current values and statistics\n    view-configuration-- Can view all configuration (not including secrets)\n    configure  -- Can enter configuration mode\nIndividual command authorization:\n")
	if err != nil || lg.CanCommit() || slices.Contains(lg.Permissions, "all") {
		t.Errorf("%+v %v", lg, err)
	}
}

func TestParseHistoryJunos151(t *testing.T) {
	const out = `0   2026-03-30 20:42:44 UTC by alice via cli
1   2026-03-30 20:42:14 UTC by alice via cli commit confirmed, rollback in 10mins
    tacctl plan sw1.example.net 2026-10-12T13:11Z by alice
2   2026-06-02 12:18:03 UTC by root via other
3   2026-03-03 14:55:44 UTC by root via cli
`
	h, err := parseHistory(out)
	if err != nil || len(h) != 4 || h[1].RollbackIn != 10 || h[1].Comment != "tacctl plan sw1.example.net 2026-10-12T13:11Z by alice" {
		t.Errorf("%+v %v", h, err)
	}
}

// An SRX on Junos 21.4 prints both the 'Junos:' line and the software
// release line; a node of a standalone box has no 'node0:' header.
func TestParseVersionSRX214(t *testing.T) {
	const out = `Hostname: fw1.example.net
Model: srx345-dc
Junos: 21.4R3-S3.4
JUNOS Software Release [21.4R3-S3.4]
`
	id, err := parseVersion(out)
	if err != nil || id.Hostname != "fw1.example.net" || id.Model != "srx345-dc" || id.Release != "21.4R3-S3.4" {
		t.Errorf("%+v %v", id, err)
	}
}

// An SRX on Junos 11.4 prints the software release line and no 'Junos:' line.
func TestParseVersionSRX114(t *testing.T) {
	const out = `Hostname: fw2.example.net
Model: srx240h2
JUNOS Software Release [11.4R7.5]
`
	id, err := parseVersion(out)
	if err != nil || id.Hostname != "fw2.example.net" || id.Model != "srx240h2" || id.Release != "11.4R7.5" {
		t.Errorf("%+v %v", id, err)
	}
}

// A class with 'all-control' and 'configure' commits on an 11.4 SRX too.
func TestParseAuthorizationSRX114(t *testing.T) {
	const out = `Current user: 'ops-rw' login: 'alice' class 'ops-rw'
Permissions:
    configure   -- Can enter configuration mode
    all-control -- Can modify any configuration
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
`
	lg, err := parseAuthorization(out)
	if err != nil || !lg.CanCommit() {
		t.Errorf("%+v %v", lg, err)
	}
}

// Entries with and without a comment line under them.
func TestParseHistorySRX214(t *testing.T) {
	const out = `0   2026-10-12 13:11:00 UTC by alice via cli commit confirmed, rollback in 5mins
    tacctl plan fw1.example.net 2026-10-12T13:11Z by alice
1   2026-10-12 12:00:00 UTC by alice via cli
    tacctl apply fw1.example.net by alice
2   2026-10-01 09:30:00 UTC by bob via cli
`
	h, err := parseHistory(out)
	if err != nil || len(h) != 3 || h[0].RollbackIn != 5 || h[1].Comment == "" || h[2].Comment != "" {
		t.Errorf("%+v %v", h, err)
	}
}

// A virtual chassis of one member (an EX4600 on Junos 18.1, as it was
// captured; the host and user are made up): 'show version' prints the header
// 'fpc0:' as it does for a chassis of several members, and the answers of
// 'commit check' and 'commit' carry no member label.
const oneMemberVersion = `fpc0:
--------------------------------------------------------------------------
Hostname: jsw1.example.net
Model: ex4600-40f
Junos: 18.1R3-S6.1
JUNOS Base OS boot [18.1R3-S6.1]
`

const (
	oneMemberCheck     = "configuration check succeeds\n"
	oneMemberConfirmed = "configuration check succeeds\n" +
		"commit confirmed will be automatically rolled back in 15 minutes unless confirmed\n" +
		"commit complete\n"
	oneMemberCommit = "configuration check succeeds\ncommit complete\n"
)

// The pre-flight lists one member, and every reply of the capture is read
// for it.
func TestOneMemberVirtualChassisCapture(t *testing.T) {
	id, err := parseVersion(oneMemberVersion)
	if err != nil || id.Hostname != "jsw1.example.net" || id.Model != "ex4600-40f" || id.Release != "18.1R3-S6.1" {
		t.Fatalf("%+v %v", id, err)
	}
	if !slices.Equal(id.Members, []string{"fpc0"}) {
		t.Fatalf("members %q", id.Members)
	}
	if ok, why := checkAnswer(split(oneMemberCheck), id.Members); !ok {
		t.Errorf("commit check: %s", why)
	}
	note := plan.ApplyConfirmedNote(15)
	if ok, why := readCommitted(split(oneMemberConfirmed), id.Members, note, textCommitComplete); !ok {
		t.Errorf("commit confirmed: %s", why)
	}
	if ok, why := readCommitted(split(oneMemberCommit), id.Members, textCommitComplete); !ok {
		t.Errorf("commit: %s", why)
	}
	// the capture's confirmed commit answers with the wrong window
	if ok, _ := readCommitted(split(oneMemberConfirmed), id.Members, plan.ApplyConfirmedNote(10), textCommitComplete); ok {
		t.Error("another window read")
	}
}

// 'show system commit' typed in configuration mode shows the statements of
// [edit system commit], none on this device, so the capture's answer is empty
// whatever the history holds. The apply reads the history in the operational
// mode of a fresh login; an empty answer there is no history and is refused,
// never read as an empty one.
func TestEmptyShowSystemCommitIsRefused(t *testing.T) {
	_, err := parseHistory("\n")
	if !errors.Is(err, ErrUnrecognised) || !strings.HasPrefix(err.Error(), "show system commit: no entry: ") {
		t.Errorf("%v", err)
	}
}
