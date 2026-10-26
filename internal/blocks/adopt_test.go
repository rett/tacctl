package blocks

import (
	"strings"
	"testing"
)

// The templates are comments only; their example, uncommented, is a block
// that passes the check (a person following the template gets what it says).
func TestTemplatesAreCommentsAndTheirExampleIsValid(t *testing.T) {
	for _, block := range KnownBlocks {
		for _, layer := range []Layer{LayerScope, LayerDevice} {
			tpl := Template(block, layer)
			doc, fs, err := LintBlock(block, tpl, layer)
			if err != nil || HasErrors(fs) || !doc.Empty() {
				t.Errorf("%s template: %v %v empty=%v", block, err, fs, doc.Empty())
			}
			_, example, ok := strings.Cut(tpl, "# Example")
			if !ok {
				t.Errorf("%s template has no example", block)
				continue
			}
			var lines []string
			for _, l := range strings.Split(example, "\n")[1:] {
				if rest, ok := strings.CutPrefix(l, "# "); ok {
					lines = append(lines, rest)
				}
			}
			d, fs, err := LintBlock(block, strings.Join(lines, "\n")+"\n", layer)
			if err != nil || HasErrors(fs) || d.Empty() {
				t.Errorf("%s example: %v %v empty=%v\n%s", block, err, fs, d.Empty(), strings.Join(lines, "\n"))
			}
		}
	}
	if got := Template("nothing", LayerScope); got != "\n" {
		t.Errorf("unknown block: %q", got)
	}
}

func TestCommentOut(t *testing.T) {
	if got := CommentOut("a\n\n  b\n"); got != "# a\n#\n#   b\n" {
		t.Errorf("%q", got)
	}
}

const adoptSNMPRaw = `set snmp name jsw1.lab.example.net
set snmp engine-id local 0123456789
set snmp location "Rack 4"
set snmp contact noc@example.net
set snmp community scope-own-string authorization read-only
set snmp community scope-own-string clients 192.0.2.0/24
set snmp community scope-own-string client-list-name TACCTL-SNMP
set snmp community poller-string authorization read-only
set snmp community poller-string clients 198.51.100.7/32
set snmp community poller-string clients 198.51.100.8/32
set snmp community "two words" authorization read-write
set snmp community "two words" clients 198.51.100.0/24 restrict
set snmp community /* SECRET-DATA */ authorization read-only
set snmp community /* SECRET-DATA */ clients 203.0.113.0/24
set snmp community $9$abcdefghij authorization read-only
set snmp community $9$abcdefghij clients 203.0.113.9/32
set snmp community $9$zyxwvutsrq clients 203.0.113.10/32
set snmp trap-group traps-string version v2
set snmp trap-group traps-string categories link
set snmp trap-group traps-string targets 198.51.100.20
set snmp trap-options agent-address outgoing-interface
set snmp trap-options source-address 192.0.2.1
set snmp v3 usm local-engine user alice authentication-sha authentication-password "$9$abcdefgh"
set snmp client-list TACCTL-SNMP 192.0.2.0/24
set snmp rmon alarm 1 variable foo
`

func TestAdoptSNMPDraft(t *testing.T) {
	own := AdoptOwn{Community: "scope-own-string", Lines: map[string]bool{
		"set snmp location \"Rack 4\"": true, "set snmp contact noc@example.net": true,
	}}
	res := AdoptSNMP(adoptSNMPRaw, own, nil, nil, LayerDevice)
	want := "set snmp community poller-string authorization read-only\n" +
		"set snmp community poller-string clients 198.51.100.7/32\n" +
		"set snmp community poller-string clients 198.51.100.8/32\n" +
		"set snmp community \"two words\" authorization read-write\n" +
		"set snmp community \"two words\" clients 198.51.100.0/24 restrict\n" +
		"set snmp trap-group traps-string version v2\n" +
		"set snmp trap-group traps-string categories link\n" +
		"set snmp trap-group traps-string targets 198.51.100.20\n" +
		"set snmp trap-options agent-address outgoing-interface\n" +
		"set snmp trap-options source-address 192.0.2.1\n"
	if res.Text != want {
		t.Errorf("draft:\n%s\nwant:\n%s", res.Text, want)
	}
	// the draft is a block that passes the check
	if _, fs := Lint(res.Text, LayerDevice); HasErrors(fs) {
		t.Errorf("the draft does not lint: %v", fs)
	}
	if res.Statements != 10 || res.Objects != 5 {
		t.Errorf("counts: %d statements, %d objects", res.Statements, res.Objects)
	}
	all := strings.Join(append(append([]string{res.Text}, res.Notes...), res.Left...), "\n")
	for _, secret := range []string{"scope-own-string", "abcdefghij", "zyxwvutsrq", "jsw1.lab.example.net", "0123456789"} {
		if strings.Contains(strings.Join(append(append([]string{}, res.Notes...), res.Left...), "\n"), secret) {
			t.Errorf("the report holds %q:\n%s", secret, all)
		}
	}
	for _, secret := range []string{"scope-own-string", "abcdefghij", "TACCTL-SNMP", "name jsw1", "engine-id"} {
		if strings.Contains(res.Text, secret) {
			t.Errorf("the draft holds %q:\n%s", secret, res.Text)
		}
	}
	notes := strings.Join(res.Notes, "\n")
	for _, w := range []string{"location, contact): 6 statements, not adopted", "never part of a block: 2 statements, not adopted", "and the like): 2 statements, not adopted"} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
	// masked and ciphertext: a line each, per statement, with the shape and
	// no value; the two ciphertext strings are told apart by their number
	left := strings.Join(res.Left, "\n")
	for _, w := range []string{
		"this community is masked (the login lacks the secret permission), so it cannot be adopted: authorization read-only",
		"this community is masked (the login lacks the secret permission), so it cannot be adopted: clients 203.0.113.0/24",
		"this community 1 is shown only as the device's ciphertext, so its string cannot be adopted: authorization read-only",
		"this community 1 is shown only as the device's ciphertext, so its string cannot be adopted: clients 203.0.113.9/32",
		"this community 2 is shown only as the device's ciphertext, so its string cannot be adopted: clients 203.0.113.10/32",
	} {
		if !strings.Contains(left, w) {
			t.Errorf("left lacks %q:\n%s", w, left)
		}
	}
}

func TestAdoptSNMPSubtractsWhatTheLevelsState(t *testing.T) {
	scope, _ := Parse("set snmp community poller-string authorization read-only\n" +
		"set snmp community poller-string clients 198.51.100.8/32\n" +
		"set snmp community poller-string clients 198.51.100.7/32\n" +
		"set snmp trap-group traps-string version v2\n")
	// The device level: the scope's identical object is not repeated; an
	// object that differs is the device's exception, whole; another is new.
	res := AdoptSNMP(adoptSNMPRaw, AdoptOwn{Community: "scope-own-string"}, nil, scope, LayerDevice)
	if strings.Contains(res.Text, "poller-string") {
		t.Errorf("an object the scope states identically is repeated:\n%s", res.Text)
	}
	if !strings.Contains(res.Text, "set snmp trap-group traps-string categories link\n") ||
		!strings.Contains(res.Text, "set snmp trap-group traps-string version v2\n") {
		t.Errorf("the trap group differs from the scope's and is the device's, whole:\n%s", res.Text)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "or the scope's: 1 object, not repeated") {
		t.Errorf("notes:\n%s", strings.Join(res.Notes, "\n"))
	}
	// The same file: an identical object is a repeat, a different one is left
	// in place and counted.
	res = AdoptSNMP(adoptSNMPRaw, AdoptOwn{Community: "scope-own-string"}, scope, nil, LayerDevice)
	if strings.Contains(res.Text, "poller-string") || strings.Contains(res.Text, "traps-string") {
		t.Errorf("an object of this block is adopted again:\n%s", res.Text)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "in this block already with other statements: 1 object, left as they are") {
		t.Errorf("notes:\n%s", strings.Join(res.Notes, "\n"))
	}
}

func TestAdoptSNMPOfNothingAndOfGarbage(t *testing.T) {
	for _, raw := range []string{"", "\n\n", "set snmp name x\n", "garbage with \"a quote\nset snmp community \"open\n"} {
		res := AdoptSNMP(raw, AdoptOwn{}, nil, nil, LayerDevice)
		if res.Text != "" || res.Statements != 0 {
			t.Errorf("%q: %q", raw, res.Text)
		}
	}
}

const adoptSystemRaw = `set system host-name jsw1
set system domain-name Lab.Example.NET
set system domain-search lab.example.net
set system time-zone UTC
set system name-server 192.0.2.53
set system name-server 192.0.2.54
set system ntp server 192.0.2.123
set system ntp server 192.0.2.123 prefer
set system ntp server 192.0.2.124 version 4
set system ntp boot-server 192.0.2.125
set system ntp authentication-key 1 type md5 value "$9$abcdefghij"
set system ntp authentication-key 2 type sha1 value "$9$klmnopqrst"
set system ntp trusted-key 1
set system login message "Authorized use only.\n  *** keep out ***\nsite \"jsw1\""
set system login user alice class super-user
set system login user alice authentication encrypted-password "$6$zzzzzzzzzzzz"
set system services ssh root-login deny
`

func TestAdoptSystemDraft(t *testing.T) {
	res := AdoptSystem(adoptSystemRaw, nil, nil, LayerDevice)
	want := "set system login message <<'EOF'\nAuthorized use only.\n  *** keep out ***\nsite \"jsw1\"\nEOF\n" +
		"set system domain-name Lab.Example.NET\n" +
		"set system domain-search lab.example.net\n" +
		"set system time-zone UTC\n" +
		"set system name-server 192.0.2.53\n" +
		"set system name-server 192.0.2.54\n" +
		"set system ntp server 192.0.2.123 prefer\n" +
		"set system ntp server 192.0.2.124 version 4\n" +
		"set system ntp boot-server 192.0.2.125\n" +
		"set system ntp trusted-key 1\n"
	if res.Text != want {
		t.Errorf("draft:\n%s\nwant:\n%s", res.Text, want)
	}
	if _, fs := LintSystem(res.Text, LayerScope); HasErrors(fs) {
		t.Errorf("the draft does not lint: %v", fs)
	}
	all := strings.Join(append(append([]string{}, res.Notes...), res.Left...), "\n")
	for _, secret := range []string{"abcdefghij", "klmnopqrst", "zzzzzzzzzzzz", "alice", "Authorized"} {
		if strings.Contains(all, secret) || strings.Contains(res.Text, secret) && secret != "Authorized" {
			t.Errorf("a value reaches the report or the draft: %q\n%s", secret, all)
		}
	}
	for _, w := range []string{"ntp authentication-key 1 holds the device's ciphertext", "ntp authentication-key 2 holds the device's ciphertext"} {
		if !strings.Contains(all, w) {
			t.Errorf("no %q:\n%s", w, all)
		}
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "and the like): 4 statements, not adopted") {
		t.Errorf("notes:\n%s", strings.Join(res.Notes, "\n"))
	}
}

func TestAdoptSystemSubtractsWhatTheLevelsState(t *testing.T) {
	scope, _ := ParseSystem("set system login message <<'EOF'\nAuthorized use only.\n  *** keep out ***\nsite \"jsw1\"\nEOF\n" +
		"set system domain-name lab.example.net\nset system time-zone Europe/Oslo\nset system name-server 192.0.2.53\n" +
		"set system ntp server 192.0.2.123 prefer\nset system ntp server 192.0.2.124\n")
	res := AdoptSystem(adoptSystemRaw, nil, scope, LayerDevice)
	// the message, the domain (case aside is the same host name only for
	// domain-search; domain-name differs by case here, so it is the device's),
	// the name server and the preferred server are the scope's already
	for _, gone := range []string{"login message", "name-server 192.0.2.53", "ntp server 192.0.2.123 prefer"} {
		if strings.Contains(res.Text, gone) {
			t.Errorf("%q is stated by the scope and repeated:\n%s", gone, res.Text)
		}
	}
	// a single value the scope states differently is the device's exception;
	// a server with other options is the device's, whole
	for _, want := range []string{"set system time-zone UTC\n", "set system ntp server 192.0.2.124 version 4\n", "set system name-server 192.0.2.54\n"} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("lacks %q:\n%s", want, res.Text)
		}
	}
	// the same file: a different single value is left in place
	res = AdoptSystem(adoptSystemRaw, scope, nil, LayerDevice)
	if strings.Contains(res.Text, "time-zone") || strings.Contains(res.Text, "ntp server 192.0.2.124") {
		t.Errorf("a statement that conflicts with this block's is adopted:\n%s", res.Text)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "differing from what this block states") {
		t.Errorf("notes:\n%s", strings.Join(res.Notes, "\n"))
	}
}

func TestAdoptSystemLoginMessageProblems(t *testing.T) {
	res := AdoptSystem("set system login message \"an \\q escape\"\n", nil, nil, LayerDevice)
	if res.Text != "" || len(res.Left) != 1 || !strings.Contains(res.Left[0], "login message could not be read") {
		t.Errorf("%q %q", res.Text, res.Left)
	}
	if strings.Contains(res.Left[0], "an \\q") {
		t.Errorf("the message is echoed: %q", res.Left[0])
	}
}
