package devreg

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testKnownHosts = "/etc/tacctl/known_hosts"

// The option vector per vendor, legacy-ssh and pin (docs/plans/
// operator-console.md 5.2 and 3.7).
func TestSSHOptionsTable(t *testing.T) {
	rsa := KeyStrings([]HostKey{testKey(t, "rsa")})
	ct := []string{"-o", "ConnectTimeout=10"}
	wti := []string{"-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no"}
	legacy := []string{"-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
		"-o", "HostKeyAlgorithms=+ssh-rsa", "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa"}
	pin := func(name string) []string {
		return []string{"-o", "UserKnownHostsFile=" + testKnownHosts, "-o", "StrictHostKeyChecking=yes",
			"-o", "HostKeyAlias=" + name, "-o", "UpdateHostKeys=no"}
	}
	dev := func(vendor string, legacy, pinned bool) Entry {
		e := Entry{Device: Device{Name: "d1", Address: "192.0.2.1", Vendor: vendor, LegacySSH: legacy}, Source: SourceDevice}
		if pinned {
			e.HostKeys = rsa
		}
		return e
	}
	host := Entry{Device: Device{Name: "web1", Vendor: VendorLinux, HostKeys: rsa}, Source: SourceHost, Target: "admin@web1.example.net"}
	for _, c := range []struct {
		name string
		e    Entry
		want []string
	}{
		{"cisco", dev("cisco", false, false), ct},
		{"cisco legacy", dev("cisco", true, false), slices.Concat(ct, legacy)},
		{"cisco legacy pinned", dev("cisco", true, true), slices.Concat(ct, legacy, pin("d1"))},
		{"cisco pinned", dev("cisco", false, true), slices.Concat(ct, pin("d1"))},
		{"juniper", dev("juniper", false, false), ct},
		{"juniper pinned", dev("juniper", false, true), slices.Concat(ct, pin("d1"))},
		{"wti", dev("wti", false, false), slices.Concat(ct, wti)},
		{"wti pinned", dev("wti", false, true), slices.Concat(ct, wti, pin("d1"))},
		{"other", dev("other", false, false), ct},
		{"other legacy", dev("other", true, false), slices.Concat(ct, legacy)},
		{"linux host pinned", host, slices.Concat(ct, pin("web1"))},
	} {
		if got := OptionArgs(SSHOptions(c.e, testKnownHosts)); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
	// Never an option that weakens the check, never BatchMode.
	for _, v := range []string{"cisco", "juniper", "wti", "other"} {
		for _, l := range []bool{false, true} {
			for _, p := range []bool{false, true} {
				args := strings.Join(OptionArgs(SSHOptions(dev(v, l, p), testKnownHosts)), " ")
				for _, bad := range []string{"StrictHostKeyChecking=no", "StrictHostKeyChecking=accept-new", "/dev/null", "BatchMode"} {
					if strings.Contains(args, bad) {
						t.Errorf("%s legacy=%v pinned=%v: %q", v, l, p, args)
					}
				}
			}
		}
	}
}

func TestSSHTarget(t *testing.T) {
	for _, c := range []struct {
		e    Entry
		want string
		ok   bool
	}{
		{Entry{Device: Device{Address: "10.99.0.1"}, Source: SourceDevice}, "10.99.0.1", true},
		{Entry{Device: Device{Address: "10.99.0.1", Hostname: "sw1.example.net"}, Source: SourceDevice}, "sw1.example.net", true},
		{Entry{Device: Device{Hostname: "web1.example.net"}, Source: SourceHost, Target: "admin@web1.example.net"}, "web1.example.net", true},
		{Entry{Device: Device{Hostname: "local"}, Source: SourceHost, Target: "local"}, "", false},
		{Entry{Source: SourceDevice}, "", false},
	} {
		if got, ok := SSHTarget(c.e); got != c.want || ok != c.ok {
			t.Errorf("SSHTarget(%+v) = %q %v", c.e, got, ok)
		}
	}
}

func TestSSHOptionConfigLine(t *testing.T) {
	if got := (SSHOption{"IdentityFile", "/k/my key"}).ConfigLine(); got != `    IdentityFile "/k/my key"` {
		t.Errorf("%q", got)
	}
	if got := (SSHOption{"Port", "2222"}).ConfigLine(); got != "    Port 2222" {
		t.Errorf("%q", got)
	}
}

// The design's 5.4 sample, with the pinning lines of 3.7: a legacy Cisco
// device and an enrolled host pinned, a WTI unit unpinned; a host enrolled
// with --local has no block.
func TestSSHConfigGolden(t *testing.T) {
	rsa, ed := testKey(t, "rsa"), testKey(t, "ed25519")
	entries := []Entry{
		{Device: Device{Name: "core-sw1", Address: "10.99.0.1", Vendor: "cisco", LegacySSH: true, HostKeys: KeyStrings([]HostKey{rsa})}, Source: SourceDevice},
		{Device: Device{Name: "oob-con1", Address: "10.99.0.9", Vendor: "wti"}, Source: SourceDevice},
		{Device: Device{Name: "web1", Hostname: "web1.example.net", Login: "admin", Port: 2222, Vendor: VendorLinux,
			HostKeys: KeyStrings([]HostKey{ed})}, Source: SourceHost, Target: "admin@web1.example.net", Identity: "~/.ssh/id_web1"},
		{Device: Device{Name: "authsrv", Hostname: "local", Vendor: VendorLinux}, Source: SourceHost, Target: "local"},
	}
	got := SSHConfig(entries, testKnownHosts, "the dev server", time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC))
	golden := filepath.Join("testdata", "ssh_config.golden")
	if *updateGolden {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("ssh-config:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(string(got), "authsrv") {
		t.Error("a --local host has a Host block")
	}
	if string(SSHConfig(nil, testKnownHosts, "s", time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC))) !=
		"# Generated by tacctl device ssh-config on s, 2026-10-03. Re-run after registry changes.\n" {
		t.Error("an empty fragment is the header alone")
	}
}
