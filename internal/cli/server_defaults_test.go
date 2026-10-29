package cli

import (
	"strings"
	"testing"
)

// The recorded server address (server.addresses) is the default of --server of
// the walkthroughs: the lines that say where the server is name it, an
// explicit --server wins for that run, and with nothing recorded the detected
// address (192.0.2.1 here) is named as before.
func TestWalkthroughsDefaultToTheRecordedServerAddress(t *testing.T) {
	// the line that tells the device where the server is
	line := map[string]string{"cisco": "address ipv4 %s\n", "juniper": "set system tacplus-server %s secret ", "wti": "Primary Host/Address       : %s\n"}
	for _, vendor := range []string{"cisco", "juniper", "wti"} {
		t.Run(vendor, func(t *testing.T) {
			at := func(addr string) string { return strings.Replace(line[vendor], "%s", addr, 1) }
			hs := newHostSandbox(t)
			walk := func(extra ...string) string {
				hs.run(nil, append([]string{"config", vendor, "--scope", "lab"}, extra...)...)
				if hs.code != 0 {
					t.Fatalf("exit %d\n%s%s", hs.code, hs.out.String(), hs.err.String())
				}
				return plain(hs.out.String())
			}
			none := walk()
			if !strings.Contains(none, at("192.0.2.1")) || strings.Contains(none, "Two server addresses") {
				t.Fatalf("nothing recorded:\n%s", none)
			}
			hs.run(nil, "server", "addresses", "add", "203.0.113.9")
			hs.expect(0, "", "")
			rec := walk()
			if !strings.Contains(rec, "203.0.113.9") || !strings.Contains(rec, "(server.addresses)") || !strings.Contains(rec, "Two server addresses") {
				t.Errorf("recorded:\n%s", rec)
			}
			// the device is told the recorded address where it was told the
			// detected one; tacctl's own source stays the detected one
			if !strings.Contains(rec, at("203.0.113.9")) || strings.Contains(rec, at("192.0.2.1")) || !strings.Contains(rec, "tacctl reaches the device from 192.0.2.1 (detected)") {
				t.Errorf("the recorded address does not stand where the detected one did:\n%s", rec)
			}
			// an explicit --server wins for that run
			exp := walk("--server", "198.51.100.7")
			if !strings.Contains(exp, at("198.51.100.7")) || strings.Contains(exp, "203.0.113.9") || !strings.Contains(exp, "(--server)") {
				t.Errorf("--server:\n%s", exp)
			}
			// and the registered device's walkthrough reads the same default
			hs.run(nil, "device", "add", "sw1", "192.168.1.5", "--vendor", vendor, "--no-host-key", "--no-lookup")
			hs.run(nil, "device", "config", "show", "sw1")
			if got := plain(hs.out.String()); hs.code != 0 || !strings.Contains(got, at("203.0.113.9")) {
				t.Errorf("device config show: exit %d\n%s%s", hs.code, got, hs.err.String())
			}
		})
	}
}

// config linux script takes the recorded address as its default and still
// takes --server; with nothing recorded the route's source address.
func TestLinuxScriptDefaultsToTheRecordedServerAddress(t *testing.T) {
	hs := newHostSandbox(t)
	script := func(extra ...string) string {
		out := hs.path("script.sh")
		hs.run(nil, append([]string{"config", "linux", "script", "--scope", "lab", "-o", out}, extra...)...)
		if hs.code != 0 {
			t.Fatalf("exit %d\n%s%s", hs.code, hs.out.String(), hs.err.String())
		}
		return hs.read("script.sh")
	}
	if got := script(); !strings.Contains(got, "TAC_SERVER=192.0.2.1\n") {
		t.Errorf("nothing recorded: %s", firstLinesWith(got, "TAC_SERVER"))
	}
	hs.run(nil, "server", "addresses", "add", "203.0.113.9")
	if got := script(); !strings.Contains(got, "TAC_SERVER=203.0.113.9\n") {
		t.Errorf("recorded: %s", firstLinesWith(got, "TAC_SERVER"))
	}
	if got := script("--server", "198.51.100.7"); !strings.Contains(got, "TAC_SERVER=198.51.100.7\n") {
		t.Errorf("--server: %s", firstLinesWith(got, "TAC_SERVER"))
	}
}

func firstLinesWith(text, word string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, word) {
			out = append(out, l)
		}
	}
	return strings.Join(out, " | ")
}

// host enroll tells a new host the recorded address; a host enrolled already
// keeps the address it has (--server changes it); --server wins; with nothing
// recorded the route to the host decides, as before.
func TestHostEnrollDefaultsToTheRecordedServerAddress(t *testing.T) {
	enrol := func(hs *hostSandbox, name string, extra ...string) string {
		hs.run(nil, append([]string{"host", "enroll", "admin@" + name + ".example.net", "--scope", "lab", "--build-on-host"}, extra...)...)
		if hs.code != 0 {
			t.Fatalf("%s: exit %d\n%s%s", name, hs.code, hs.out.String(), hs.err.String())
		}
		return hs.pushed
	}
	// every host of the sandbox resolves to one address, so one host to a sandbox
	hs := newHostSandbox(t)
	if got := enrol(hs, "web1"); !strings.Contains(got, "TAC_SERVER=192.0.2.1\n") {
		t.Errorf("nothing recorded: %s", firstLinesWith(got, "TAC_SERVER"))
	}
	hs.run(nil, "server", "addresses", "add", "203.0.113.9")
	// a registered host keeps its own address when enrolled again, and --server changes it
	if got := enrol(hs, "web1"); !strings.Contains(got, "TAC_SERVER=192.0.2.1\n") {
		t.Errorf("web1 again: %s", firstLinesWith(got, "TAC_SERVER"))
	}
	if got := enrol(hs, "web1", "--server", "198.51.100.7"); !strings.Contains(got, "TAC_SERVER=198.51.100.7\n") {
		t.Errorf("web1 --server: %s", firstLinesWith(got, "TAC_SERVER"))
	}
	// a new host is told the recorded one
	hs = newHostSandbox(t)
	hs.run(nil, "server", "addresses", "add", "203.0.113.9")
	if got := enrol(hs, "web2"); !strings.Contains(got, "TAC_SERVER=203.0.113.9\n") || !strings.Contains(hs.registry(), "web2|admin@web2.example.net||lab|203.0.113.9|\n") {
		t.Errorf("recorded: %s\n%s", firstLinesWith(got, "TAC_SERVER"), hs.registry())
	}
	// --server wins
	hs = newHostSandbox(t)
	hs.run(nil, "server", "addresses", "add", "203.0.113.9")
	if got := enrol(hs, "web3", "--server", "198.51.100.7"); !strings.Contains(got, "TAC_SERVER=198.51.100.7\n") {
		t.Errorf("--server: %s", firstLinesWith(got, "TAC_SERVER"))
	}
}

// The managed scope's prefixes are derived from the recorded address: a sync
// of the server whose setting and entry differ makes them follow the setting.
func TestManagedScopePrefixesFollowTheRecordedAddress(t *testing.T) {
	hs := newHostSandbox(t)
	enrolLocal(t, hs, "--server", "192.0.2.10")
	hs.write("state/tacctl.yaml", "server:\n  addresses:\n  - 198.51.100.20\n", 0o600)
	hs.run(nil, "host", "sync", "authsrv")
	out := plain(hs.out.String())
	if hs.code != 0 || !strings.Contains(out, "Repaired the managed server login.") || !strings.Contains(hs.store(), "prefixes: [127.0.0.1/32, 198.51.100.20/32]") {
		t.Errorf("exit %d\n%s%s\n%s", hs.code, out, hs.err.String(), hs.store())
	}
}
