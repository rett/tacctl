package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// withDevice registers a device in the sandbox's devices file.
func (hs *hostSandbox) withDevice(name, address string) {
	hs.t.Helper()
	f := devreg.Empty()
	f.Devices = []*devreg.Device{{Name: name, Address: address, Vendor: "cisco"}}
	text, err := f.Text()
	if err != nil {
		hs.t.Fatal(err)
	}
	hs.write("state/devices.yaml", string(text), 0o600)
}

// A new host name is a name a device could have: no tacctl word, and no
// host or device already has it ignoring case. Every refusal changes
// nothing and goes nowhere near ssh.
func TestHostEnrollNewNameRules(t *testing.T) {
	hs := newHostSandbox(t)
	hs.withDevice("core-sw1", "192.0.2.77")

	for _, c := range []struct {
		args []string
		errs []string
	}{
		{[]string{"web1", "--name", "all"}, []string{"'all' is a tacctl word and cannot name a host", "Nothing was changed."}},
		{[]string{"web1", "--name", "Local"}, []string{"'Local' is a tacctl word and cannot name a host"}},
		{[]string{"--local", "--name", "device"}, []string{"'device' is a tacctl word and cannot name a host"}},
		// The name worked out from the target is held to the same rule.
		{[]string{"all.example.net"}, []string{"'all' is a tacctl word and cannot name a host"}},
		{[]string{"web1", "--name", "CORE-sw1"}, []string{"'core-sw1' is already registered as a device (192.0.2.77)", "Nothing was changed."}},
	} {
		r := hs.runner()
		hs.run(r, append([]string{"host", "enroll", "--scope", "lab"}, c.args...)...)
		hs.expect(1, "", c.errs[0])
		for _, e := range c.errs[1:] {
			if !strings.Contains(hs.err.String(), e) {
				t.Errorf("%q: stderr lacks %q: %q", c.args, e, hs.err.String())
			}
		}
		if r.Called("ssh") || hs.registry() != "" {
			t.Errorf("%q: ssh %v, registry %q", c.args, r.Called("ssh"), hs.registry())
		}
	}

	hs.run(nil, "host", "enroll", "web1", "--scope", "lab")
	hs.expect(0, "Host 'web1' enrolled.", "")
	before := hs.registry()

	// The same name in another case is the enrolled host: refused, and the
	// registered spelling is named.
	for _, name := range []string{"Web1", "WEB1"} {
		r := hs.runner()
		hs.run(r, "host", "enroll", "web1", "--name", name, "--scope", "lab")
		hs.expect(1, "", "'web1' is enrolled; names are not case-sensitive. Nothing was changed.")
		if !strings.Contains(hs.err.String(), "--name web1") {
			t.Errorf("%s: no way out: %q", name, hs.err.String())
		}
		if r.Called("ssh") || hs.registry() != before {
			t.Errorf("%s: ssh %v, registry %q", name, r.Called("ssh"), hs.registry())
		}
	}

	// Under its registered name the host is enrolled again, as before.
	hs.run(nil, "host", "enroll", "web1", "--name", "web1")
	hs.expect(0, "Host 'web1' enrolled.", "")
	if hs.registry() != before {
		t.Errorf("registry %q, want %q", hs.registry(), before)
	}

	// A name that is only a reserved word in an old registry is not
	// refused for a host already enrolled under that exact spelling.
	hs.write("state/linux-hosts", "all|root@web1||lab|192.0.2.1|\n", 0o600)
	hs.run(nil, "host", "enroll", "web1", "--name", "all")
	hs.expect(0, "Host 'all' enrolled.", "")
}

// A value option with no value is a usage error that names the option; the
// 0.2.13 command exited 1 without a word.
func TestHostEnrollOptionNeedsAValue(t *testing.T) {
	hs := newHostSandbox(t)
	for _, opt := range []string{"--scope", "--server", "--name", "--port", "--identity"} {
		for _, args := range [][]string{{"web1", opt}, {"web1", opt, ""}} {
			r := hs.runner()
			hs.run(r, append([]string{"host", "enroll"}, args...)...)
			hs.expect(1, "", opt+" needs a value.")
			if !strings.Contains(hs.err.String(), "Usage: tacctl host enroll") {
				t.Errorf("%q: no usage line: %q", args, hs.err.String())
			}
			if r.Called("ssh") || hs.registry() != "" {
				t.Errorf("%q: went on", args)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(hs.dir, "state", "linux-hosts")); err == nil {
		t.Error("a registry was made")
	}
}

// Two enrolments of one name in two cases that both passed the check (one is
// a name from before, with upper case): the registry's lock decides, the
// first to write wins and the other is refused with nothing written, never
// two hosts sharing one pin record.
func TestHostEnrollOfAFoldEqualNameFinishedMeanwhileIsRefused(t *testing.T) {
	hs := newHostSandbox(t)
	r := hs.runner()
	written := false
	const other = "Web1|root@other.example.net||lab|192.0.2.1|\n"
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" }, func(c execx.Cmd) (execx.Result, error) {
		if strings.Contains(strings.Join(c.Args, " "), "mktemp") {
			_, _ = io.ReadAll(c.Stdin)
			return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
		}
		if !written {
			// The other enrolment finishes while this one's script runs.
			written = true
			hs.write("state/linux-hosts", other, 0o600)
		}
		return execx.Result{}, nil
	})
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--name", "web1", "--scope", "lab", "--allow-uid-mismatch", "--remove-home", "--build-on-host")
	hs.expect(1, "", "'Web1' is enrolled; names are not case-sensitive. The client script already ran on the host; the registry was not changed.")
	if hs.registry() != other {
		t.Errorf("registry %q", hs.registry())
	}
	if strings.Contains(hs.out.String(), "enrolled.") {
		t.Errorf("stdout %q", hs.out.String())
	}
}

// lateDevice is a runner whose first ssh call after the script was pushed
// registers a device called name at addr, the way a 'device add' that
// finishes while the client script runs does. It reports the devices file
// the device left.
func (hs *hostSandbox) lateDevice(name, addr string) (*fake.Runner, *string) {
	r := hs.runner()
	devices := new(string)
	done := false
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" || c.Name == "bash" }, func(c execx.Cmd) (execx.Result, error) {
		if strings.Contains(strings.Join(c.Args, " "), "mktemp") {
			_, _ = io.ReadAll(c.Stdin)
			return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
		}
		if !done {
			done = true
			hs.withDevice(name, addr)
			*devices = hs.read("state/devices.yaml")
		}
		return execx.Result{}, nil
	})
	return r, devices
}

// A device registered while the client script ran (D235, D236): the name is
// checked against the device registry again once the registry line is
// written, and the line is taken back. Nothing else of the enrolment is
// written: no record, no pins, no audit line.
func TestHostEnrollOfANameADeviceTookMeanwhileIsRefused(t *testing.T) {
	hs := newHostSandbox(t)
	r, devices := hs.lateDevice("web1", "192.0.2.60")
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--name", "web1", "--scope", "lab", "--allow-uid-mismatch", "--remove-home", "--build-on-host")
	hs.expect(1, "", "A device named 'web1' (192.0.2.60) was registered while the client script ran; a host and a device cannot share a name. "+
		"The script already ran on the host; the registry was not changed. Enroll it under a name of its own: "+
		"tacctl host enroll admin@web1.example.net --scope lab --name <other>")
	if !r.CalledRegexp(`sudo -n bash /tmp/tacctl.AbCd1234`) {
		t.Errorf("the script did not run: %q", r.Argvs())
	}
	if hs.registry() != "" {
		t.Errorf("registry %q", hs.registry())
	}
	if rec := hs.record("web1"); rec != "" {
		t.Errorf("a record was written: %s", rec)
	}
	if got := hs.read("state/devices.yaml"); got != *devices || strings.Contains(got, "hostkeys") {
		t.Errorf("the device registry changed:\n%s\nwas\n%s", got, *devices)
	}
	if r.CalledRegexp(`host enroll name=`) || strings.Contains(hs.out.String(), "enrolled") {
		t.Errorf("enrolled: %q\n%s", r.Argvs(), hs.out.String())
	}
	if r.Called("ssh-keyscan") {
		t.Errorf("keys were scanned: %q", r.Argvs())
	}

	// --local names its own flag in the way on, and a name equal ignoring
	// case is the same name.
	hs = newHostSandbox(t)
	hs.loopback()
	r, _ = hs.lateDevice("Web2", "192.0.2.61")
	hs.run(r, "host", "enroll", "--local", "--name", "web2", "--scope", "lab")
	hs.expect(1, "", "A device named 'Web2' (192.0.2.61) was registered while the client script ran")
	if !strings.Contains(hs.err.String(), "tacctl host enroll --local --scope lab --name <other>") || hs.registry() != "" {
		t.Errorf("stderr %q registry %q", hs.err.String(), hs.registry())
	}
}

// A host that is enrolled already keeps its own name: a re-enrolment is not
// held to the device namespace a second time (the first check refuses a
// device that is there before the script).
func TestHostReEnrollSkipsTheLateDeviceCheck(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "host", "enroll", "admin@web1.example.net", "--name", "web1", "--scope", "lab")
	hs.expect(0, "Host 'web1' enrolled.", "")
	r, _ := hs.lateDevice("web1", "192.0.2.62")
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--name", "web1", "--scope", "lab")
	hs.expect(0, "Host 'web1' enrolled.", "")
	if !strings.HasPrefix(hs.registry(), "web1|") {
		t.Errorf("registry %q", hs.registry())
	}
}

// The late refusals leave two things of the enrolment in place: the host's
// own scope opened to both protocols and the bench address added to the
// scope. Both are warned of, with the way to undo them.
func TestHostEnrollLateDeviceConflictWarnsOfAnOpenedScope(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "add", "linux-web1", "--prefixes", "192.0.2.50/32", "--secret", "generate")
	hs.expect(0, "", "")
	hs.run(nil, "scope", "protocols", "linux-web1", "set", "radius")
	if hs.code != 0 {
		t.Fatalf("protocols: %d %q", hs.code, hs.err.String())
	}
	r, _ := hs.lateDevice("web1", "192.0.2.60")
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--name", "web1", "--method", "tacplus", "--build-on-host")
	hs.expect(1, "opening it to tacacs for this host.", "was registered while the client script ran")
	if !strings.Contains(hs.out.String(), "Scope 'linux-web1' is still open to tacacs, radius; see 'tacctl scope protocols linux-web1'.") {
		t.Errorf("no warning of the open scope: %q", hs.out.String())
	}
	if hs.registry() != "" {
		t.Errorf("registry %q", hs.registry())
	}
}

func TestHostEnrollLateConflictsWarnOfTheStagingAddress(t *testing.T) {
	const staged = "Staging address 192.0.2.50/32 stays in scope 'lab' for the host 'web1', which is not enrolled; remove it: tacctl scope staging remove 192.0.2.50/32"

	// A device registered while the script ran.
	hs := newHostSandbox(t)
	r, _ := hs.lateDevice("web1", "192.0.2.60")
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--name", "web1", "--scope", "lab", "--staging", "--build-on-host")
	hs.expect(1, "", "was registered while the client script ran")
	if !strings.Contains(hs.out.String(), staged) {
		t.Errorf("device: no warning of the staging address: %q", hs.out.String())
	}
	if !strings.HasPrefix(hs.read("state/staging"), "192.0.2.50/32|lab|host|web1|") {
		t.Errorf("staging %q", hs.read("state/staging"))
	}

	// A host of the same name, in another case, enrolled meanwhile.
	hs = newHostSandbox(t)
	r = hs.runner()
	written := false
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" }, func(c execx.Cmd) (execx.Result, error) {
		if strings.Contains(strings.Join(c.Args, " "), "mktemp") {
			_, _ = io.ReadAll(c.Stdin)
			return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
		}
		if !written {
			written = true
			hs.write("state/linux-hosts", "Web1|root@other.example.net||lab|192.0.2.1|\n", 0o600)
		}
		return execx.Result{}, nil
	})
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--name", "web1", "--scope", "lab", "--staging", "--build-on-host")
	hs.expect(1, "", "'Web1' is enrolled; names are not case-sensitive.")
	if !strings.Contains(hs.out.String(), staged) {
		t.Errorf("taken: no warning of the staging address: %q", hs.out.String())
	}

	// Nothing staged, nothing said: the scope answers the address.
	hs = newHostSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "add", "192.0.2.0/24")
	r, _ = hs.lateDevice("web1", "192.0.2.60")
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--name", "web1", "--scope", "lab", "--staging", "--build-on-host")
	hs.expect(1, "", "was registered while the client script ran")
	if strings.Contains(hs.out.String(), "Staging address") || strings.Contains(hs.out.String(), "still open") {
		t.Errorf("a warning with nothing left: %q", hs.out.String())
	}
}

// A new name an orphaned break-glass hold is recorded under is refused like
// 'host rename' refuses it: the files word that hold as a device's until it is
// released, and an enrolment does not render.
func TestHostEnrollRefusesTheNameOfAnOrphanHold(t *testing.T) {
	hs := newHostSandbox(t)
	hs.write("state/tacctl.yaml", "breakglass_hold:\n  web9:\n    address: 192.0.2.99\n    reason: console recovery\n    since: 2026-10-01 10:00\n    by: root\n", 0o600)
	r := hs.runner()
	hs.run(r, "host", "enroll", "admin@web1.example.net", "--name", "web9", "--scope", "lab", "--build-on-host")
	hs.expect(1, "", "A break-glass hold is recorded under the name 'web9' (192.0.2.99)")
	if !strings.Contains(hs.err.String(), "A hold is removed only by 'tacctl breakglass release web9'. Nothing was changed.") {
		t.Errorf("stderr %q", hs.err.String())
	}
	if r.Called("ssh") || hs.registry() != "" {
		t.Errorf("ssh %v registry %q", r.Called("ssh"), hs.registry())
	}
}
