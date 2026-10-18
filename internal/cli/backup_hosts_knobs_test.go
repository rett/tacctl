//go:build testknobs

package cli

import (
	"strings"
	"testing"
)

// A snapshot that cannot be taken stops the registry change, and says that
// the host itself was set up.
func TestHostEnrollThatCannotSnapshotLeavesTheRegistry(t *testing.T) {
	hs := newHostSandbox(t)
	hs.env = append(hs.env, "TACCTL_FAULT=snapshot")
	hs.run(nil, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--allow-uid-mismatch", "--remove-home", "--build-on-host")
	if hs.code == 0 {
		t.Fatalf("enrolled: %q", hs.out.String())
	}
	if hs.registry() != "" {
		t.Errorf("registry %q", hs.registry())
	}
	if !strings.Contains(plain(hs.out.String()), "the registry was not changed; run the same command again") {
		t.Errorf("stdout %q", hs.out.String())
	}
}

// The same for unenroll: the registry line, the pins and the record stay.
func TestHostUnenrollThatCannotSnapshotLeavesTheHost(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--allow-uid-mismatch", "--remove-home", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	before := hs.registry()
	hs.env = append(hs.env, "TACCTL_FAULT=snapshot")
	hs.run(nil, "host", "unenroll", "web1")
	if hs.code == 0 || hs.registry() != before || before == "" {
		t.Errorf("unenroll: %d, registry %q (was %q)", hs.code, hs.registry(), before)
	}
	if !strings.Contains(plain(hs.out.String()), "the host is still registered; run the same command again") {
		t.Errorf("stdout %q", hs.out.String())
	}
}
