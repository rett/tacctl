package lifecycle_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/lifecycle"
)

// wtiPlainDevices is a registry with WTI units in three scopes of the
// multi-scope fixture (lab, prod, dmz) and a Cisco device that is not a unit.
const wtiPlainDevices = `version: 1
settings: {stale_days: 30}
devices:
  wti-lab-1: {address: 192.168.1.5, vendor: wti}
  wti-lab-2: {address: 192.168.1.6, vendor: wti}
  wti-prod-1: {address: 10.1.2.3, vendor: wti}
  lab-sw1: {address: 172.16.0.1, vendor: cisco}
`

// wtiPlainHost is an upgrade host with the multi-scope store, the registry
// above and VarLib in place (an upgrade does not create it).
func wtiPlainHost(t *testing.T, overrides string) *ohost {
	t.Helper()
	o := newOhost(t)
	o.cloned()
	fixture, err := os.ReadFile("../../tests/fixtures/store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	o.write(o.p.StoreFile, string(fixture))
	if err := os.Chmod(o.p.StoreFile, 0o600); err != nil {
		t.Fatal(err)
	}
	o.write(o.p.DevicesFile, wtiPlainDevices)
	o.write(filepath.Join(o.p.VarLib, "devices-seen.json"), "{}\n")
	o.write(o.p.Overrides, overrides)
	o.be.Conf.Reload()
	return o
}

// The upgrade tells once which scopes have plain entries on a unit: the
// scope's own list where it has one, the global list for a scope that has
// none, and says nothing of a scope without a WTI unit or of an entry that
// lists services.
func TestUpgradeTellsOncePlainEntriesOnWTIUnits(t *testing.T) {
	o := wtiPlainHost(t, `mgmt_acl:
  permits:
    - 10.1.0.0/16
    - 203.0.113.0/24:tcp/22
scope_mgmt_acl:
  permits:
    lab:
      - 192.168.5.0/24
      - 192.168.6.0/24:tcp/22
`)
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	got := o.text()
	for _, want := range []string{
		"Management ACL: plain entries now permit every protocol and port on WTI units.",
		"scope lab: 192.168.5.0/24  (2 WTI devices: wti-lab-1, wti-lab-2)",
		"scope prod: 10.1.0.0/16  (1 WTI device: wti-prod-1; the global list)",
		"'iptables -A INPUT -s <cidr> -j ACCEPT'",
		"(0.2.6 rendered ssh and ICMP)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q:\n%s", want, got)
		}
	}
	for _, not := range []string{"192.168.6.0/24", "203.0.113.0/24", "lab-sw1"} {
		if strings.Contains(got, not) {
			t.Errorf("the notice names %q:\n%s", not, got)
		}
	}
	if !lifecycle.WTIPlainNoticeDone(o.p) {
		t.Fatal("no marker")
	}
	// A second upgrade says nothing of it.
	o.stdout.Reset()
	if code := upgrade(o); code != 0 {
		t.Fatalf("second exit %d\n%s", code, o.stderr)
	}
	if strings.Contains(o.text(), "Management ACL: plain entries") {
		t.Errorf("second run:\n%s", o.text())
	}
}

// Nothing to say is nothing printed, and the marker is still written: a plain
// entry added afterwards is added knowing what it means, and the plan warns.
func TestUpgradeWTIPlainNoticeNothingToSay(t *testing.T) {
	for name, overrides := range map[string]string{
		"services only":   "mgmt_acl:\n  permits:\n    - 10.1.0.0/16:tcp/22\n    - 192.168.0.0/16:tcp/22,udp/161\n",
		"no list":         "",
		"ipv6 plain only": "mgmt_acl:\n  permits:\n    - 2001:db8::/32\n",
	} {
		t.Run(name, func(t *testing.T) {
			o := wtiPlainHost(t, overrides)
			if code := upgrade(o); code != 0 {
				t.Fatalf("exit %d\n%s", code, o.stderr)
			}
			if strings.Contains(o.text(), "Management ACL: plain entries") {
				t.Errorf("printed:\n%s", o.text())
			}
			if !lifecycle.WTIPlainNoticeDone(o.p) {
				t.Error("no marker")
			}
			// the entry added afterwards is not announced by the next upgrade
			o.write(o.p.Overrides, "mgmt_acl:\n  permits:\n    - 10.1.0.0/16\n")
			o.be.Conf.Reload()
			o.stdout.Reset()
			if code := upgrade(o); code != 0 {
				t.Fatalf("second exit %d\n%s", code, o.stderr)
			}
			if strings.Contains(o.text(), "Management ACL: plain entries") {
				t.Errorf("second run:\n%s", o.text())
			}
		})
	}
}

// An install with no WTI unit registered is not told, and a fresh install
// (marked at install) is not told either.
func TestUpgradeWTIPlainNoticeNoUnits(t *testing.T) {
	o := wtiPlainHost(t, "mgmt_acl:\n  permits:\n    - 10.1.0.0/16\n")
	o.write(o.p.DevicesFile, "version: 1\ndevices:\n  lab-sw1: {address: 172.16.0.1, vendor: cisco}\n")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if strings.Contains(o.text(), "Management ACL: plain entries") {
		t.Errorf("printed:\n%s", o.text())
	}

	o = wtiPlainHost(t, "mgmt_acl:\n  permits:\n    - 10.1.0.0/16\n")
	if err := lifecycle.MarkWTIPlainNotice(o.p); err != nil {
		t.Fatal(err)
	}
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if strings.Contains(o.text(), "Management ACL: plain entries") {
		t.Errorf("a marked install was told:\n%s", o.text())
	}
}
