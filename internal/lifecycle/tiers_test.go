package lifecycle_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
)

// store15 is the multi-scope fixture with extra groups: neteng and ops at
// priv-lvl 15, helpdesk at 14.
func (o *ohost) store15() {
	o.t.Helper()
	fixture, err := os.ReadFile("../../tests/fixtures/store.multiscope.yaml")
	if err != nil {
		o.t.Fatal(err)
	}
	extra := "groups:\n  neteng: {priv_lvl: 15, juniper_class: ENG-CLASS}\n  helpdesk: {priv_lvl: 14, juniper_class: HD-CLASS}\n  ops: {priv_lvl: 15, juniper_class: OPS-CLASS}\n"
	o.write(o.p.StoreFile, strings.Replace(string(fixture), "groups:\n", extra, 1))
	if err := os.Chmod(o.p.StoreFile, 0o600); err != nil {
		o.t.Fatal(err)
	}
}

// S2: upgrade writes tier.<group>: superuser for every group other than the
// built-in superuser at priv-lvl 15 or more that has no setting (what 0.2.2
// treated it as), one line each, after a snapshot, and leaves everything
// else alone; a second upgrade changes nothing.
func TestUpgradePinsTheTiersOfGroupsAt15(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.store15()
	// ops has a setting already: it is the operator's, and stays.
	o.write(o.p.Overrides, "tier:\n  ops: engineer\n")
	o.be.Conf.Reload()
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	y := readFile(t, o.p.Overrides)
	if !strings.Contains(y, "neteng: superuser") || !strings.Contains(y, "ops: engineer") || strings.Contains(y, "helpdesk") || strings.Contains(y, "superuser: superuser") {
		t.Errorf("tacctl.yaml:\n%s", y)
	}
	// The migration is recorded outside tacctl.yaml, in the state directory.
	if !strings.HasPrefix(o.p.TierPinMarker, o.p.VarLib+"/") || !lifecycle.TierPinDone(o.p) {
		t.Errorf("no marker at %s", o.p.TierPinMarker)
	}
	if !strings.Contains(o.text(), "Group 'neteng' (priv-lvl 15): tier recorded as superuser in "+o.p.Overrides+" (what 0.2.2 treated it as; change it with: tacctl group edit neteng tier <tier>).") ||
		strings.Contains(o.text(), "Group 'ops'") || strings.Contains(o.text(), "Group 'helpdesk'") {
		t.Errorf("output:\n%s", o.text())
	}
	snaps, _ := os.ReadDir(o.p.BackupDir)
	if len(snaps) == 0 {
		t.Error("no snapshot was taken")
	}
	// Idempotent: nothing is said, written or snapshotted again.
	o.stdout.Reset()
	if code := upgrade(o); code != 0 {
		t.Fatalf("second exit %d\n%s", code, o.stderr)
	}
	if strings.Contains(o.text(), "tier recorded") || readFile(t, o.p.Overrides) != y {
		t.Errorf("second run:\n%s", o.text())
	}
	if again, _ := os.ReadDir(o.p.BackupDir); len(again) != len(snaps) {
		t.Errorf("the second run took a snapshot: %d -> %d", len(snaps), len(again))
	}
}

// S2: with no tacctl.yaml the upgrade creates it with the settings.
func TestUpgradePinsIntoAMissingConf(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.store15()
	if _, err := os.Stat(o.p.Overrides); err == nil {
		t.Fatal("the sandbox has a tacctl.yaml")
	}
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	y := readFile(t, o.p.Overrides)
	if !strings.Contains(y, "neteng: superuser") || !strings.Contains(y, "ops: superuser") {
		t.Errorf("tacctl.yaml:\n%s", y)
	}
	if !lifecycle.TierPinDone(o.p) {
		t.Errorf("no marker at %s", o.p.TierPinMarker)
	}
	// Once the marker is there a missing tacctl.yaml is no reason to write
	// one: the groups stay ambiguous until a superuser sets them.
	if err := os.Remove(o.p.Overrides); err != nil {
		t.Fatal(err)
	}
	o.be.Conf.Reload()
	o.stdout.Reset()
	if code := upgrade(o); code != 0 {
		t.Fatalf("second exit %d\n%s", code, o.stderr)
	}
	if _, err := os.Stat(o.p.Overrides); err == nil || strings.Contains(o.text(), "tier recorded") {
		t.Errorf("the second upgrade pinned again:\n%s\n%s", o.text(), readFile(t, o.p.Overrides))
	}
}

// S1, the sequence of the review: the first upgrade records neteng as
// superuser and the operator sets it to engineer; its key is lost later (an
// old tacctl.yaml copied back, a hand edit); the next routine upgrade must
// not write neteng: superuser again. The group stays ambiguous (the gate
// holds its members at the operator tier) until a superuser sets the tier.
func TestUpgradeDoesNotRepinALostTierAfterTheMigration(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.store15()
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	// neteng is an engineer group; then the file is replaced by an old copy
	// without the key.
	o.write(o.p.Overrides, "tier:\n  neteng: engineer\n  ops: superuser\n")
	o.be.Conf.Reload()
	o.write(o.p.Overrides, "tier:\n  ops: superuser\n")
	o.be.Conf.Reload()
	before := readFile(t, o.p.Overrides)
	snaps, _ := os.ReadDir(o.p.BackupDir)
	o.stdout.Reset()
	for i := 0; i < 2; i++ {
		if code := upgrade(o); code != 0 {
			t.Fatalf("upgrade %d: exit %d\n%s", i, code, o.stderr)
		}
		if got := readFile(t, o.p.Overrides); got != before || strings.Contains(got, "neteng") || strings.Contains(o.text(), "tier recorded") {
			t.Fatalf("upgrade %d wrote the lost tier back:\n%s\n%s", i, got, o.text())
		}
	}
	if again, _ := os.ReadDir(o.p.BackupDir); len(again) != len(snaps) {
		t.Errorf("a snapshot was taken for nothing: %d -> %d", len(snaps), len(again))
	}
	o.be.Conf.Reload()
	_, m, _, err := model.Load(model.Paths{Store: o.p.StoreFile, Config: o.p.Config, DatesDir: o.p.PWDatesDir, DisabledDir: filepath.Join(o.p.BackupDir, "disabled")})
	if err != nil {
		t.Fatal(err)
	}
	if got := policy.UnsetTierGroups(o.be.Conf, m); len(got) != 1 || got[0] != "neteng" {
		t.Errorf("ambiguous groups %v, want [neteng]", got)
	}
}

// S1: an unreadable tacctl.yaml leaves no marker, so the migration runs at
// the first upgrade after it is fixed.
func TestUpgradeLeavesNoMarkerWhenItCouldNotPin(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.store15()
	o.write(o.p.Overrides, "tier:\n  ops: [engineer\n")
	o.be.Conf.Reload()
	upgrade(o)
	if lifecycle.TierPinDone(o.p) {
		t.Fatal("a marker was left although nothing was pinned")
	}
	o.write(o.p.Overrides, "tier:\n  ops: engineer\n")
	o.be.Conf.Reload()
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if y := readFile(t, o.p.Overrides); !strings.Contains(y, "neteng: superuser") || !lifecycle.TierPinDone(o.p) {
		t.Errorf("after the repair:\n%s", y)
	}
}

// B1 (the migration side): a built-in readonly or operator at priv-lvl 15
// is recorded as superuser, what 0.2.2 gave it; the built-in superuser gets
// no line.
func TestUpgradePinsBuiltinGroupsRaisedTo15(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.store15()
	s := readFile(t, o.p.StoreFile)
	o.write(o.p.StoreFile, strings.Replace(s, "operator: {priv_lvl: 7,", "operator: {priv_lvl: 15,", 1))
	if err := os.Chmod(o.p.StoreFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	y := readFile(t, o.p.Overrides)
	if !strings.Contains(y, "operator: superuser") || strings.Contains(y, "readonly:") || strings.Contains(y, "\n  superuser:") {
		t.Errorf("tacctl.yaml:\n%s", y)
	}
}

// S1: after a store import only the groups the import brought are pinned;
// one the store had keeps what tacctl.yaml says of it, also when that is
// nothing (the setting was lost).
func TestPinImportedGroupTiersSkipsGroupsTheStoreHad(t *testing.T) {
	o := newOhost(t)
	o.store15()
	o.write(o.p.Overrides, "backends:\n  enabled: [tacacs]\n")
	o.be.Conf.Reload()
	snaps := 0
	done := lifecycle.PinImportedGroupTiers(o.p, o.be.Conf, o.out, func() error { snaps++; return nil }, []string{"neteng", "helpdesk", "superuser"})
	if len(done) != 1 || done[0] != "ops" || snaps != 1 {
		t.Fatalf("pinned %v (%d snapshots), want [ops]", done, snaps)
	}
	y := readFile(t, o.p.Overrides)
	if !strings.Contains(y, "ops: superuser") || strings.Contains(y, "neteng") {
		t.Errorf("tacctl.yaml:\n%s", y)
	}
	// Not once-only: a later import pins the groups it brings, marker or not.
	if lifecycle.TierPinDone(o.p) {
		t.Error("the import wrote the upgrade's marker")
	}
	// Nothing known before (first import into an empty store): all of them.
	o.write(o.p.Overrides, "")
	o.be.Conf.Reload()
	if done = lifecycle.PinImportedGroupTiers(o.p, o.be.Conf, o.out, nil, nil); len(done) != 2 {
		t.Errorf("first import pinned %v, want neteng and ops", done)
	}
}

// S1: a fresh install records that there is nothing to migrate, and
// uninstall takes the marker away.
func TestMarkTierPinRoundTrip(t *testing.T) {
	o := newOhost(t)
	if lifecycle.TierPinDone(o.p) {
		t.Fatal("marker before anything ran")
	}
	if err := lifecycle.MarkTierPin(o.p); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(o.p.TierPinMarker); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("marker: %v %v", st, err)
	}
	if !lifecycle.TierPinDone(o.p) {
		t.Error("marker not seen")
	}
}

// S2: a tacctl.yaml that cannot be read is not written over: a warning, and
// the groups stay ambiguous until a superuser sets their tier.
func TestUpgradeDoesNotPinThroughAnUnreadableConf(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.store15()
	broken := "tier:\n  ops: [engineer\n"
	o.write(o.p.Overrides, broken)
	o.be.Conf.Reload()
	upgrade(o)
	if readFile(t, o.p.Overrides) != broken {
		t.Errorf("tacctl.yaml was written:\n%s", readFile(t, o.p.Overrides))
	}
	if !strings.Contains(o.text()+o.stderr.String(), "Tier settings of groups not recorded") {
		t.Errorf("no warning:\n%s\n%s", o.text(), o.stderr)
	}
}
