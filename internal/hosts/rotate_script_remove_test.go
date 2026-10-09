package hosts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The grant goes before anything else: if userdel cannot run (the account is
// logged in) the account is left without its sudoers line, and the output
// says so. The group goes only when it is the account's own.
func TestRotateRemoveDropsTheLineFirstAndTheGroupWithCare(t *testing.T) {
	h := newStubHost(t)
	h.plant("old", "1500", RotateMarker, true)
	if err := writeSudoers(t, h, []byte("# x\nold ALL=(ALL:ALL) NOPASSWD: ALL\nother ALL=(ALL:ALL) ALL\n")); err != nil {
		t.Fatal(err)
	}
	rm := RotateRemove{Account: "old", Range: testRange, Avoid: testAvoid}.Script()
	out, code := h.run(rm, "STUB_USERDEL_FAIL=1")
	su, _ := os.ReadFile(h.sudoers)
	if code != 1 || !strings.Contains(out, "Its sudoers line is gone and the account is expired") || h.uidOf("old") != "1500" ||
		strings.Contains(string(su), "old ") || !strings.Contains(string(su), "other ALL") {
		t.Errorf("userdel fails: %d\n%s\n%s", code, out, su)
	}
	// A group of the same name that is neither the account's UID nor its
	// primary group is somebody else's: kept.
	h = newStubHost(t)
	h.plant("old", "1500", RotateMarker, true)
	h.write("group", strings.Replace(h.read("group"), "old:x:1500:", "old:x:2000:", 1))
	if out, code := h.run(rm); code != 0 || strings.Contains(h.calls(), "groupdel") || !strings.Contains(h.read("group"), "old:x:2000:") {
		t.Errorf("foreign group: %d\n%s\n%s", code, out, h.calls())
	}
	// Its own group (the number of the account) goes.
	h = newStubHost(t)
	h.plant("old", "1500", RotateMarker, true)
	if out, code := h.run(rm); code != 0 || !strings.Contains(h.calls(), "groupdel old") {
		t.Errorf("own group: %d\n%s\n%s", code, out, h.calls())
	}
}

// SudoersOnly (an adopted account whose proof failed): the account's line
// goes and nothing else.
func TestRotateRemoveSudoersOnly(t *testing.T) {
	h := newStubHost(t)
	h.plant("deploy2", "1500", RotateMarker, true)
	if err := writeSudoers(t, h, []byte("# x\ndeploy2 ALL=(ALL:ALL) NOPASSWD: ALL\nother ALL=(ALL:ALL) ALL\n")); err != nil {
		t.Fatal(err)
	}
	out, code := h.run(RotateRemove{Account: "deploy2", SudoersOnly: true, Range: testRange}.Script())
	su, _ := os.ReadFile(h.sudoers)
	if code != 0 || !strings.Contains(out, "the account itself was left") || h.uidOf("deploy2") != "1500" || strings.Contains(h.calls(), "userdel") ||
		strings.Contains(string(su), "deploy2") || !strings.Contains(string(su), "other ALL") || !fileExists(filepath.Join(h.state, "deploy2")) || !fileExists(filepath.Join(h.home, "deploy2")) {
		t.Errorf("%d\n%s\n%s", code, out, su)
	}
}
