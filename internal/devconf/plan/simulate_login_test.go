package plan

import (
	"strings"
	"testing"
)

// The in-memory IOS editor refuses what IOS refuses: 'login authentication
// <list>' under a line before 'aaa new-model' is set (and again after 'no aaa
// new-model'); 'login local' is a line command either way.
func TestSimulatorRefusesLoginAuthenticationBeforeNewModel(t *testing.T) {
	const raw = "hostname r1\n!\nline con 0\n!\nline vty 0 4\n login local\n!\nend\n"
	leaf := Line{Op: OpLine, Context: []string{"line con 0"}, Text: "login authentication CONSOLE"}
	model := Line{Op: OpLine, Text: "aaa new-model"}

	err := ParseIOS(raw).Apply([]Line{leaf})
	if err == nil || !strings.Contains(err.Error(), "before 'aaa new-model'") {
		t.Errorf("a leaf typed before aaa new-model: %v", err)
	}
	if err := ParseIOS(raw).Apply([]Line{{Op: OpLine, Context: []string{"line vty 0 4"}, Text: "login local"}}); err != nil {
		t.Errorf("login local: %v", err)
	}
	if err := ParseIOS(raw).Apply([]Line{model, leaf}); err != nil {
		t.Errorf("a leaf after aaa new-model: %v", err)
	}
	if err := ParseIOS(raw).Apply([]Line{model, {Op: OpNo, Text: "aaa new-model"}, leaf}); err == nil {
		t.Errorf("a leaf after 'no aaa new-model' is accepted")
	}
	// a device that already has it
	if err := ParseIOS("aaa new-model\n" + raw).Apply([]Line{leaf}); err != nil {
		t.Errorf("a device with aaa new-model: %v", err)
	}
}
