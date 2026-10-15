package fakedev

import "testing"

// 'netconf.follow': the NETCONF subsystem answers exactly when the committed
// configuration holds a 'system services netconf' statement, and
// 'netconf.disable.noeffect' keeps it answering (D148's test device).
func TestNetconfFollowsTheCommittedService(t *testing.T) {
	subsystem := func(t *testing.T, knobs map[string]string) error {
		t.Helper()
		srv, _, _ := newJunos(t, knobs)
		conn, err := dialJunos(t, srv, DefaultUser, DefaultPassword)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		sess, err := conn.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sess.Close() }()
		return sess.RequestSubsystem("netconf")
	}
	// without the knob the subsystem answers whatever is configured
	if err := subsystem(t, map[string]string{}); err != nil {
		t.Errorf("no knob: %v", err)
	}
	// with it, a configuration with no service refuses the subsystem
	if err := subsystem(t, map[string]string{"netconf.follow": ""}); err == nil {
		t.Error("netconf.follow: the subsystem answered with no service configured")
	}
	// and the knob that makes a delete ineffective keeps it answering
	if err := subsystem(t, map[string]string{"netconf.follow": "", "netconf.disable.noeffect": ""}); err != nil {
		t.Errorf("noeffect: %v", err)
	}
}
