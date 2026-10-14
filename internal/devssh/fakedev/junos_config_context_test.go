package fakedev

import (
	"testing"
	"time"
)

// The 'compare.context' knob prints the unchanged neighbours of a change
// as a device does; rollback N stays the configuration of history entry N,
// the expiry's 'root via other' entry among them.
func TestJunosCompareContextAndRollbacks(t *testing.T) {
	srv, _, clk := newJunos(t, map[string]string{"compare.context": ""})
	c, _ := shell(t, srv, DefaultUser, DefaultPassword)
	c.send("configure exclusive")
	c.send("set snmp community zz-new authorization read-only")
	cmp := c.send("show | compare")
	mustContain(t, "compare", cmp, "[edit snmp]\n    community public { ... }\n+   community zz-new {\n+       authorization read-only;\n+   }")
	c.send(`commit confirmed 2 comment "tacctl apply x"`)
	c.send("exit")
	_ = c.conn.Close()
	clk.Advance(2 * time.Minute)
	if h := srv.History(); len(h) != 3 || h[0].User != "root" || h[0].Via != "other" || h[1].Comment != "tacctl apply x" {
		t.Fatalf("history %+v", h)
	}
	// rollback 2 is the configuration before the commit, which the expiry
	// restored; rollback 1 the commit's
	for n, empty := range map[string]bool{"0": true, "1": false, "2": true} {
		out, err := execOut(t, srv, DefaultUser, DefaultPassword, "show configuration | compare rollback "+n+" | no-more")
		if err != nil || (out == "") != empty {
			t.Errorf("rollback %s: %q %v", n, out, err)
		}
	}
	out, _ := execOut(t, srv, DefaultUser, DefaultPassword, "show configuration | compare rollback 1 | no-more")
	mustContain(t, "rollback 1", out, "    community public { ... }\n-   community zz-new {\n")
	// without the knob, no context
	srv2, _, _ := newJunos(t, map[string]string{})
	c2, _ := shell(t, srv2, DefaultUser, DefaultPassword)
	c2.send("configure exclusive")
	c2.send("set snmp community zz-new authorization read-only")
	if cmp := c2.send("show | compare"); cmp != "[edit snmp]\n+   community zz-new {\n+       authorization read-only;\n+   }" {
		t.Errorf("no knob: %q", cmp)
	}
}
