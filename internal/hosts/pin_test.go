package hosts

import (
	"context"
	"strconv"
	"testing"
)

func TestScanTarget(t *testing.T) {
	for _, c := range []struct {
		target, port string
		host         string
		p            int
		ok           bool
	}{
		{"admin@web1.example.net", "", "web1.example.net", 22, true},
		{"web1.example.net", "2222", "web1.example.net", 2222, true},
		{"root@192.0.2.50", "22", "192.0.2.50", 22, true},
		{"web1", "junk", "web1", 22, true},
		{"web1", "70000", "web1", 22, true},
		{Local, "", "", 0, false},
		{"", "", "", 0, false},
		{"admin@", "", "", 22, false},
	} {
		h, p, ok := ScanTarget(c.target, c.port)
		if h != c.host || p != c.p || ok != c.ok {
			t.Errorf("%q %q: %q %d %v", c.target, c.port, h, p, ok)
		}
	}
}

func TestPinKeys(t *testing.T) {
	var got []string
	env := &Env{PinHostKeys: func(_ context.Context, name, host string, port int) {
		got = append(got, name+" "+host+" "+strconv.Itoa(port))
	}}
	env.PinKeys(context.Background(), Entry{Name: "web1", Target: "admin@web1.example.net", Port: "2200"})
	env.PinKeys(context.Background(), Entry{Name: "srv", Target: Local})
	if len(got) != 1 || got[0] != "web1 web1.example.net 2200" {
		t.Errorf("pinned %q", got)
	}
	(&Env{}).PinKeys(context.Background(), Entry{Name: "web1", Target: "web1"}) // no pinner: nothing
}
