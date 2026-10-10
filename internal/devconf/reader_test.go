package devconf

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

type fakeRunner struct {
	out  map[string]string
	errs map[string]error
	ran  []string
}

func (f *fakeRunner) Run(_ context.Context, cmd string) (string, error) {
	f.ran = append(f.ran, cmd)
	if err := f.errs[cmd]; err != nil {
		return "", err
	}
	return f.out[cmd], nil
}

func TestCommands(t *testing.T) {
	setup, read, err := Commands("juniper")
	if err != nil || len(setup) != 0 || read != "show configuration | display inheritance no-comments | display set" {
		t.Errorf("junos: %q %q %v", setup, read, err)
	}
	setup, read, err = Commands("ios-xe")
	if err != nil || !slices.Equal(setup, []string{"terminal length 0"}) || read != "show running-config" {
		t.Errorf("ios: %q %q %v", setup, read, err)
	}
	if _, _, err := Commands("wti"); !errors.Is(err, ErrUnsupportedVendor) {
		t.Errorf("wti: %v", err)
	}
	if _, err := Reader("wti"); !errors.Is(err, ErrUnsupportedVendor) {
		t.Errorf("wti reader: %v", err)
	}
}

func TestReader(t *testing.T) {
	ctx := context.Background()
	t.Run("junos", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{"show configuration | display inheritance no-comments | display set": "set a b\r\n---(more)---\r\nset c d\r\n"}}
		read, err := Reader("junos")
		if err != nil {
			t.Fatal(err)
		}
		got, err := read(ctx, f)
		if err != nil || got != "set a b\nset c d\n" || !slices.Equal(f.ran, []string{"show configuration | display inheritance no-comments | display set"}) {
			t.Errorf("%q %v %q", got, err, f.ran)
		}
	})
	t.Run("ios", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{"show running-config": "version 15.2\n"}}
		read, _ := Reader("ios")
		got, err := read(ctx, f)
		if err != nil || got != "version 15.2" && got != "version 15.2\n" || !slices.Equal(f.ran, []string{"terminal length 0", "show running-config"}) {
			t.Errorf("%q %v %q", got, err, f.ran)
		}
	})
	t.Run("empty", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{}}
		read, _ := Reader("junos")
		if _, err := read(ctx, f); !errors.Is(err, ErrParse) {
			t.Errorf("%v", err)
		}
	})
	t.Run("run error", func(t *testing.T) {
		boom := errors.New("boom")
		f := &fakeRunner{errs: map[string]error{"terminal length 0": boom}}
		read, _ := Reader("ios")
		if _, err := read(ctx, f); !errors.Is(err, boom) || len(f.ran) != 1 {
			t.Errorf("%v %q", err, f.ran)
		}
	})
}

func TestUnwrapNetconf(t *testing.T) {
	for _, tc := range []struct{ name, reply, want string }{
		{"command", `<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><configuration-output>set a b
set snmp contact &quot;NOC &lt;noc@example.net&gt;&quot;
</configuration-output></rpc-reply>`, "set a b\nset snmp contact \"NOC <noc@example.net>\"\n"},
		{"get-configuration", `<rpc-reply><configuration-set>set x y
</configuration-set></rpc-reply>`, "set x y\n"},
		{"declared charset", `<?xml version="1.0" encoding="us-ascii"?><rpc-reply><configuration-output>set a b
</configuration-output></rpc-reply>`, "set a b\n"},
	} {
		got, _, err := UnwrapNetconf(tc.reply)
		if err != nil || got != tc.want {
			t.Errorf("%s: %q %v", tc.name, got, err)
		}
	}
	for name, reply := range map[string]string{
		"rpc-error": `<rpc-reply><rpc-error><error-severity>error</error-severity><error-message>syntax error</error-message></rpc-error></rpc-reply>`,
		"none":      `<rpc-reply><ok/></rpc-reply>`,
		"not xml":   `<<<`,
	} {
		if _, _, err := UnwrapNetconf(reply); !errors.Is(err, ErrParse) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, _, err := UnwrapNetconf(`<rpc-reply><rpc-error><error-severity>error</error-severity><error-message>bad thing</error-message></rpc-error></rpc-reply>`)
	if err == nil || !strings.Contains(err.Error(), "bad thing") {
		t.Errorf("%v", err)
	}
}
