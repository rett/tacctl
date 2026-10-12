package lifecycle

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// opHost is a Host whose tacctl.yaml holds text and whose VarLib is a
// fresh temporary directory (so the notice's marker is real).
func opHost(t *testing.T, text string) (*Host, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tacctl.yaml")
	if text != "" {
		if err := os.WriteFile(cfg, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "var"), 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	p := paths.Paths{VarLib: filepath.Join(dir, "var"), OperatorNoticeMarker: filepath.Join(dir, "var", "operator-policy-noted")}
	c := conf.Load(cfg, conf.DefaultBackends)
	h := &Host{Env: &Env{Env: &backend.Env{Conf: c, Paths: p, Out: ui.Output{Stdout: &out, Stderr: &out}}}}
	return h, &out
}

// The device lines are said on the first upgrade onto this release even
// when nothing stale is stored (an install on the shipped values, or one
// whose 0.2.3 lists the upgrade just dropped: its devices still carry
// 'privilege exec all level 7 ping' and Junos 'clear' in OP-CLASS), once,
// and not at all for an install the marker says was told or installed
// fresh.
func TestOperatorNoticeDeviceLinesOnFirstUpgrade(t *testing.T) {
	h, out := opHost(t, "")
	h.operatorNotice()
	got := out.String()
	for _, want := range []string{
		"no privilege exec all level 7 ping", "no privilege exec all level 7 traceroute",
		"no privilege exec all level 7 monitor capture", "no privilege exec level 7 clear counters",
		"no privilege exec level 7 clear line", "no privilege exec level 7 clear ip arp",
		"no privilege exec level 7 clear arp-cache", "no privilege exec level 7 clear mac address-table dynamic",
		"delete system login class OP-CLASS permissions clear", "tacctl device config plan <device>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("first upgrade lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "These stored settings") {
		t.Errorf("nothing stale is stored, but the notice names settings:\n%s", got)
	}
	if !OperatorNoticeDone(h.Paths) {
		t.Fatal("the marker was not written")
	}
	out.Reset()
	h.operatorNotice()
	if out.Len() != 0 {
		t.Errorf("a second upgrade printed:\n%s", out.String())
	}
	// A fresh install is marked at install: nothing is said afterwards.
	h2, out2 := opHost(t, "")
	if err := MarkOperatorNotice(h2.Paths); err != nil {
		t.Fatal(err)
	}
	h2.operatorNotice()
	if out2.Len() != 0 {
		t.Errorf("a fresh install printed:\n%s", out2.String())
	}
}

// A stored 0.2.3 preset value is named with the preset's reset (one line
// for the commands and the Junos sets of a group), and said again on every
// upgrade while it is stored, with the device lines.
func TestOperatorNoticePresetFixLine(t *testing.T) {
	h, out := opHost(t, "")
	c := h.Conf
	if err := policy.WriteJunosSet(c, "operator", conf.JunosDenyCommands, []string{`^(file|request|restart|start|load|op|test|configure|edit|clear (bgp|ospf|ospf3|isis|ldp|rsvp|mpls|pim|igmp|msdp|bfd|vrrp|lacp|system|security|network-access|log|dhcp)|monitor traffic .*write-file|show system rollback)( .*)?$`}); err != nil {
		t.Fatal(err)
	}
	if err := MarkOperatorNotice(h.Paths); err != nil {
		t.Fatal(err)
	}
	h.operatorNotice()
	got := out.String()
	if !strings.Contains(got, "junos operator deny-commands") || !strings.Contains(got, "tacctl group reset operator --preset --only junos") ||
		!strings.Contains(got, "no privilege exec all level 7 ping") || strings.Contains(got, "tacctl group commands reset operator") {
		t.Errorf("notice:\n%s", got)
	}
}
