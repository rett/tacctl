package cli

import (
	"strings"
	"testing"
)

// confText is tacctl.yaml of the sandbox.
func confText(sb *sandbox) string { return sb.read("state/tacctl.yaml") }

// 'config reports' shows both limits with where each stands.
func TestConfigReportsShowDefaultsAndSet(t *testing.T) {
	sb := newSandbox(t, true)
	out := plain(sb.asAlice("", "config", "reports"))
	for _, want := range []string{
		"  max-size:  10 MiB   (default; ", "  max-count: 100 reports   (default; ", "A user's own limit wins ('tacctl user reports-limit').",
	} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("show lacks %q: %d\n%s", want, sb.code, out)
		}
	}
	if show := plain(sb.asAlice("", "config", "reports", "show")); show != out {
		t.Errorf("show differs from the bare verb:\n%s\n%s", show, out)
	}
	sb.asAlice("", "config", "reports", "max-size", "20Mi")
	sb.asAlice("", "config", "reports", "max-count", "0")
	out = plain(sb.asAlice("", "config", "reports"))
	for _, want := range []string{"  max-size:  20 MiB   (set; ", "  max-count: no cap   (set; "} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if text := confText(sb); !strings.Contains(text, "max_size: 20971520") || !strings.Contains(text, "max_count: 0") {
		t.Errorf("tacctl.yaml:\n%s", text)
	}
}

// The size takes bytes or Ki, Mi, Gi; 0 is no cap; the value is stored in
// bytes and said back.
func TestConfigReportsSetSize(t *testing.T) {
	sb := newSandbox(t, true)
	for _, c := range []struct{ in, stored, said string }{
		{"123456", "123456", "123456 bytes"},
		{"512Ki", "524288", "512 KiB"},
		{"1Gi", "1073741824", "1 GiB"},
		{"0", "0", "no cap"},
	} {
		sb.asAlice("", "config", "reports", "max-size", c.in)
		sb.expect(0, "The largest report set to "+c.said+".", "")
		if text := confText(sb); !strings.Contains(text, "max_size: "+c.stored+"\n") {
			t.Errorf("%s: tacctl.yaml\n%s", c.in, text)
		}
	}
	// the default is no override: the key goes
	sb.asAlice("", "config", "reports", "max-size", "10Mi")
	sb.expect(0, "The largest report set to 10 MiB.", "")
	if text := confText(sb); strings.Contains(text, "max_size") {
		t.Errorf("the default was stored:\n%s", text)
	}
	if out := plain(sb.asAlice("", "config", "reports")); !strings.Contains(out, "max-size:  10 MiB   (default; ") {
		t.Errorf("show after the default:\n%s", out)
	}
	if out := sb.asAlice("", "config", "reports", "max-size"); !strings.Contains(out, "Largest report: 10 MiB") || !strings.Contains(out, "Usage: tacctl config reports max-size") {
		t.Errorf("bare max-size:\n%s", out)
	}
}

func TestConfigReportsSetCount(t *testing.T) {
	sb := newSandbox(t, true)
	for _, c := range []struct{ in, said string }{{"500", "500 reports"}, {"1", "1 report"}, {"0", "no cap"}, {"100000", "100000 reports"}} {
		sb.asAlice("", "config", "reports", "max-count", c.in)
		sb.expect(0, "The most reports per user set to "+c.said+".", "")
		if text := confText(sb); !strings.Contains(text, "max_count: "+c.in+"\n") {
			t.Errorf("%s: tacctl.yaml\n%s", c.in, text)
		}
	}
	if out := sb.asAlice("", "config", "reports", "max-count"); !strings.Contains(out, "Most reports per user: 100000 reports") {
		t.Errorf("bare max-count:\n%s", out)
	}
}

// A bad value is refused with a message and leaves the file as it was.
func TestConfigReportsRefusesBadValues(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "config", "reports", "max-size", "5Mi")
	before := confText(sb)
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"max-size", "2Gi"}, "over the largest size limit"},
		{[]string{"max-size", "1073741825"}, "over the largest size limit"},
		{[]string{"max-size", "-1"}, "is not a size"},
		{[]string{"max-size", "10MB"}, "is not a size"},
		{[]string{"max-size", "1.5Mi"}, "is not a size"},
		{[]string{"max-size", "Mi"}, "is not a size"},
		{[]string{"max-size", "big"}, "is not a size"},
		{[]string{"max-size", "1Mi", "2Mi"}, "Unknown argument: '2Mi'"},
		{[]string{"max-count", "100001"}, "over the largest count limit"},
		{[]string{"max-count", "-1"}, "is not a count"},
		{[]string{"max-count", "10Mi"}, "is not a count"},
		{[]string{"max-count", "many"}, "is not a count"},
		{[]string{"max-count", "5", "6"}, "Unknown argument: '6'"},
		{[]string{"show", "extra"}, "Unknown argument: 'extra'"},
	} {
		sb.asAlice("", append([]string{"config", "reports"}, c.args...)...)
		sb.expect(1, "", c.err)
		if confText(sb) != before {
			t.Errorf("%v changed tacctl.yaml:\n%s", c.args, confText(sb))
		}
	}
	sb.asAlice("", "config", "reports", "frob")
	sb.expect(1, "", "Unknown subcommand: 'frob'")
}

// A hand-edited file with a value the schema refuses reads as the default,
// and 'config validate' is where that is said.
func TestConfigReportsOutOfRangeReadAsDefaults(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "reports:\n  max_size: 2000000000\n  max_count: -4\n", 0o600)
	out := plain(sb.cfgRun("", []string{"config", "reports", "show"}, nil))
	for _, w := range []string{"max-size:  10 MiB", "max-count: 100 reports"} {
		if sb.code != 0 || !strings.Contains(out, w) {
			t.Errorf("show lacks %q: %d\n%s", w, sb.code, out)
		}
	}
	sb.cfgRun("", []string{"config", "validate"}, nil)
	if sb.code == 0 || !strings.Contains(sb.stderr()+sb.out.String(), "reports.max_size") {
		t.Errorf("validate: %d %q %q", sb.code, sb.stderr(), sb.out.String())
	}
}

// The usage is printed by -h and help, exit 0, and names the verbs.
func TestConfigReportsUsage(t *testing.T) {
	sb := newSandbox(t, true)
	out := plain(sb.asAlice("", "config", "reports", "help"))
	if sb.code != 0 || !strings.Contains(out, "Usage: tacctl config reports [show|max-size|max-count] [<value>]") || !strings.Contains(out, "tacctl config reports max-size 20Mi") {
		t.Errorf("help: %d\n%s", sb.code, out)
	}
	for _, w := range []string{"-h", "--help"} {
		out := plain(sb.asAlice("", "config", "reports", w))
		if sb.code != 0 || !strings.Contains(out, "max-size") || !strings.Contains(out, "max-count") {
			t.Errorf("%s: %d\n%s", w, sb.code, out)
		}
	}
}

// The setters leave an audit detail line with the old and the new value.
func TestConfigReportsAuditDetail(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "config", "reports", "max-size", "20Mi")
	sb.asAlice("", "config", "reports", "max-count", "7")
	var lines []string
	for _, c := range sb.runner.Calls() {
		if c.Name == "logger" {
			lines = append(lines, strings.Join(c.Args, " "))
		}
	}
	all := strings.Join(lines, "\n")
	for _, w := range []string{"key=max_count", "from=100", "to=7"} {
		if !strings.Contains(all, w) {
			t.Errorf("no %q in the audit lines:\n%s", w, all)
		}
	}
}
