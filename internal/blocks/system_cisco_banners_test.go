package blocks

import (
	"strings"
	"testing"
)

const bannersText = "banner login <<'EOF'\nAuthorized use only.\nEOF\n" +
	"banner motd <<'EOF'\nMaintenance window: Sunday.\nEOF\n" +
	"banner exec <<'EOF'\nYou are logged in.\nEOF\n"

func TestIOSBannersParseRenderAndRoundTrip(t *testing.T) {
	b, fs := LintIOSSystem(bannersText, LayerScope)
	if HasErrors(fs) {
		t.Fatalf("errors:\n%s", dump(fs))
	}
	if b.BannerBodyOf("login") != "Authorized use only." || b.BannerBodyOf("motd") != "Maintenance window: Sunday." || b.BannerBodyOf("exec") != "You are logged in." {
		t.Errorf("bodies: %+v %+v %+v", b.Banner, b.BannerMOTD, b.BannerExec)
	}
	st := IOSSystemStatements(b)
	want := []string{"banner login ^", "Authorized use only.", "^", "banner motd ^", "Maintenance window: Sunday.", "^", "banner exec ^", "You are logged in.", "^"}
	if strings.Join(st, "|") != strings.Join(want, "|") {
		t.Errorf("statements: %q", st)
	}
	if out := b.String(false); out != bannersText {
		t.Errorf("String:\n%s", out)
	}
	if el := b.String(true); strings.Contains(el, "Maintenance") || strings.Count(el, "<message:") != 3 {
		t.Errorf("elided:\n%s", el)
	}
	if b.Empty() {
		t.Error("a block of banners is empty")
	}
	// stated twice, empty, with a terminator line: refused by kind
	for _, c := range []struct{ text, want string }{
		{"banner motd <<'EOF'\na\nEOF\nbanner motd <<'EOF'\nb\nEOF\n", "the motd banner is stated twice"},
		{"banner exec <<'EOF'\n\nEOF\n", "the exec banner is empty"},
		{"banner exec <<'EOF'\n<message: 2 lines, 3 characters, id 12345678>\nEOF\n", "the exec banner is a placeholder"},
		{"banner motd <<'EOF'\n" + strings.Repeat("x", 81) + "\nEOF\n", "of the motd banner is 81 characters"},
		{"banner motd <<'EOF'\nnever closed\n", "the heredoc of the motd banner is never closed"},
	} {
		if _, fs := LintIOSSystem(c.text, LayerScope); !anyFindingHas(fs, SevError, c.want) {
			t.Errorf("%q: want %q:\n%s", c.text, c.want, dump(fs))
		}
	}
}

func TestIOSBannersLayersAndNoLines(t *testing.T) {
	scope, _ := ParseIOSSystem(bannersText)
	dev, _ := ParseIOSSystem("banner motd <<'EOF'\nDevice notice.\nEOF\nno banner exec\n")
	got := ResolveIOSSystem(nil, scope, dev)
	if got.BannerBodyOf("motd") != "Device notice." || got.BannerBodyOf("login") != "Authorized use only." || got.BannerOf("exec") != nil {
		t.Errorf("resolved: %q %q %q", got.BannerBodyOf("login"), got.BannerBodyOf("motd"), got.BannerBodyOf("exec"))
	}
	if out := dev.String(false); !strings.Contains(out, "no banner exec\n") {
		t.Errorf("String lacks the no line:\n%s", out)
	}
	d2, fs := ParseIOSSystem("no banner motd\n")
	if HasErrors(fs) || IOSSystemNotManagedLines(d2)[0] != "no banner motd" {
		t.Errorf("no banner motd: %v", IOSSystemNotManagedLines(d2))
	}
}

func TestAdoptIOSBannersOfEveryKind(t *testing.T) {
	raw := strings.Join([]string{"banner exec ^C", "exec text", "^C", "banner motd ^C", "motd text", "^C", "banner login ^C", "login text", "^C", "banner incoming ^C", "x", "^C", ""}, "\n")
	res := AdoptIOSSystem(raw, nil, nil, LayerDevice)
	for _, want := range []string{"banner login <<'EOF'\nlogin text\nEOF\n", "banner motd <<'EOF'\nmotd text\nEOF\n", "banner exec <<'EOF'\nexec text\nEOF\n"} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("the draft lacks %q:\n%s", want, res.Text)
		}
	}
	if strings.Contains(res.Text, "incoming") {
		t.Errorf("another banner is adopted:\n%s", res.Text)
	}
	same, _ := ParseIOSSystem("banner motd <<'EOF'\nmotd text\nEOF\n")
	res = AdoptIOSSystem(raw, same, nil, LayerDevice)
	if strings.Contains(res.Text, "motd") {
		t.Errorf("a banner stated already is repeated:\n%s", res.Text)
	}
}
