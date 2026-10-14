package devssh

import "testing"

func TestJunosOtherPrompt(t *testing.T) {
	for in, want := range map[string]string{
		"u@h> ": "u@h# ",
		"u@h# ": "u@h> ",
		"u@h>":  "",
		"rtr#":  "",
		"":      "",
	} {
		if got := junosOtherPrompt(in); got != want {
			t.Errorf("junosOtherPrompt(%q) = %q, want %q", in, got, want)
		}
	}
	if profiles[VendorCisco].other != nil {
		t.Error("the Cisco profile has one prompt")
	}
}

func TestLocationLineIsNeverAPrompt(t *testing.T) {
	for line, want := range map[string]bool{
		"[edit]":                      true,
		"[edit system login]":         true,
		"{master:0}[edit]":            true,
		"{master:1}[edit protocols]":  true,
		"[edit] ":                     false,
		"edit":                        false,
		"[editor]":                    false,
		"x [edit]":                    false,
		"{master:0}":                  false,
		"u@h# ":                       false,
		"{master:0}[edit] u@h# ":      false,
		"[edit system]\nu@h# ":        false,
		"+  [edit interfaces xe-0/0]": false,
	} {
		if got := LocationLine(line); got != want {
			t.Errorf("LocationLine(%q) = %v, want %v", line, got, want)
		}
		if got := profiles[VendorJuniper].prompt.MatchString(line); got {
			t.Errorf("the prompt detector takes %q for a prompt", line)
		}
	}
}

// The first line of the output, when it is the echoed command, is never a
// prompt; the same text on a later line is.
func TestOutBufEchoIsNoPrompt(t *testing.T) {
	o := outBuf{prev: -1, prompt: "u@h> ", alt: "u@h# ", echo: "u@h#"}
	o.add([]byte("u@h# \r\n"))
	if len(o.altHits) != 0 || o.count(1) != 0 {
		t.Fatalf("the echo was counted: %+v", o.altHits)
	}
	o.add([]byte("error\r\nu@h# \r\n"))
	if len(o.altHits) != 1 || o.count(1) != 1 {
		t.Fatalf("a later line must count: %+v", o.altHits)
	}

	// As the tail, before its newline arrived.
	p := outBuf{prev: -1, prompt: "u@h> ", alt: "u@h# ", echo: "u@h#"}
	p.add([]byte("u@h# "))
	if k := p.at("u@h# "); k != -1 || p.count(1) != 0 {
		t.Errorf("the echo as the tail: at = %d, count = %d", k, p.count(1))
	}
	p.add([]byte("\r\nx\r\nu@h# "))
	if k := p.at("u@h# "); k != 1 || p.count(1) != 1 {
		t.Errorf("a prompt after the echo: at = %d, count = %d", k, p.count(1))
	}
}

// The two prompts are counted apart, so a line of the other one in the
// middle of the output does not add to the one that stands at the end.
func TestOutBufCountsPromptsApart(t *testing.T) {
	o := outBuf{prev: -1, prompt: "u@h> ", alt: "u@h# "}
	o.add([]byte("show motd\r\nWelcome\r\nu@h# \r\nmore\r\nu@h> "))
	if k := o.at("u@h> "); k != 0 {
		t.Fatalf("at = %d, want 0", k)
	}
	if o.count(0) != 1 || o.count(1) != 1 {
		t.Errorf("counts = %d, %d; want 1, 1", o.count(0), o.count(1))
	}
}

func TestLocationLineForms(t *testing.T) {
	for _, l := range []string{"[edit]", "[edit system login]", "{master:0}[edit]", "{master}[edit]", "{primary:node0}[edit protocols]", "{secondary:node1}[edit]"} {
		if !LocationLine(l) {
			t.Errorf("LocationLine(%q) = false", l)
		}
	}
	for _, l := range []string{"edit", "[editor]", "{master:0}", "x [edit]", "[edit]x"} {
		if LocationLine(l) {
			t.Errorf("LocationLine(%q) = true", l)
		}
	}
}
