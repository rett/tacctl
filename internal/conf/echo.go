package conf

import "github.com/rett/tacctl/internal/ui"

// echoE is what bash 'echo -e "<s>"' prints, without its newline: 0.1.16
// printed its [WARN]/[ERROR] lines through echo -e, so a problem text
// holding '\t' reaches the terminal as a real tab.
func echoE(s string) string {
	out, _ := ui.EchoE(s)
	return out
}
