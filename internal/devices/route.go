package devices

import (
	"context"
	"strings"

	"github.com/rett/tacctl/internal/execx"
)

// UnknownServer is what a device config names the server when the route
// lookup finds no source address.
const UnknownServer = "<TACQUITO_SERVER_IP>"

// ServerIP is the address a device reaches this server at by default:
//
//	ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'
//
// in a command substitution (every word after a 'src', one per line,
// trailing newlines dropped), or UnknownServer when that is empty. ip
// stays an exec (docs/plans/go-rewrite.md 3.6): it asks the kernel, and the
// tests stub it.
func ServerIP(ctx context.Context, r execx.Runner) string {
	res, err := r.Run(ctx, execx.Cmd{Name: "ip", Args: []string{"-4", "route", "get", "1.0.0.0"}})
	if err != nil {
		return UnknownServer
	}
	var out []string
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		f := awkFields(line)
		for i, w := range f {
			if w == "src" {
				next := ""
				if i+1 < len(f) {
					next = f[i+1]
				}
				out = append(out, next)
			}
		}
	}
	ip := strings.TrimRight(strings.Join(out, "\n"), "\n")
	if ip == "" {
		return UnknownServer
	}
	return ip
}

// awkFields are the fields of awk's default field splitting (mawk: runs
// of blanks and tabs).
func awkFields(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
}
