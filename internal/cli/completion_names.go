package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/model"
)

// '_completion-names <kind>' is bash completion's bridge to live names
// ('sudo -n tacctl _completion-names <kind>', bin/tacctl.sh at 0.1.16): it
// runs the tier gate and preflight, then prints the names one per line.
// A kind is native when completionKinds has it; a kind in
// delegatedCompletionKinds is still bash's; any other kind prints nothing
// (exit 0), as in bash. Cutting a kind over is moving it from the second
// table to the first; a new kind is one entry.
var completionKinds = map[string]func(m *model.Model) []string{
	// model_users: every user, the accounting sink included, sorted.
	KindUsers: (*model.Model).UserNames,
	// model_groups and model_scopes: every name, sorted.
	KindGroups: (*model.Model).GroupNames,
	KindScopes: (*model.Model).ScopeNames,
}

// delegatedCompletionKinds are the kinds bash still answers (WP2.4d:
// backups, backends, enabled-backends; WP2.4c: listeners).
var delegatedCompletionKinds = map[string]bool{
	"backups": true, "backends": true, "enabled-backends": true, "listeners": true,
}

func completionNamesCmd(inv *invocation) *cobra.Command {
	c := hidden("_completion-names")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		kind := arg(args, 0)
		if delegatedCompletionKinds[kind] {
			return delegate(inv.app)
		}
		return inv.native(withPreflight, func([]string) error {
			names, ok := completionKinds[kind]
			if !ok {
				return nil
			}
			// 'model_users 2>/dev/null': a model that cannot be read is
			// exit 1 with nothing printed (set -e).
			m, err := inv.model()
			if err != nil {
				return exit(1)
			}
			if l := names(m); len(l) > 0 {
				inv.write(strings.Join(l, "\n") + "\n")
			}
			return nil
		})(cmd, args)
	}
	return c
}
