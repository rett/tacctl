package cli

import (
	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/lifecycle"
)

// The top-level verbs outside the families (bin/tacctl.sh's dispatch at
// 0.1.16): install, upgrade, uninstall (lib/lifecycle.sh; internal/lifecycle
// since WP3.3d). passwd (lib/users.sh) and status (lib/service.sh) are
// native too: passwd.go, status.go. None of the three runs preflight (they
// work on a machine without a store), all are behind the tier gate.
func lifecycleCmds(inv *invocation) []*cobra.Command {
	cmd := func(use, short string, run func(*lifecycle.Host, []string) error) *cobra.Command {
		c := verb(use, short)
		c.RunE = inv.native(noPreflight, func(args []string) error { return run(inv.lifecycleHost(), args) })
		return c
	}
	return []*cobra.Command{
		cmd("install [--branch <name>]", "Install tacctl and the TACACS+ backend (tacquito) from scratch",
			func(h *lifecycle.Host, args []string) error { return lifecycle.Install(inv.ctx, h, args) }),
		cmd("upgrade [--branch <name>]", "Pull latest source, rebuild, update scripts and every enabled backend",
			func(h *lifecycle.Host, args []string) error { return lifecycle.Upgrade(inv.ctx, h, args) }),
		cmd("uninstall", "Remove tacctl, its backends' services and all associated files",
			func(h *lifecycle.Host, args []string) error { return lifecycle.Uninstall(inv.ctx, h, args) }),
	}
}

// lifecycleHost is what install, upgrade and uninstall run on: the
// invocation's backend set (made first, so the lifecycle Env shares it:
// every phase of the command runs on the same backends), its environment
// and the commit this binary was built from.
func (inv *invocation) lifecycleHost() *lifecycle.Host {
	a := inv.app
	a.Backends()
	return &lifecycle.Host{
		Env:     lifecycle.NewEnv(a.BackendEnv(), a.Knobs.Rand(), a.EUID == 0),
		Environ: a.Env,
		Commit:  inv.build.Commit,
	}
}
