package cli

import (
	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// passwdCmd is 'tacctl passwd' (lib/users.sh cmd_passwd_self at 0.1.16),
// native since WP2.4a: the caller changes the password of the tacctl user
// that matches their own login. The target is SUDO_USER only — there is
// deliberately no username argument, so the sudoers rule of the lower tiers
// can allow this exact command without letting anyone reset somebody
// else's password — and the current password must verify first.
func passwdCmd(inv *invocation) *cobra.Command {
	return withRun(verb("passwd", "Change your own password (asks for the current one)"),
		inv.native(withPreflight, inv.passwdSelf))
}

func (inv *invocation) passwdSelf(args []string) error {
	a := inv.app
	if len(args) > 0 {
		return inv.usageErr("Usage: tacctl passwd   (changes your own password; takes no arguments)",
			"To set another user's password: tacctl user passwd <username>")
	}
	username := a.Env.Get("SUDO_USER")
	if username == "" || username == "root" {
		return inv.usageErr("'tacctl passwd' changes the password of the user who invoked sudo.",
			"As root, use: tacctl user passwd <username>")
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if err := names.ValidateUsername(username); err != nil {
		return err
	}
	u, ok, err := inv.userInfo(username)
	if err != nil {
		return err
	}
	if !ok {
		return inv.usageErr("No tacctl user named '" + username + "'.")
	}
	if u.status == "disabled" {
		return inv.usageErr("User '" + username + "' is disabled. Ask a superuser to re-enable it.")
	}
	m, _ := inv.model()
	stored := m.User(username).Hash

	inv.echo("")
	inv.echoE("  Changing password for: " + ui.Bold + username + ui.NC)
	p := a.Prompter()
	current, err := p.Password("  Current password: ")
	if err != nil {
		return err
	}
	if hash.Verify(current, stored) != hash.Match {
		// Same rate limit as 'user verify': not a local bcrypt oracle.
		inv.pause(failDelay)
		a.Logger(inv.ctx, "auth.warning", "passwd FAIL user="+username+" reason=bad-current-password")
		return inv.usageErr("Current password does not match.")
	}
	t := a.Tunables()
	password, err := p.PromptPassword(username, t.PasswordMinLength, a.Knobs.Rand())
	if err != nil {
		return err
	}
	if password == current {
		return inv.usageErr("New password must differ from the current one.")
	}
	h, err := hash.GenerateWith(password, t.BcryptCost, a.Knobs.Rand())
	if err != nil {
		return err
	}
	if err := inv.storeApply(func(s *store.Store) error {
		return s.UserSet(username, "hash="+h, "password_changed=today")
	}); err != nil {
		return err
	}
	a.Logger(inv.ctx, "auth.info", "passwd OK user="+username+" (self-service)")
	a.Out.Info("Password changed for '" + username + "'.")
	inv.echo("")
	return nil
}
