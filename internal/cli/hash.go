package cli

import (
	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/hash"
)

// The 'hash' family (lib/users.sh cmd_hash at 0.1.16), native since WP2.4a.
// It runs as the invoking user, never under sudo (reexec.go), needs no
// store and runs no preflight. python3-bcrypt's import check is gone with
// python3 (docs/plans/go-rewrite.md 3.9 item 4).
func hashCmd(inv *invocation) *cobra.Command {
	n := func(run func([]string) error) func(*cobra.Command, []string) error {
		return inv.native(noPreflight, run)
	}
	c := verb("hash <subcommand>", "Bcrypt helper (generate, commands — runs as invoking user, no sudo)",
		withRun(verb("generate", "Prompt for a password and print its bcrypt hash"), n(inv.hashGenerate)),
		withRun(verb("commands", "Show OS-specific one-liners for offline generation"), n(func([]string) error {
			inv.write(hashRecipes())
			return nil
		})),
	)
	// No sub-command, help, -h, --help: the usage, exit 0; anything else:
	// an error, the usage, exit 1.
	c.RunE = n(func(args []string) error {
		switch sub := arg(args, 0); sub {
		case "", "-h", "--help", "help":
			inv.write(hashUsage())
			return nil
		default:
			inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
			inv.write(hashUsage())
			return exit(1)
		}
	})
	return c
}

// hashUsage is cmd_hash_usage.
func hashUsage() string { return Usage("hash", nil) }

// hashGenerate is cmd_hash_generate: ask for a password (blank: one is
// generated and announced on stderr), print its hash and the admin command
// that takes it. Extra arguments are ignored.
func (inv *invocation) hashGenerate([]string) error {
	a := inv.app
	t := a.Tunables()
	pw, err := a.Prompter().PromptPassword("", t.PasswordMinLength, a.Knobs.Rand())
	if err != nil {
		return err
	}
	h, err := hash.GenerateWith(pw, t.BcryptCost, a.Knobs.Rand())
	if err != nil {
		return err
	}
	inv.write("\n  Bcrypt hash (provide this to your admin):\n\n  " + h + "\n\n  Admin command:\n" +
		"    tacctl user add <username> <group> --hash '" + h + "'\n\n")
	return nil
}

// hashRecipes is cmd_hash_commands: the client-side recipes, verbatim.
func hashRecipes() string {
	return `
  Bcrypt hash generation — client-side recipes
  (run on the operator's machine; plaintext password never leaves it)

  =================================================================
  Any OS — Python 3 with the 'bcrypt' module
  =================================================================
    # install once:  python3 -m pip install --user bcrypt
    #                (use 'py' instead of 'python3' on Windows)
    python3 -c "import bcrypt,binascii,getpass; p=getpass.getpass('Password: ').encode(); r=bcrypt.hashpw(p,bcrypt.gensalt(12)); print('raw:',r.decode()); print('hex:',binascii.hexlify(r).decode())"

  =================================================================
  Linux / macOS — htpasswd (no Python needed)
  =================================================================
    # install once:  apt install apache2-utils  OR  brew install httpd
    htpasswd -nBC 12 "" | cut -d: -f2

  =================================================================
  Handing the hash to your admin
  =================================================================
  'tacctl user passwd --hash' accepts either form; the server
  normalizes to hex internally. So either line works:
      tacctl user passwd <user> --hash '$2b$12$...'          # raw
      tacctl user passwd <user> --hash '24326224313224...'   # hex

`
}
