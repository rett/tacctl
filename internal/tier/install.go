package tier

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"

	"github.com/rett/tacctl/internal/execx"
)

// ErrVisudo is InstallSudoers' refusal of a body 'visudo -cf' rejects;
// nothing was installed.
var ErrVisudo = errors.New("visudo validation failed")

// InstallError is an 'install' that exited non-zero (its own message is
// on stderr).
type InstallError struct{ Code int }

func (e *InstallError) Error() string { return "install exited " + strconv.Itoa(e.Code) }

// TempError is a temporary file that could not be created.
type TempError struct{ Err error }

func (e *TempError) Error() string { return e.Err.Error() }
func (e *TempError) Unwrap() error { return e.Err }

// InstallSudoers is the one way tacctl installs a sudoers drop-in (both
// 'config sudoers [tiers] install' and the upgrade's refresh of the tiers
// file): body is written to a temporary file, 'visudo -cf' checks it (its
// complaints go to stderr), and 'install -m 0440 -o root -g root' puts it
// in place as dst. Both programs are external, so the suite stubs them. A
// rejected body is ErrVisudo and dst is left as it was; the temporary
// file never stays behind.
func InstallSudoers(ctx context.Context, r execx.Runner, stdout, stderr io.Writer, body, dst string) error {
	f, err := os.CreateTemp("", "tmp.")
	if err != nil {
		return &TempError{Err: err}
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, werr := f.WriteString(body)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	res, _ := r.Run(ctx, execx.Cmd{Name: "visudo", Args: []string{"-cf", tmp}, Stderr: stderr})
	if res.Code != 0 {
		return ErrVisudo
	}
	res, _ = r.Run(ctx, execx.Cmd{Name: "install", Args: []string{"-m", "0440", "-o", "root", "-g", "root", tmp, dst},
		Stdout: stdout, Stderr: stderr})
	if res.Code != 0 {
		return &InstallError{Code: res.Code}
	}
	return nil
}
