package execx

import (
	"context"
	"io"
)

// Attached runs c with the terminal: stdin, stdout and stderr are the
// caller's own, so a program that owns the terminal (ssh -t, a sudo
// password prompt, a [y/N] question) works as it would from a login shell.
// While it runs, a signal that cancels ctx (Ctrl-C reaches the whole
// foreground process group) is left to the child: it is not killed for it,
// and its exit status is returned as it ended, as bash's wait does (a
// program that traps SIGINT and exits 130 comes back as 130). interrupted
// reports whether ctx was cancelled meanwhile, so the caller can stop
// afterwards. err is for a program that could not start (code 127) or a
// wait that failed.
//
// 'tacctl host' runs ssh this way (hosts.Attached) and 'tacctl shell' runs
// each of its lines this way.
func Attached(ctx context.Context, r Runner, c Cmd, stdin io.Reader, stdout, stderr io.Writer) (code int, interrupted bool, err error) {
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
	p, err := r.Start(context.WithoutCancel(ctx), c)
	if err != nil {
		return 127, ctx.Err() != nil, err
	}
	res, err := p.Wait()
	return res.Code, ctx.Err() != nil, err
}
