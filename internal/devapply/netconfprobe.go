package devapply

import (
	"context"
	"errors"
	"fmt"

	"github.com/rett/tacctl/internal/devssh"
)

// ProbeNetconf dials the device afresh and asks for the NETCONF subsystem
// and its hello, which is how a change to the NETCONF service is proved
// (D148): "hello ok" when the device answers, "port closed" when it refuses
// the subsystem, "no hello" when it accepts it and does not say hello.
// Anything else (the dial, the login, a timeout, a closed session) is an
// error: a proof that cannot be had is never a pass.
func ProbeNetconf(ctx context.Context, t devssh.Target) (string, error) {
	c, release, err := dialLife(ctx, t)
	if err != nil {
		return "", err
	}
	defer release()
	defer func() { _ = c.Close() }()
	ns, err := c.NETCONF()
	switch {
	case err == nil:
		_ = ns.Close()
		return ProbeHelloOK, nil
	case errors.Is(err, devssh.ErrNoSubsystem):
		return ProbePortClosed, nil
	case errors.Is(err, devssh.ErrProtocol):
		return ProbeNoHello, nil
	}
	return "", fmt.Errorf("the NETCONF probe could not tell: %w", err)
}
