package devssh

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
)

// passwordMemo is the one password of one connection: the source is asked
// at most once, and the password is handed to the device at most once (a
// rejected password is not sent again by the next method: one failed
// attempt per device, not one per method, so a batch with a wrong password
// does not lock the account on every device it reaches).
//
// The source runs in its own goroutine and never under the lock, and a wait
// for it ends with the context of the handshake: a source that blocks costs
// the connect timeout, not forever (the goroutine is left to finish).
type passwordMemo struct {
	ctx context.Context

	mu    sync.Mutex
	src   PasswordSource // dropped once called
	done  chan struct{}  // closed when the source has answered
	value string         // cleared at the single send
	err   error
	nsent int
}

// errPasswordUsed aborts the authentication when the password was sent and
// rejected already; Dial reports it as ErrAuth.
var errPasswordUsed = errors.New("the password was rejected")

// use is the password for one transmission, once: a later call is
// errPasswordUsed.
func (m *passwordMemo) use() (string, error) {
	m.mu.Lock()
	if m.nsent > 0 {
		m.mu.Unlock()
		return "", errPasswordUsed
	}
	if m.done == nil {
		m.done = make(chan struct{})
		src := m.src
		m.src = nil
		go func() {
			pw, err := src()
			m.mu.Lock()
			m.value, m.err = pw, err
			m.mu.Unlock()
			close(m.done)
		}()
	}
	done := m.done
	m.mu.Unlock()

	select {
	case <-done:
	case <-m.ctx.Done():
		return "", m.ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return "", m.err
	}
	if m.nsent > 0 {
		return "", errPasswordUsed
	}
	pw := m.value
	m.value = ""
	m.nsent++
	return pw, nil
}

// plain is the 'password' method's callback.
func (m *passwordMemo) plain() (string, error) { return m.use() }

// challenge is the 'keyboard-interactive' method's callback: it answers a
// password prompt (echo off) with the password, once, and every other
// prompt with nothing. An exchange with no prompts is answered with no
// answers. An empty answer to an unknown prompt fails that method and
// leaves the password for the next one, which is better than aborting.
func (m *passwordMemo) challenge(_, _ string, questions []string, echos []bool) ([]string, error) {
	answers := make([]string, len(questions))
	for i, q := range questions {
		if i >= len(echos) || echos[i] || !IsPasswordPrompt(q) {
			continue
		}
		pw, err := m.use()
		switch {
		case errors.Is(err, errPasswordUsed):
			// A retry round of the same method: nothing more to send.
			return answers, nil
		case err != nil:
			return nil, err
		}
		answers[i] = pw
	}
	return answers, nil
}

// srcErr is the error the password source returned, if it did.
func (m *passwordMemo) srcErr() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

// sent is how many times the password went to the device.
func (m *passwordMemo) sent() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nsent
}

// reNotPasswordWord matches the short words of the prompts that mention a
// password and are not for the user's: a new or repeated one, a PIN, a code.
// They are matched as words, so a host or a user named 'newyork' is not
// refused.
var reNotPasswordWord = regexp.MustCompile(`\b(new|retype|re-enter|confirm|again|old|pin|code|sms|duo|mfa)\b`)

// notPasswordParts are the parts of a prompt for a second factor or a
// one-time secret; they are matched as substrings, so 'OneTimePassword:'
// and 'OTPPassword:' are refused too.
var notPasswordParts = []string{
	"one-time", "one time", "onetime", "otp", "token", "passcode", "securid",
	"2fa", "mfa", "factor", "verif", "authenticator", "challenge",
}

// IsPasswordPrompt reports whether a keyboard-interactive prompt asks for
// the user's password: 'Password:', "user@host's password:", 'Password for
// alice:'. A prompt for a new or repeated password, a one-time password, a
// token, a second factor, a verification code or anything else is not, and
// gets no answer from the password source.
func IsPasswordPrompt(prompt string) bool {
	p := strings.ToLower(strings.TrimSpace(prompt))
	if !strings.Contains(p, "password") || reNotPasswordWord.MatchString(p) {
		return false
	}
	for _, part := range notPasswordParts {
		if strings.Contains(p, part) {
			return false
		}
	}
	return true
}
