package sftpd

import (
	"errors"

	"github.com/pkg/sftp"
)

// The reasons a request is refused; they are the Err text of an Event with
// Op "refused".
const (
	reasonSSH         = ".ssh"
	reasonOutside     = "outside the home"
	reasonSymlink     = "symlink"
	reasonQuota       = "quota"
	reasonUnsupported = "unsupported"
	reasonBadPath     = "bad path"
)

// statusError is an error that carries its SFTP status: the code the
// library sends (it finds it through Unwrap) and the message the client
// shows. A non-empty reason marks a refusal, which is audited.
type statusError struct {
	reason string
	code   error
	msg    string
}

func (e *statusError) Error() string { return e.msg }
func (e *statusError) Unwrap() error { return e.code }

// refuse is a refusal with permission-denied status.
func refuse(reason, msg string) error {
	return &statusError{reason: reason, code: sftp.ErrSSHFxPermissionDenied, msg: msg}
}

func errSSH() error {
	return refuse(reasonSSH, "permission denied")
}

func errSymlink() error {
	return refuse(reasonSymlink, "permission denied: symbolic links are not followed")
}

func errOutside() error {
	return refuse(reasonOutside, "permission denied: the home directory itself cannot be changed")
}

func errUnsupported(what string) error {
	return &statusError{reason: reasonUnsupported, code: sftp.ErrSSHFxOpUnsupported, msg: what + " is not supported"}
}

func errBadPath(msg string) error {
	return &statusError{reason: reasonBadPath, code: sftp.ErrSSHFxFailure, msg: msg}
}

// reasonOf is the refusal reason in err, or "" when err is not a refusal.
func reasonOf(err error) string {
	var se *statusError
	if errors.As(err, &se) {
		return se.reason
	}
	return ""
}
