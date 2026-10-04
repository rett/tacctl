// Package backend is the protocol-neutral half of tacctl's daemons
// (lib/backend.sh at the 0.1.16 tag): the contract a backend module
// implements (Backend), the registry of modules, the enabled list
// (backends.enabled in tacctl.yaml), and the machinery every mutation runs
// through — the gate, the all-or-nothing render of every enabled backend,
// the restarts, drift reporting and StoreApply, the one mutation path.
//
// A backend is a daemon that serves the model over one protocol: tacquito
// for TACACS+ (internal/backend/tacacs), FreeRADIUS for RADIUS
// (internal/backend/radius). Everything protocol-neutral — the store,
// tacctl.yaml, snapshots, the commands that change users, groups and
// scopes — talks to a daemon only through the methods of Backend, so a
// further backend is one more module and no edits here. 'tacacss' (TACACS+
// over TLS) is a reserved id with no module.
//
// # Shared and per backend
//
// Shared: the truth. store.yaml and tacctl.yaml are one pair of files, so a
// mutation is one write, a snapshot is one directory, and the rollback of a
// failed command restores one pair. rendered.json is one file too
// ({path: sha256}); paths never collide between backends and Artifacts
// says whose a path is. Per backend: the artifacts, their drift state, the
// gate, the restart.
//
// # The mutation path with N backends (StoreApply)
//
//  1. gate      every enabled backend's RenderGate, before anything is
//     written. One refusal refuses the command. A backend that answers
//     GateAdopt is rendered with force in step 4, the others are not.
//  2. snapshot  once.
//  3. write     the caller's writer, once.
//  4. render    RenderAll, in two passes so that either every backend's
//     artifacts are replaced or none is: stage (every backend renders into
//     a private directory and proves the result; a failure stops the
//     command with no artifact touched), then commit (only renames and
//     checksum records remain; the artifacts and rendered.json are copied
//     first, and if a commit still fails every artifact already replaced and
//     rendered.json are put back). StoreApply then puts store.yaml and
//     tacctl.yaml back, so the store never disagrees with a rendered
//     artifact because one backend failed after another succeeded.
//  5. restart   only the backends whose commit reported a change.
//
// What remains possible is a crash between two renames of step 4, or a
// restore that itself fails (it warns per file). Both leave an artifact
// that is not what the store renders, and neither is silent: 'tacctl config
// validate' reports it, and 'tacctl config render' repairs it.
//
// # Messages and errors
//
// The machinery (Gate, RenderAll, StoreApply, ConfigRender) writes its
// messages through the Env's ui.Output exactly as 0.1.16 prints them and
// returns an *Error, whose Code is the exit status (ErrFailed 1,
// ErrRefused 3): the caller prints nothing more. Lookups (Set.Get,
// Set.Enabled) return errors that have not been printed (UnknownError,
// EnabledError).
package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Phase is one step of a lifecycle command at which the generic command
// hands over to a module (BACKEND_*_PHASES). A module does nothing, and
// returns nil, for a phase it has no work in, including one it does not
// know.
type Phase string

// The lifecycle phases.
const (
	PhaseBuild     Phase = "build"
	PhaseFiles     Phase = "files"
	PhaseAccount   Phase = "account"
	PhaseStart     Phase = "start"
	PhasePreflight Phase = "preflight"
	PhaseConfig    Phase = "config"
	PhaseFinish    Phase = "finish"
	PhaseStop      Phase = "stop"
	PhaseProgram   Phase = "program"
	PhaseData      Phase = "data"
)

// The phases of each lifecycle command, in the order the generic commands
// run them (lib/backend.sh BACKEND_INSTALL_PHASES, BACKEND_UPGRADE_PHASES,
// BACKEND_UNINSTALL_PHASES). Everything up to 'account' comes before the
// first render of an install, 'start' after.
var (
	InstallPhases   = []Phase{PhaseBuild, PhaseFiles, PhaseAccount, PhaseStart}
	UpgradePhases   = []Phase{PhasePreflight, PhaseBuild, PhaseConfig, PhaseFiles, PhaseFinish}
	UninstallPhases = []Phase{PhaseStop, PhaseProgram, PhaseData, PhaseAccount}
)

// Description is a backend's 'describe' output.
type Description struct {
	Protocol  string   // protocol=  (tacacs, radius)
	Impl      string   // impl=      (tacquito, freeradius)
	Units     []string // units=     the systemd units, the main one first
	User      string   // user=      the service account
	ConfigDir string   // config_dir=
	LogDir    string   // log_dir=
	// ImportCmd is the command that adopts a hand edit of the backend's
	// artifacts into the store; "" when there is none (what the DRIFT hint
	// says).
	ImportCmd string
}

// GateResult is a backend's answer to "may a mutating command replace the
// artifacts?" (render_gate).
type GateResult int

// The gate's answers.
const (
	// GateOK: yes.
	GateOK GateResult = iota
	// GateAdopt: yes, and they must be rendered with force: tacctl never
	// rendered them, but they say what the store says.
	GateAdopt
	// GateRefused: no, they hold edits tacctl would discard (messages
	// written).
	GateRefused
	// GateFailed: the gate could not tell (messages written).
	GateFailed
)

// Code is the bash return status of render_gate for the answer: 0, 10, 3,
// 1.
func (g GateResult) Code() int {
	switch g {
	case GateOK:
		return 0
	case GateAdopt:
		return 10
	case GateRefused:
		return 3
	}
	return 1
}

func (g GateResult) String() string {
	switch g {
	case GateOK:
		return "ok"
	case GateAdopt:
		return "adopt"
	case GateRefused:
		return "refused"
	}
	return "failed"
}

// ServiceAction is an action of Backend.Service.
type ServiceAction string

// The service actions. Restart (and Reload, which restarts) reports its
// own outcome and never fails the caller; IsActive returns systemctl's word
// and an error when it is not "active"; Since and PID return a value.
// Enable and Disable are the boot-time half of Start and Stop.
const (
	ServiceStart    ServiceAction = "start"
	ServiceStop     ServiceAction = "stop"
	ServiceRestart  ServiceAction = "restart"
	ServiceReload   ServiceAction = "reload"
	ServiceEnable   ServiceAction = "enable"
	ServiceDisable  ServiceAction = "disable"
	ServiceIsActive ServiceAction = "is-active"
	ServiceSince    ServiceAction = "since"
	ServicePID      ServiceAction = "pid"
)

// StatusPart is a part of 'tacctl status' a backend prints (status <part>).
type StatusPart string

// The status parts. With more than one backend enabled the four first
// parts of a backend are printed together under its own heading, so a part
// must read well after the others and carry no heading of its own. Summary
// is what 'tacctl backend status' adds after the listeners; a backend
// without it returns ErrUnsupported.
const (
	StatusService    StatusPart = "service"
	StatusConfig     StatusPart = "config"
	StatusAccounting StatusPart = "accounting"
	StatusActivity   StatusPart = "activity"
	StatusSummary    StatusPart = "summary"
)

// Listener is one listener in effect, as 'listeners list' prints it
// ('<name> <network> <address>'): a network that starts with tcp is a tcp
// socket, udp a udp one, and one that ends in 6 an IPv6 one.
type Listener struct {
	Name    string
	Network string
	Address string
}

// ListenerOps is a backend's listeners.<id>.<name> of tacctl.yaml ('tacctl
// config listen' is their CLI).
type ListenerOps interface {
	// List is the listeners in effect, the built-in ones first.
	List() ([]Listener, error)
	// Show is one listener as 'tacctl config listen' prints it.
	Show(ctx context.Context, name string) (string, error)
	// Set creates or changes a listener, makes the daemon follow and
	// reports; when the daemon does not come up everything is as it was
	// and the error says so.
	Set(ctx context.Context, name, network, address string) error
	// Reset puts a built-in listener back to its default, or removes any
	// other, the same way.
	Reset(ctx context.Context, name string) error
}

// Constraints is what the daemon puts on a shared secret
// (secret_constraints): MaxLen 0 is no limit, Charset "" any character
// (else a bracket expression).
type Constraints struct {
	MaxLen  int
	Charset string
}

// Backend is the contract of a backend module (lib/backend.sh "The
// contract", BACKEND_VERBS). Methods that print write through the Env the
// module was made with: results and info/warn lines on Stdout, errors on
// Stderr; the render steps (RenderGate, RenderStage, RenderCommit) write
// everything on Stderr.
type Backend interface {
	// ID is the registry id (tacacs, radius).
	ID() string
	// Describe is the backend's description.
	Describe() Description
	// Installed reports whether the daemon and its unit are on this
	// machine.
	Installed() bool

	// Install, Upgrade and Uninstall run one phase of the lifecycle
	// command; tree is the tacctl checkout shipped files are taken from. An
	// unknown phase is a no-op (nil).
	Install(ctx context.Context, phase Phase, tree string) error
	Upgrade(ctx context.Context, phase Phase, tree string) error
	Uninstall(ctx context.Context, phase Phase, keepLogs bool) error

	// Artifacts is every file the backend renders (absolute paths, whether
	// or not they exist yet), the main one first.
	Artifacts() []string
	// RenderCheck is a trial render of the current store, nothing
	// installed: one of the rendered status words for the live artifacts
	// against it (current, same, ok, drift, unrecorded, missing,
	// unreadable). An error (message written) when the store cannot be
	// rendered. A backend with a config checker runs it here.
	RenderCheck(ctx context.Context) (string, error)
	// RenderGate is step 1 of StoreApply (see GateResult).
	RenderGate(ctx context.Context) GateResult
	// RenderStage renders the current store and tacctl.yaml into the
	// private directory dir, proves the result and decides whether the
	// live artifacts may be replaced. It touches nothing outside dir.
	// ErrRefused: drift, and force is not set; any other error: failed.
	RenderStage(ctx context.Context, dir string, force bool) error
	// RenderCommit installs what RenderStage left in dir: each artifact by
	// rename, owner and mode set, checksum recorded. changed reports
	// whether any artifact was replaced.
	RenderCommit(ctx context.Context, dir string) (changed bool, err error)
	// RenderNotes warns, after 'tacctl config render', about anything the
	// rendered state means for this daemon. Usually silent.
	RenderNotes(ctx context.Context)

	// Service acts on the daemon, or with a listener on whatever serves
	// that listener (see ServiceAction). An unknown action is
	// ErrUnsupported.
	Service(ctx context.Context, action ServiceAction, listener string) (string, error)
	// Listeners is the backend's listeners.
	Listeners() ListenerOps
	// Status writes one part of 'tacctl status' to w; ErrUnsupported for a
	// part the backend does not have.
	Status(ctx context.Context, part StatusPart, w io.Writer) error
	// Log is 'tacctl log <sub> [args]' for this daemon (tail [n], search
	// <term>, failures, clear [-y]); ErrUnsupported for another sub.
	Log(ctx context.Context, sub string, args []string, w io.Writer) error
	// Accounting is 'tacctl log accounting' (sub tail [n]); ErrUnsupported
	// for another sub.
	Accounting(ctx context.Context, sub string, args []string, w io.Writer) error
	// LastLogin is the user's most recent login, 'YYYY-MM-DD HH:MM:SS', or
	// "never".
	LastLogin(ctx context.Context, user string) (string, error)
	// SecretConstraints is what the daemon puts on a shared secret.
	SecretConstraints() Constraints
	// DeviceVars is what a device template of this protocol needs from the
	// daemon (KEY -> VALUE; empty when nothing).
	DeviceVars(ctx context.Context, vendor, scope string) (map[string]string, error)
}

// Error is a failure of the backend machinery, or a module's, whose
// messages have already been written. Code is the exit status 0.1.16
// returns for it.
type Error struct {
	Code   int
	Reason string
}

func (e *Error) Error() string { return fmt.Sprintf("backend: %s (exit status %d)", e.Reason, e.Code) }

// ExitCode is the exit status.
func (e *Error) ExitCode() int { return e.Code }

// The machinery's errors. Their messages have been written; they only carry
// the exit status.
var (
	// ErrFailed: the step failed (exit 1).
	ErrFailed = &Error{Code: 1, Reason: "failed"}
	// ErrRefused: a rendered file holds edits the command would discard
	// (exit 3).
	ErrRefused = &Error{Code: 3, Reason: "refused"}
	// ErrUnsupported: the backend has no such action, part or sub-command
	// (exit 2, as backend_call reports an unknown verb).
	ErrUnsupported = &Error{Code: 2, Reason: "unsupported"}
)

// ErrAdopt is the internal "adopt" answer of a gate as an error (exit
// status 10, never seen by an operator): code that reports gate answers as
// errors maps GateAdopt to it.
var ErrAdopt = errors.New("backend: the rendered files are to be adopted")

// UnknownError is backend_call's refusal of an id no module registered
// (exit 2). Its message has not been printed.
type UnknownError struct{ ID string }

func (e *UnknownError) Error() string { return "Unknown backend '" + e.ID + "'." }

// ExitCode is 2.
func (e *UnknownError) ExitCode() int { return 2 }

// ExitCode maps an error of this package to its exit status: nil 0, *Error
// its Code, *UnknownError 2, ErrAdopt 10, anything else 1.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var be *Error
	if errors.As(err, &be) {
		return be.Code
	}
	var ue *UnknownError
	if errors.As(err, &ue) {
		return 2
	}
	if errors.Is(err, ErrAdopt) {
		return 10
	}
	return 1
}

// Reported reports whether err's messages have already been written (an
// *Error): a caller then exits with ExitCode(err) and prints nothing.
func Reported(err error) bool {
	var be *Error
	return errors.As(err, &be)
}
