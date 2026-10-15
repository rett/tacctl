package devapply

// The choice of the transport an apply writes through (0.2.10, D150): a
// pure function of the setting, the device's last NETCONF probe and what the
// transaction is about to change, so that the rule is one table and the CLI
// only acts on its answer.

import "context"

// Setting is the word of device.apply.transport and of --transport on
// 'device config apply'.
type Setting string

// The settings.
const (
	// SettingAuto is NETCONF where the device answered the last read and
	// can confirm, else the command line.
	SettingAuto Setting = "auto"
	// SettingCLI is the Junos command line, as 0.2.9 wrote.
	SettingCLI Setting = "cli"
	// SettingNetconf is NETCONF and nothing else: a device that cannot is
	// failed, never written over the command line.
	SettingNetconf Setting = "netconf"
)

// Valid reports whether s is one of the three settings.
func (s Setting) Valid() bool {
	return s == SettingAuto || s == SettingCLI || s == SettingNetconf
}

// Via is the transport a device was written through.
type Via string

// The transports.
const (
	ViaCLI     Via = "cli"
	ViaNetconf Via = "netconf"
)

// The words of a device's last NETCONF probe (devconf.Record.Netconf).
const (
	ProbeHelloOK    = "hello ok"
	ProbePortClosed = "port closed"
	ProbeNoHello    = "no hello"
)

// The reasons a transport was not the one the setting names. They are the
// words after "via cli: " in a line, the review and the record.
const (
	// ReasonServiceChange is a delta that adds, changes or removes a
	// statement of the NETCONF service: it is made over the command line
	// because its verification depends on the service (D148).
	ReasonServiceChange = "netconf service change"
	// ReasonNotProbed is a device whose NETCONF has never been probed.
	ReasonNotProbed = "NETCONF not probed (a pull records it)"
	// ReasonPortClosed and ReasonNoHello are the last probe's answers.
	ReasonPortClosed = "NETCONF port closed at the last read"
	ReasonNoHello    = "NETCONF gave no hello at the last read"
	// ReasonCannotConfirm is a device that answered but offers no confirmed
	// commit over NETCONF, or whose login may not commit.
	ReasonCannotConfirm = "cannot confirm over NETCONF"
)

// ChooseInput is what the choice is made from.
type ChooseInput struct {
	// Setting is the effective setting: --transport over
	// device.apply.transport.
	Setting Setting
	// Probe is the device's last NETCONF probe from its record ("" or
	// "not probed" when it has none).
	Probe string
	// ServiceChange is set once the delta is known to touch
	// 'system services netconf' (plan.TouchesNetconf).
	ServiceChange bool
	// CLIOnly is a verb that has no NETCONF form (onboard, seed, the
	// one-shot local login): the command line whatever the setting says.
	CLIOnly bool
}

// Choice is the answer.
type Choice struct {
	// Via is the transport to use.
	Via Via
	// Reason is why Via is not what the setting names ("" when it is, or
	// when the setting names the command line).
	Reason string
	// Fail is set when the setting forbids the only transport that can
	// carry the change (--transport netconf with a service change): the
	// device is failed with these words and nothing is sent.
	Fail string
}

// Choose decides the transport of one device. It never probes: the probe is
// the record's, and the capabilities a dialled NETCONF login offers are
// checked by the caller (JunosNetconf.Capable), which then asks again with
// ReasonCannotConfirm as its own fallback.
func Choose(in ChooseInput) Choice {
	switch {
	case in.CLIOnly:
		return Choice{Via: ViaCLI}
	case in.Setting == SettingCLI:
		return Choice{Via: ViaCLI}
	case in.ServiceChange && in.Setting == SettingNetconf:
		return Choice{Via: ViaCLI, Fail: "a change to the NETCONF service is made over the command line, " +
			"which --transport netconf does not use; run it with --transport cli or auto"}
	case in.ServiceChange:
		return Choice{Via: ViaCLI, Reason: ReasonServiceChange}
	case in.Setting == SettingNetconf:
		return Choice{Via: ViaNetconf}
	}
	switch in.Probe {
	case ProbeHelloOK:
		return Choice{Via: ViaNetconf}
	case ProbePortClosed:
		return Choice{Via: ViaCLI, Reason: ReasonPortClosed}
	case ProbeNoHello:
		return Choice{Via: ViaCLI, Reason: ReasonNoHello}
	}
	return Choice{Via: ViaCLI, Reason: ReasonNotProbed}
}

// Words is the choice as a line says it: "via cli: port closed", "via
// netconf", "via cli".
func (c Choice) Words() string {
	if c.Reason == "" {
		return "via " + string(c.Via)
	}
	return "via " + string(c.Via) + ": " + c.Reason
}

// Capable reads the login over the dialled NETCONF session and reports why an
// apply cannot commit and confirm through it ("" when it can): the device
// offers no confirmed commit, or the login's class may not commit. An error
// is a session that could not be read (no hello, a refused subsystem), which
// the caller words as the dial's.
func (j *JunosNetconf) Capable(ctx context.Context) (string, error) {
	lg, err := j.Login(ctx)
	if err != nil {
		return "", err
	}
	if j.Confirms() {
		return "", nil
	}
	if !lg.CanCommit() {
		return "the login's class (" + cut(lg.Class) + ") cannot commit", nil
	}
	return "the device offers no confirmed commit over NETCONF", nil
}
