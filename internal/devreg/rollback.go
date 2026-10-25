package devreg

import (
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The optional per-device location of 0.2.3 (D41, 'tacctl device location')
// and the rollback to 0.2.2 (D50, the tool of the 0.2.3 release; 0.2.4's
// tool targets 0.2.3, which reads the location, and uses RollbackSNMP
// below): 0.2.2's parser of devices.yaml refuses a
// device with a key it does not know ("device 'x': unknown key
// 'location'."; parseDevice of the 0.2.2 tag has address, vendor,
// hostname, description, port, legacy_ssh, host_keys and ack), so the
// registry cannot be read at all while one device has a location.

// Located are the names of the devices that have a location, in file order,
// of the registry at path (none when the file is missing).
func Located(path string) ([]string, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range f.Devices {
		if d.Location != "" {
			out = append(out, d.Name)
		}
	}
	return out, nil
}

// RollbackLocations removes the location of every device, under the
// registry's lock, in one write; before runs first (a snapshot). It returns
// the names it cleared, in file order. A registry without a location is not
// written (before does not run), and a missing file is not created.
func RollbackLocations(path string, before func() error) ([]string, error) {
	names, err := Located(path)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	var cleared []string
	_, err = Mutate(path, "", before, func(f *File) error {
		cleared = cleared[:0]
		for _, d := range f.Devices {
			if d.Location != "" {
				cleared = append(cleared, d.Name)
				d.Location = ""
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cleared, nil
}

// The per-device SNMP settings of 0.2.4 (D72 of docs/plans/0.2.4-plan.md):
// 0.2.3's parser refuses a device with a key it does not know (device 'x':
// unknown key 'snmp'), so, like the location, the map has to go before 0.2.3
// is installed: 'tacctl rollback 0.2.3' (D73, internal/lifecycle) plans with
// SNMPOverridden and applies with RollbackSNMP, and 0.2.3 (and 0.2.2) refuse
// the whole registry while one device has a map. The credentials are files of their own under
// StateDir/snmp/devices/, which 0.2.3 never opens: they stay (a later 0.2.4
// finds them again, and 'device snmp <name> clear' removes them).

// SNMPOverridden are the names of the devices that have SNMP settings of
// their own, in file order, of the registry at path (none when the file is
// missing).
func SNMPOverridden(path string) ([]string, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range f.Devices {
		if !d.SNMP.Empty() {
			out = append(out, d.Name)
		}
	}
	return out, nil
}

// RollbackSNMP removes the SNMP settings of every device, under the
// registry's lock, in one write; before runs first (a snapshot). It returns
// the names it cleared, in file order. A registry without any is not
// written (before does not run), and a missing file is not created.
func RollbackSNMP(path string, before func() error) ([]string, error) {
	names, err := SNMPOverridden(path)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	var cleared []string
	_, err = Mutate(path, "", before, func(f *File) error {
		cleared = cleared[:0]
		for _, d := range f.Devices {
			if !d.SNMP.Empty() {
				cleared = append(cleared, d.Name)
				d.SNMP = SNMP{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cleared, nil
}

// The per-device configuration syntax of 0.2.5 (D113 of docs/plans/0.2.5-
// plan.md, 'tacctl device ios-syntax'): 0.2.4's parser (and 0.2.3's, and
// 0.2.2's) refuses a device with a key it does not know (device 'x':
// unknown key 'ios_syntax'), so the key goes before an older release is
// installed, as the location and the SNMP map do: a rollback plans with
// IOSSyntaxSet and applies with RollbackIOSSyntax. An older binary
// compares a legacy-ssh Cisco device as IOS 12.x again, which is what the
// rollback's notes say.

// IOSSyntaxSet are the names of the devices that have a configuration
// syntax setting, in file order, of the registry at path (none when the file
// is missing).
func IOSSyntaxSet(path string) ([]string, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range f.Devices {
		if d.IOSSyntax != "" {
			out = append(out, d.Name)
		}
	}
	return out, nil
}

// RollbackIOSSyntax removes the configuration syntax setting of every
// device, under the registry's lock, in one write; before runs first (a
// snapshot). It returns the names it cleared, in file order. A registry
// without any is not written (before does not run), and a missing file is
// not created.
func RollbackIOSSyntax(path string, before func() error) ([]string, error) {
	names, err := IOSSyntaxSet(path)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	var cleared []string
	_, err = Mutate(path, "", before, func(f *File) error {
		cleared = cleared[:0]
		for _, d := range f.Devices {
			if d.IOSSyntax != "" {
				cleared = append(cleared, d.Name)
				d.IOSSyntax = ""
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cleared, nil
}

// The key of the configuration syntax setting (0.2.18, D273): ios_syntax,
// where 0.2.5 to 0.2.17 read and write config_syntax (OldSyntaxKey) and
// refuse a device with a key they do not know ("unknown key 'ios_syntax'").
// This release reads either; 'tacctl rollback 0.2.17|0.2.16|0.2.9' writes
// the setting back under the old key with RollbackIOSSyntaxKey, after
// planning with SyntaxKeyed. A release that reads the old key and is run
// again later reads it again (Load), and its next change stores ios_syntax.

// SyntaxKeyed are the devices with a configuration syntax setting of the
// registry at path when a device of the file holds it under ios_syntax:
// what RollbackIOSSyntaxKey writes (none when the file is missing, or holds
// the setting under the old key only).
func SyntaxKeyed(path string) ([]Device, error) {
	f, err := Load(path)
	if err != nil || !f.syntaxKeyed {
		return nil, err
	}
	var out []Device
	for _, d := range f.Devices {
		if d.IOSSyntax != "" {
			out = append(out, d.Clone())
		}
	}
	return out, nil
}

// oldKeyText is Text with the setting under OldSyntaxKey.
func (f *File) oldKeyText() ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	out, err := yamlpy.EmitChecked(f.docWith(OldSyntaxKey), yamlpy.StoreOptions, Header, pyyaml.LoadBytes)
	if err != nil {
		return nil, fail("cannot write the device registry (" + firstLine(err.Error()) + "); nothing was written")
	}
	return out, nil
}

// RollbackIOSSyntaxKey writes the registry at path with every device's
// configuration syntax under OldSyntaxKey, under the registry's lock, in one
// write; before runs first (a snapshot). Every other key is written as this
// release writes it. It returns the names of the devices whose setting it
// wrote, in file order. A registry that needs no write is not written
// (before does not run), and a missing file is not created.
func RollbackIOSSyntaxKey(path string, before func() error) ([]string, error) {
	devs, err := SyntaxKeyed(path)
	if err != nil || len(devs) == 0 {
		return nil, err
	}
	if before != nil {
		if err := before(); err != nil {
			return nil, err
		}
	}
	unlock, err := Lock(path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := Load(path)
	if err != nil || !f.syntaxKeyed {
		return nil, err
	}
	text, err := f.oldKeyText()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, d := range f.Devices {
		if d.IOSSyntax != "" {
			names = append(names, d.Name)
		}
	}
	if err := atomicWrite(path, text, 0o600); err != nil {
		return nil, err
	}
	return names, nil
}

// The per-device NETCONF service setting of 0.2.10 (D145 of docs/plans/
// 0.2.10-plan.md, 'tacctl device netconf'): 0.2.9's parser refuses a device
// with a key it does not know (device 'x': unknown key 'netconf'), so the
// key goes before an older release is installed, as the configuration
// syntax does: a rollback plans with NetconfSet and applies with
// RollbackNetconf.

// NetconfSet are the names of the devices that have a NETCONF service
// setting, in file order, of the registry at path (none when the file is
// missing).
func NetconfSet(path string) ([]string, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range f.Devices {
		if !d.Netconf.Empty() {
			out = append(out, d.Name)
		}
	}
	return out, nil
}

// RollbackNetconf removes the NETCONF service setting of every device, under
// the registry's lock, in one write; before runs first (a snapshot). It
// returns the names it cleared, in file order. A registry without any is not
// written (before does not run), and a missing file is not created.
func RollbackNetconf(path string, before func() error) ([]string, error) {
	names, err := NetconfSet(path)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	var cleared []string
	_, err = Mutate(path, "", before, func(f *File) error {
		cleared = cleared[:0]
		for _, d := range f.Devices {
			if !d.Netconf.Empty() {
				cleared = append(cleared, d.Name)
				d.Netconf = Netconf{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cleared, nil
}
