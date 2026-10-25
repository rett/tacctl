package devreg

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
// unknown key 'config_syntax'), so the key goes before an older release is
// installed, as the location and the SNMP map do: a rollback plans with
// ConfigSyntaxSet and applies with RollbackConfigSyntax. An older binary
// compares a legacy-ssh Cisco device as IOS 12.x again, which is what the
// rollback's notes say.

// ConfigSyntaxSet are the names of the devices that have a configuration
// syntax setting, in file order, of the registry at path (none when the file
// is missing).
func ConfigSyntaxSet(path string) ([]string, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range f.Devices {
		if d.ConfigSyntax != "" {
			out = append(out, d.Name)
		}
	}
	return out, nil
}

// RollbackConfigSyntax removes the configuration syntax setting of every
// device, under the registry's lock, in one write; before runs first (a
// snapshot). It returns the names it cleared, in file order. A registry
// without any is not written (before does not run), and a missing file is
// not created.
func RollbackConfigSyntax(path string, before func() error) ([]string, error) {
	names, err := ConfigSyntaxSet(path)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	var cleared []string
	_, err = Mutate(path, "", before, func(f *File) error {
		cleared = cleared[:0]
		for _, d := range f.Devices {
			if d.ConfigSyntax != "" {
				cleared = append(cleared, d.Name)
				d.ConfigSyntax = ""
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cleared, nil
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
