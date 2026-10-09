package devreg

// The optional per-device location of 0.2.3 (D41, 'tacctl device location')
// and the rollback to 0.2.2 (D50): 0.2.2's parser of devices.yaml refuses a
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
