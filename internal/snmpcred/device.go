package snmpcred

// The credentials of one device (D72 of docs/plans/0.2.4-plan.md): one file
// per device, StateDir/snmp/devices/<name>.yaml (0600, the directory 0700),
// in the format of snmp.yaml and of the scope files. The per-scope loader
// opens snmp/<scope>.yaml by name and never lists the directory, so 0.2.3
// ignores the subdirectory (and a scope called 'devices' has the file
// devices.yaml, which is no clash). A device's non-secret settings are the
// registry's (devices.yaml, internal/devreg); only the community and the v3
// user with its passphrases are here.
//
// A device name is compared case-insensitively by the registry, so the file
// is the lowercased name; the name is checked against the registry's shape
// (letters, digits, '.', '_' and '-', no leading '.', no '..') so it can
// never leave the directory.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DevicesDir is the name of the subdirectory of the SNMP directory that
// holds the per-device files.
const DevicesDir = "devices"

// DeviceHeader starts a device's file.
const DeviceHeader = "# tacctl SNMP credentials of one device (D72). Secret: 0600, never printed.\n" +
	"# Edit with 'tacctl device snmp <name> community|v3-user|clear'.\n"

// maxDeviceFileName is the longest file name a directory entry may have;
// the name and '.yaml' must fit.
const maxDeviceFileName = 255

// reDeviceName is the registry's device name shape (devreg.ValidateName).
var reDeviceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$`)

// DeviceFile is the credentials file of a device under dir (the SNMP
// directory, StateDir/snmp).
func DeviceFile(dir, name string) (string, error) {
	if !reDeviceName.MatchString(name) || strings.Contains(name, "..") || strings.HasSuffix(name, ".") {
		return "", fail("Invalid device name '" + name + "'.")
	}
	file := strings.ToLower(name) + ".yaml"
	if len(file) > maxDeviceFileName {
		return "", fail("The device name '" + name + "' is too long to hold SNMP credentials in a file of its own.")
	}
	return filepath.Join(dir, DevicesDir, file), nil
}

// LoadDevice reads the device's file; a missing one is no credentials.
func LoadDevice(dir, name string) (Creds, error) {
	p, err := DeviceFile(dir, name)
	if err != nil {
		return Creds{}, err
	}
	return Load(p)
}

// SaveDevice writes the device's file (0600) in dir/devices (0700, and dir
// itself 0700); no credentials at all removes the file, and the
// directories when that leaves them empty.
func SaveDevice(dir, name string, c Creds) error {
	p, err := DeviceFile(dir, name)
	if err != nil {
		return err
	}
	if c.Empty() {
		return RemoveDevice(dir, name)
	}
	for _, d := range []string{dir, filepath.Join(dir, DevicesDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fail("Cannot create " + d + ": " + errText(err))
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return fail("Cannot protect " + d + ": " + errText(err))
		}
	}
	return saveWith(p, c, DeviceHeader)
}

// RemoveDevice deletes the device's file (a missing one is fine), and the
// directories when that leaves them empty.
func RemoveDevice(dir, name string) error {
	p, err := DeviceFile(dir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail("Cannot remove " + p + ": " + errText(err))
	}
	_ = os.Remove(filepath.Dir(p)) // only when empty
	_ = os.Remove(dir)             // only when empty
	return nil
}

// RenameDevice moves the device's file to the new name (a device renamed);
// no file is nothing to do, and a rename of the spelling only keeps the
// file. A file the new name already has is never overwritten: it is a
// leftover (a device removed by an older release, a file restored by hand),
// and the renamed device would otherwise lose its own credentials to it
// (the same refusal as RenameScope's).
func RenameDevice(dir, old, newName string) error {
	from, err := DeviceFile(dir, old)
	if err != nil {
		return err
	}
	to, err := DeviceFile(dir, newName)
	if err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if _, err := os.Lstat(from); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := CheckNoDeviceFile(dir, newName); err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail("Cannot rename " + from + ": " + errText(err))
	}
	return nil
}

// CheckNoDeviceFile is nil when the device has no credentials file under
// dir. A new device (or a device renamed to the name) that finds one would
// pick up the credentials of an earlier device of that name; the refusal
// names the file and how to go on.
func CheckNoDeviceFile(dir, name string) error {
	p, err := DeviceFile(dir, name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(p); err == nil {
		return fail("SNMP credentials for a device named '"+name+"' are already on disk: "+p+".",
			"They belong to an earlier device of that name, and the new one would use them. Remove the file (or move it away), then run the command again.")
	}
	return nil
}
