package devconf

import (
	"strings"
	"testing"
)

// The archive path of an IOS device (0.2.7): only the file system word is
// read from the running configuration, whatever else the path holds.
func TestArchiveFSIsTheFileSystemOfTheArchivePath(t *testing.T) {
	const head = "version 15.6\nhostname r1\n!\n"
	cases := []struct {
		name, text, want string
	}{
		{"flash", "archive\n log config\n  hidekeys\n path flash:tacctl-\n maximum 14\n!\nend\n", "flash:"},
		{"path first", "archive\n path bootflash:cfg/arc-\n!\n", "bootflash:"},
		{"disk with a directory", "archive\n path disk0:/archive/$h-\n!\n", "disk0:"},
		{"upper case", "archive\n path FLASH:x\n!\n", "flash:"},
		{"remote: no host, user or secret", "archive\n path ftp://user:pw@192.0.2.9/dir/\n!\n", "ftp:"},
		{"remote scp", "archive\n path scp://backup@192.0.2.9/cfg\n!\n", "scp:"},
		{"no path", "archive\n log config\n  hidekeys\n!\n", ""},
		{"no archive", "interface Loopback0\n ip address 192.0.2.1 255.255.255.255\n!\n", ""},
		{"a path of another hierarchy", "crypto pki trustpoint X\n path flash:x\n!\narchive\n log config\n!\n", ""},
		{"a nested path", "archive\n log config\n  path flash:nested\n!\n", ""},
		{"no file system", "archive\n path tacctl-\n!\n", ""},
		{"odd word", "archive\n path fl@sh:x\n!\n", ""},
		{"a prefix of archive", "archived\n path flash:x\n!\n", ""},
	}
	for _, c := range cases {
		ext, err := Extract("cisco", head+c.text)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if ext.ArchiveFS != c.want {
			t.Errorf("%s: %q, want %q", c.name, ext.ArchiveFS, c.want)
		}
	}
	// no secret of a remote path is anywhere in what Extract keeps
	ext, err := Extract("cisco", head+"archive\n path ftp://user:pw@192.0.2.9/dir/\n!\n")
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range ext.Sections {
		for _, l := range s.Lines {
			if strings.Contains(l, "user:pw") || strings.Contains(l, "192.0.2.9") {
				t.Errorf("section %s keeps %q", name, l)
			}
		}
	}
}
