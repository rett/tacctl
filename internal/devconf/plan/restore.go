package plan

// The restore point of an IOS plan (0.2.7, 'device config plan --restore-point').
//
// A block of its own, before the plan's region and outside its banners, that
// makes a file of the device's running configuration, so that a person who
// has to go back has more than the 'no' lines of the back-out:
//
//	!!!!! RESTORE POINT FROM HERE: <device> !!!!!
//	copy running-config <fs>tacctl-<label>-<yyyymmdd-hhmm>.cfg
//	<one empty line>
//	!!!!! RESTORE POINT TO HERE: <device> !!!!!
//
// or, where the pull read an 'archive' with a 'path' and no file system was
// named, the one line 'archive config' (it asks for no name). The block is
// not part of the region: the region's allowlist (CheckRegion) is unchanged
// and refuses a 'copy', and this block has an allowlist of its own
// (CheckRestorePoint) that names exactly the shapes below. It is not a
// rollback timer (D100: IOS has no commit-confirm for a line paste), only a
// file; the back-out gains 'configure replace <file> force' as an alternative
// to its 'no' lines.
//
// Nothing here was pasted on a device in 0.2.7: the report says so.

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
)

// RestorePoint asks for the restore point of an IOS plan (Options) and is
// what the plan carries (Delta.Restore).
type RestorePoint struct {
	// FS is the file system the person named ('flash:', 'bootflash:',
	// 'disk0:'): the restore point is then a named copy on it. Empty: the
	// device's archive path is used.
	FS string
	// ArchiveFS is the file system of the device's archive path as the pull
	// read it ("" when it has none, or the record does not say). Used only
	// when FS is empty.
	ArchiveFS string
}

// The two forms of a restore point.
const (
	// RestoreCopy is 'copy running-config <fs>tacctl-<label>-<ts>.cfg'.
	RestoreCopy = "copy"
	// RestoreArchive is 'archive config'.
	RestoreArchive = "archive"
)

// reRestoreFS is a file system word: lower case letters and digits, a colon.
var reRestoreFS = regexp.MustCompile(`^[a-z0-9]+:$`)

// restoreRemoteFS are the file systems a copy would ask more questions for
// (an address, a user), which the one empty line of the block does not answer.
var restoreRemoteFS = []string{"ftp:", "tftp:", "rcp:", "scp:", "sftp:", "http:", "https:", "null:", "system:"}

// ValidRestoreFS says why a file system word is not usable ("" when it is).
func ValidRestoreFS(fs string) string {
	switch {
	case !reRestoreFS.MatchString(fs):
		return "'" + fs + "' is not a file system of a device ('flash:', 'bootflash:', 'disk0:': lower case letters and digits, then a colon)"
	case slices.Contains(restoreRemoteFS, fs):
		return "'" + fs + "' is not a local file system: a copy to it asks for more than the one empty line of the block answers (use flash:, bootflash:, disk0: or the like)"
	}
	return ""
}

// Mode is RestoreCopy when a file system was named, RestoreArchive when the
// archive path is used, and "" when neither is known.
func (r *RestorePoint) Mode() string {
	switch {
	case r == nil:
		return ""
	case r.FS != "":
		return RestoreCopy
	case r.ArchiveFS != "":
		return RestoreArchive
	}
	return ""
}

// Validate is the reason the restore point cannot be made ("" when it can).
func (r *RestorePoint) Validate() string {
	switch {
	case r == nil:
		return ""
	case r.FS != "":
		return ValidRestoreFS(r.FS)
	case r.ArchiveFS == "":
		return "no file system is known for the restore point: the last pull of the device shows no 'archive' with a 'path'"
	}
	return ""
}

// restoreLabel is the part of the file name that says the device: its first
// label (the name up to the first dot: IOS limits a file name to about 63
// characters), with every character outside letters, digits, '-' and '_'
// turned into '-', at most 32 characters.
func restoreLabel(device string) string {
	label, _, _ := strings.Cut(device, ".")
	label = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '-'
	}, label)
	if len(label) > 32 {
		label = label[:32]
	}
	if label == "" {
		label = "device"
	}
	return label
}

// File is the file the copy form makes: '<fs>tacctl-<label>-<yyyymmdd-hhmm>.cfg'
// (the plan's time, UTC). "" for the archive form, whose name the device makes.
func (r *RestorePoint) File(h Header) string {
	if r.Mode() != RestoreCopy {
		return ""
	}
	return r.FS + "tacctl-" + restoreLabel(h.Device) + "-" + h.Now.UTC().Format("20060102-1504") + ".cfg"
}

// FileSystem is the file system the restore point is on.
func (r *RestorePoint) FileSystem() string {
	if r.Mode() == RestoreCopy {
		return r.FS
	}
	return r.ArchiveFS
}

// Command is the one command of the block.
func (r *RestorePoint) Command(h Header) string {
	if r.Mode() == RestoreArchive {
		return "archive config"
	}
	return "copy running-config " + r.File(h)
}

// Name is what the kept back-out records of the restore point: the file, or
// "archive config" for the form that has no name of its own.
func (r *RestorePoint) Name(h Header) string {
	if r.Mode() == RestoreArchive {
		return "archive config"
	}
	return r.File(h)
}

// RestoreName is the restore point of a plan as the kept back-out records it
// ("" when the plan has none, or nothing is pasted).
func RestoreName(d Delta, h Header) string {
	if !d.restoreShown() {
		return ""
	}
	return d.Restore.Name(h)
}

// restoreShown reports whether the output has a restore block: the plan asked
// for one, and there is a region to paste (the first, or a cleanup alone).
func (d Delta) restoreShown() bool {
	return d.Vendor == devconf.FamilyIOS && d.Restore.Mode() != "" && (!d.Empty() || !d.Cleanup.Empty())
}

// restoreNote is the sentence the report carries for the 'archive config'
// form, the one form of the restore point not run on a device: the copy form
// and its 'configure replace' alternative are not marked.
const restoreNote = "restore point: the 'archive config' form has not been checked on a device (not lab-tested): read it before you use it"

// restoreNoteFor is restoreNote for the form that carries it, else "".
func restoreNoteFor(r *RestorePoint) string {
	if r != nil && r.Mode() == RestoreArchive {
		return restoreNote
	}
	return ""
}

// RestoreLines are the lines between the restore banners: the one command
// and, for a copy, the one empty line that answers its 'Destination
// filename' prompt. nil when the output has no restore block.
func RestoreLines(d Delta, h Header) []string {
	if !d.restoreShown() {
		return nil
	}
	if d.Restore.Mode() == RestoreArchive {
		return []string{d.Restore.Command(h)}
	}
	return []string{d.Restore.Command(h), ""}
}

func restoreFromBanner(d Delta, h Header) string {
	bc := bannerChar(d.Vendor)
	return bc + " RESTORE POINT FROM HERE: " + h.Device + " " + bc
}

func restoreToBanner(d Delta, h Header) string {
	bc := bannerChar(d.Vendor)
	return bc + " RESTORE POINT TO HERE: " + h.Device + " " + bc
}

// RestoreRegion is the restore block of an output: the comments that say
// what it is and how to use it, then its banner pair and the lines between
// them ("" when the plan has none). It is written before the plan's region.
func RestoreRegion(d Delta, h Header) string {
	if !d.restoreShown() {
		return ""
	}
	var b strings.Builder
	c := commentLeader(d.Vendor)
	add := func(s string) {
		for _, l := range wrapText(s, 96) {
			b.WriteString(c + " " + l + "\n")
		}
	}
	r := d.Restore
	fs := r.FileSystem()
	switch r.Mode() {
	case RestoreCopy:
		add("RESTORE POINT (--restore-point): a copy of the running configuration of " + h.Device + " on " + fs + ", made before the plan is pasted. " +
			"Paste this block first and on its own, at the privileged prompt (a prompt ending in #, not in (config)#), then check that 'dir " + fs +
			"' lists " + strings.TrimPrefix(r.File(h), fs) + " before you paste the plan.")
		add("The one empty line answers the 'Destination filename' prompt; it does no harm where that prompt is off ('file prompt quiet'). " +
			"A paste tool that drops blank lines turns the next line, the closing banner, into the file name: paste this block as it stands, or type the copy line yourself.")
	default:
		add("RESTORE POINT (--restore-point): the running configuration of " + h.Device + ", archived with 'archive config' before the plan is pasted " +
			"(the pull read an archive path on " + fs + "; the device names the file from it and asks for no name). " +
			"Paste this block first and on its own, at the privileged prompt (a prompt ending in #, not in (config)#), then check that 'show archive' lists " +
			"a new, newest entry before you paste the plan.")
	}
	room := "It needs free space on " + fs + "."
	if slices.Contains(restoreRemoteFS, fs) {
		room = "It needs room on the server the archive path names (" + fs + ")."
	}
	add("It is a copy of the running configuration, so it holds the device's secrets in their own forms: protect the file and delete it when you are done. " + room)
	add("It is a file, not a rollback timer: IOS has no commit-confirm for a pasted plan and nothing restores it by itself. " +
		"To go back with it, see the back-out ('tacctl device config plan " + h.Device + " --backout').")
	b.WriteString(restoreFromBanner(d, h) + "\n")
	for _, l := range RestoreLines(d, h) {
		b.WriteString(l + "\n")
	}
	b.WriteString(restoreToBanner(d, h) + "\n")
	b.WriteString(c + "\n")
	return b.String()
}

// restoreAlternative writes, through add (a paragraph, wrapped) and lit (a
// line typed as it stands, a comment), the 'configure replace' way back: what
// it is, the caveats of the 12.4 lab and where the file is. lead is "Or, " or
// "". Comment lines only: tacctl pastes none of it.
func restoreAlternative(d Delta, h Header, lead string, add func(string), lit func(string)) {
	r := d.Restore
	if r.Mode() == "" {
		return
	}
	word := "if"
	if lead == "" {
		word = "If"
	}
	switch r.Mode() {
	case RestoreCopy:
		add(lead + word + " the restore point was taken (" + r.File(h) + " is on " + r.FS + "), put that file back; in privileged mode, not in configuration mode:")
		lit("configure replace " + r.File(h) + " force")
	default:
		add(lead + word + " the restore point was taken ('archive config': the file is the newest entry of 'show archive', named by the device's archive path on " +
			r.ArchiveFS + "), put that file back; in privileged mode, not in configuration mode:")
		lit("configure replace <that file> force")
	}
	add("'configure replace' applies the difference between the file and the running configuration; " +
		"where a release does not have it, 'copy <file> running-config' only MERGES the file into the running configuration and removes nothing. " +
		"On IOS 12.4 the removal of 'aaa new-model' was skipped in one pass: do not rely on it for AAA, use the 'no' lines of the back-out.")
	add("Check as after the plan (a pull with --diff, a NEW ssh session), then delete the file, and any copy the replace left on the file system, when you are done.")
}

// CheckRestorePoint is the whole-paste invariant of the restore block, as an
// allowlist over the lines between its banners: exactly 'archive config', or
// exactly one 'copy running-config <fs>tacctl-<label>-<yyyymmdd-hhmm>.cfg'
// and one empty line. A byte that is not printable ASCII is a fault.
func CheckRestorePoint(lines []string) error {
	for i, l := range lines {
		for j := 0; j < len(l); j++ {
			if c := l[j]; c < 0x20 || c > 0x7e {
				return fmt.Errorf("line %d, %q, holds a byte (0x%02x) that is not printable ASCII", i+1, l, c)
			}
		}
	}
	switch {
	case slices.Equal(lines, []string{"archive config"}):
		return nil
	case len(lines) == 2 && lines[1] == "" && reRestoreCopy.MatchString(lines[0]):
		fs := reRestoreCopy.FindStringSubmatch(lines[0])[1]
		if ValidRestoreFS(fs) != "" {
			return fmt.Errorf("the copy goes to %s: %s", fs, ValidRestoreFS(fs))
		}
		return nil
	case len(lines) == 0:
		return errors.New("an empty restore block")
	}
	return fmt.Errorf("the restore block is %q, not 'archive config' or one 'copy running-config <fs>tacctl-<name>-<time>.cfg' and an empty line", lines)
}

var reRestoreCopy = regexp.MustCompile(`^copy running-config ([a-z0-9]+:)tacctl-[A-Za-z0-9_-]+-[0-9]{8}-[0-9]{4}\.cfg$`)
