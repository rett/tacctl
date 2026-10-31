// Package blocks is tacctl's configuration blocks (0.2.7, docs/plans/
// 0.2.7-blocks-plan.md): the vendor syntax a scope, or one device, carries
// beyond the structured settings, kept as text files and held to a grammar
// of their own (snmp.go: the Junos snmp block).
//
// The store (this file) is the files: StateDir/blocks/<scope>/<vendor>/
// <block> for a scope and StateDir/blocks/_devices/<device>/<vendor>/<block>
// for a device, directories 0700 and files 0600, written through a
// temporary file in the same directory (fsync, rename) so a reader never
// sees half a block. The device directory starts with '_', which no scope
// name does (names.MatchScope: a letter first), so it can never be a scope.
//
// Which blocks are in force is not the store's to say: tacctl.yaml names
// them (blocks.<scope>.<vendor> and blocks_device.<device>.<vendor>,
// internal/conf). A file the manifest does not name is ignored, and a name
// without a file is a finding (Verify, VerifyDevices).
// The store never prints what a block holds: a block carries community
// strings.
package blocks

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/names"
)

// The vendors a block is written for (the values of a scope's vendor
// attributes and of a device's vendor). Junos is the only one with a grammar
// in this release.
const (
	VendorJuniper = "juniper"
	VendorCisco   = "cisco"
)

// Vendors are the vendors the store accepts, in the order they are listed.
var Vendors = []string{VendorJuniper, VendorCisco}

// The blocks tacctl knows.
const (
	BlockSNMP   = "snmp"
	BlockSystem = "system"
)

// KnownBlocks are the block names the store accepts today, in the order they
// are listed: a table, extended when a block type exists (a name of another
// shape is refused whatever the table says).
var KnownBlocks = []string{BlockSNMP, BlockSystem}

// DevicesDir is the directory of the device level under the store's root.
// It starts with '_', so it can never be the name of a scope (a scope name
// starts with a letter).
const DevicesDir = "_devices"

// MaxSize is the most bytes one block file may hold (a login message of
// banner art is a few kilobytes).
const MaxSize = 256 * 1024

// ErrNotFound is what Read and Remove say of a block that has no file.
var ErrNotFound = errors.New("no such block")

var (
	reBlock  = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	reDevice = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$`)
)

func fail(lines ...string) error { return &names.Error{Msgs: lines} }

func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// Level is where a block applies: a scope's, or one device's. Exactly one
// field is set.
type Level struct {
	Scope  string
	Device string
}

// ScopeLevel is the level of a scope's blocks.
func ScopeLevel(scope string) Level { return Level{Scope: scope} }

// DeviceLevel is the level of one device's own blocks.
func DeviceLevel(device string) Level { return Level{Device: device} }

// IsDevice reports a device level.
func (l Level) IsDevice() bool { return l.Device != "" }

// String names the level for a message: "scope lab" or "device <name>".
func (l Level) String() string {
	if l.IsDevice() {
		return "device " + l.Device
	}
	return "scope " + l.Scope
}

// Validate is nil when the level names exactly one scope or one device, in a
// shape that can never leave the directory.
func (l Level) Validate() error {
	switch {
	case l.Scope != "" && l.Device != "":
		return fail("A block level is a scope or a device, not both.")
	case l.IsDevice():
		return ValidateDevice(l.Device)
	}
	return ValidateScope(l.Scope)
}

// dir is the level's path elements under the root; the device's name is
// lower case, as the registry compares names without regard to case.
func (l Level) dir() []string {
	if l.IsDevice() {
		return []string{DevicesDir, strings.ToLower(l.Device)}
	}
	return []string{l.Scope}
}

// ValidateScope checks a scope name against the store's shape
// (names.MatchScope), so it can never leave the directory or be the device
// level's.
func ValidateScope(scope string) error {
	if !names.MatchScope(scope) {
		return fail("Invalid scope name '" + scope + "'.")
	}
	return nil
}

// ValidateDevice checks a device name against the registry's shape (letters,
// digits, '.', '_' and '-', no leading '.', no '..', no trailing '.'), so it
// can never leave the directory.
func ValidateDevice(device string) error {
	if !reDevice.MatchString(device) || strings.Contains(device, "..") || strings.HasSuffix(device, ".") {
		return fail("Invalid device name '" + device + "'.")
	}
	return nil
}

// ValidateVendor checks a vendor against Vendors.
func ValidateVendor(vendor string) error {
	if !slices.Contains(Vendors, vendor) {
		return fail("Unknown vendor '" + vendor + "' for a block (one of: " + strings.Join(Vendors, ", ") + ").")
	}
	return nil
}

// ValidateBlock checks a block name: the shape [a-z0-9-]{1,32} and a name in
// KnownBlocks.
func ValidateBlock(block string) error {
	if !reBlock.MatchString(block) {
		return fail("Invalid block name '" + block + "' (lower case letters, digits and '-', at most 32).")
	}
	if !slices.Contains(KnownBlocks, block) {
		return fail("Unknown block '" + block + "' (one of: " + strings.Join(KnownBlocks, ", ") + ").")
	}
	return nil
}

// Store is the block files under Dir (paths.Paths.BlocksDir).
type Store struct {
	Dir string
}

// NewStore is the store rooted at dir.
func NewStore(dir string) *Store { return &Store{Dir: dir} }

// levelDir is the directory of a level's blocks (after validating it).
func (s *Store) levelDir(l Level) (string, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	return filepath.Join(append([]string{s.Dir}, l.dir()...)...), nil
}

// vendorDir is the directory of a level's blocks of one vendor.
func (s *Store) vendorDir(l Level, vendor string) (string, error) {
	d, err := s.levelDir(l)
	if err != nil {
		return "", err
	}
	if err := ValidateVendor(vendor); err != nil {
		return "", err
	}
	return filepath.Join(d, vendor), nil
}

// Path is the file of a block (it need not exist).
func (s *Store) Path(l Level, vendor, block string) (string, error) {
	d, err := s.vendorDir(l, vendor)
	if err != nil {
		return "", err
	}
	if err := ValidateBlock(block); err != nil {
		return "", err
	}
	return filepath.Join(d, block), nil
}

// Read is a block's text; ErrNotFound when it has no file. A file that is
// not a regular one (a symbolic link) is refused.
func (s *Store) Read(l Level, vendor, block string) ([]byte, error) {
	p, err := s.Path(l, vendor, block)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ErrNotFound
	case err != nil:
		return nil, fail("Cannot read " + p + ": " + errText(err))
	case !fi.Mode().IsRegular():
		return nil, fail(p + " is not a regular file.")
	case fi.Size() > MaxSize:
		return nil, fail(p + " is larger than 256 KiB.")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fail("Cannot read " + p + ": " + errText(err))
	}
	return data, nil
}

// Write puts a block's text in place: a temporary file in the same
// directory (0600), fsync, rename, then the directory's fsync, with the
// directories made 0700 on the way. Nothing is written when data is larger
// than MaxSize.
func (s *Store) Write(l Level, vendor, block string, data []byte) error {
	p, err := s.Path(l, vendor, block)
	if err != nil {
		return err
	}
	if len(data) > MaxSize {
		return fail("A block is at most 256 KiB (this one is " + strconv.Itoa(len(data)) + " bytes).")
	}
	d := filepath.Dir(p)
	if err := mkdirAll700(s.Dir, d); err != nil {
		return err
	}
	tf, err := os.CreateTemp(d, "."+block+".*.tmp")
	if err != nil {
		return fail("Cannot write " + p + ": " + errText(err))
	}
	tmp := tf.Name()
	bad := func(err error) error {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return fail("Cannot write " + p + ": " + errText(err))
	}
	if err := tf.Chmod(0o600); err != nil {
		return bad(err)
	}
	if _, err := tf.Write(data); err != nil {
		return bad(err)
	}
	if err := tf.Sync(); err != nil {
		return bad(err)
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return fail("Cannot write " + p + ": " + errText(err))
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return fail("Cannot write " + p + ": " + errText(err))
	}
	if df, err := os.Open(d); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}

// mkdirAll700 makes dir and every directory between root and it 0700,
// whatever the umask; a directory that exists is made 0700 too.
func mkdirAll700(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fail("Cannot create " + dir + ".")
	}
	cur := root
	for _, part := range append([]string{""}, strings.Split(rel, string(filepath.Separator))...) {
		cur = filepath.Join(cur, part)
		if err := os.Mkdir(cur, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fail("Cannot create " + cur + ": " + errText(err))
		}
		if err := os.Chmod(cur, 0o700); err != nil {
			return fail("Cannot protect " + cur + ": " + errText(err))
		}
	}
	return nil
}

// Remove deletes a block's file (ErrNotFound when there is none) and the
// directories that leave empty, up to the root.
func (s *Store) Remove(l Level, vendor, block string) error {
	p, err := s.Path(l, vendor, block)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return fail("Cannot remove " + p + ": " + errText(err))
	}
	s.prune(filepath.Dir(p))
	return nil
}

// prune removes dir and its parents up to the root while they are empty.
func (s *Store) prune(dir string) {
	for dir != s.Dir && strings.HasPrefix(dir, s.Dir+string(filepath.Separator)) {
		if os.Remove(dir) != nil { // only when empty
			return
		}
		dir = filepath.Dir(dir)
	}
	_ = os.Remove(s.Dir) // only when empty
}

// List is the names of the regular files of a level's vendor directory that
// are names of blocks (anything else in it, a temporary file included, is
// not a block), sorted. A missing directory has none.
func (s *Store) List(l Level, vendor string) ([]string, error) {
	d, err := s.vendorDir(l, vendor)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fail("Cannot read " + d + ": " + errText(err))
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && reBlock.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}

// Scopes are the scopes that have a directory under the root (the device
// level's directory is not one: it is no scope name), sorted.
func (s *Store) Scopes() ([]string, error) {
	return s.subdirs(s.Dir, func(n string) bool { return ValidateScope(n) == nil })
}

// Devices are the devices that have a directory of their own blocks, sorted
// (their lower case names).
func (s *Store) Devices() ([]string, error) {
	return s.subdirs(filepath.Join(s.Dir, DevicesDir), func(n string) bool { return ValidateDevice(n) == nil })
}

func (s *Store) subdirs(dir string, ok func(string) bool) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fail("Cannot read " + dir + ": " + errText(err))
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsDir() && ok(e.Name()) {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}

// Vendors are the vendors a level has a directory for, in the order of the
// Vendors table.
func (s *Store) Vendors(l Level) ([]string, error) {
	d, err := s.levelDir(l)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range Vendors {
		if fi, err := os.Lstat(filepath.Join(d, v)); err == nil && fi.IsDir() {
			out = append(out, v)
		}
	}
	return out, nil
}

// RemoveScope deletes every block of the scope (a scope removed); no
// directory is nothing to do.
func (s *Store) RemoveScope(scope string) error {
	d, err := s.levelDir(ScopeLevel(scope))
	if err != nil {
		return err
	}
	if err := os.RemoveAll(d); err != nil {
		return fail("Cannot remove " + d + ": " + errText(err))
	}
	_ = os.Remove(s.Dir) // only when empty
	return nil
}

// RenameScope moves the scope's blocks to the new name (a scope renamed); no
// directory is nothing to do. A directory the new name already has is never
// merged into or replaced: it is a leftover (a scope removed earlier, a
// directory a rollback kept), and the renamed scope would otherwise lose its
// own blocks to it or take it over.
func (s *Store) RenameScope(old, newName string) error {
	from, err := s.levelDir(ScopeLevel(old))
	if err != nil {
		return err
	}
	to, err := s.levelDir(ScopeLevel(newName))
	if err != nil {
		return err
	}
	if _, err := os.Lstat(from); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := s.CheckNoScope(newName); err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail("Cannot rename " + from + ": " + errText(err))
	}
	return nil
}

// CheckNoScope is nil when the scope has no blocks directory. A new scope
// (or a scope renamed to the name) that finds one would pick up the blocks
// of an earlier scope of that name: a directory left by a scope removed with
// the files restored, by a rollback, or by hand. The refusal names it and
// how to go on.
func (s *Store) CheckNoScope(scope string) error {
	d, err := s.levelDir(ScopeLevel(scope))
	if err != nil {
		return err
	}
	if _, err := os.Lstat(d); err == nil {
		return fail("Configuration blocks for a scope named '"+scope+"' are already on disk: "+d+".",
			"They belong to an earlier scope of that name, and the new one would use them. Remove the directory (or move it away), then run the command again.")
	}
	return nil
}

// HasScope reports whether the scope has a blocks directory.
func (s *Store) HasScope(scope string) bool {
	d, err := s.levelDir(ScopeLevel(scope))
	if err != nil {
		return false
	}
	_, err = os.Lstat(d)
	return err == nil
}

// RemoveDevice deletes every block of the device (a device removed); no
// directory is nothing to do. The device level's directory goes when that
// leaves it empty.
func (s *Store) RemoveDevice(device string) error {
	d, err := s.levelDir(DeviceLevel(device))
	if err != nil {
		return err
	}
	if err := os.RemoveAll(d); err != nil {
		return fail("Cannot remove " + d + ": " + errText(err))
	}
	s.prune(filepath.Dir(d))
	return nil
}

// RenameDevice moves the device's blocks to the new name (a device
// renamed); no directory is nothing to do, and a rename of the spelling only
// keeps it (the directory is the lower case name). A directory the new name
// already has is never merged into or replaced: it is a leftover (a device
// removed by hand, a directory a rollback kept), and the renamed device
// would otherwise lose its own blocks to it or take it over.
func (s *Store) RenameDevice(old, newName string) error {
	from, err := s.levelDir(DeviceLevel(old))
	if err != nil {
		return err
	}
	to, err := s.levelDir(DeviceLevel(newName))
	if err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if _, err := os.Lstat(from); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := s.CheckNoDevice(newName); err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail("Cannot rename " + from + ": " + errText(err))
	}
	return nil
}

// File is one block file of a device, read to be written under another
// name.
type File struct {
	Vendor, Block string
	Data          []byte
}

// ReadDevice reads every block file of the device (a device with none has
// none), vendor by vendor in the order of Vendors and each vendor's blocks
// by name. Nothing is written, so a file that cannot be read is found before
// a copy changes anything.
func (s *Store) ReadDevice(device string) ([]File, error) {
	var out []File
	l := DeviceLevel(device)
	vendors, err := s.Vendors(l)
	if err != nil {
		return nil, err
	}
	for _, v := range vendors {
		list, err := s.List(l, v)
		if err != nil {
			return nil, err
		}
		for _, b := range list {
			data, err := s.Read(l, v, b)
			if err != nil {
				return nil, err
			}
			out = append(out, File{Vendor: v, Block: b, Data: data})
		}
	}
	return out, nil
}

// WriteDevice writes files as the blocks of the device, which must have no
// blocks directory (CheckNoDevice: a copy never merges into the blocks of an
// earlier device of the name). A write that fails takes back what was
// written, so the device has no half a copy.
func (s *Store) WriteDevice(device string, files []File) error {
	if len(files) == 0 {
		return nil
	}
	if err := s.CheckNoDevice(device); err != nil {
		return err
	}
	for _, f := range files {
		if err := s.Write(DeviceLevel(device), f.Vendor, f.Block, f.Data); err != nil {
			_ = s.RemoveDevice(device)
			return err
		}
	}
	return nil
}

// CheckNoDevice is nil when the device has no blocks directory. A new device
// (or a device renamed to the name) that finds one would pick up the blocks
// of an earlier device of that name: a directory left by a device removed
// with the files restored, by a rollback, or by hand. The refusal names it
// and how to go on.
func (s *Store) CheckNoDevice(device string) error {
	d, err := s.levelDir(DeviceLevel(device))
	if err != nil {
		return err
	}
	if _, err := os.Lstat(d); err == nil {
		return fail("Configuration blocks for a device named '"+device+"' are already on disk: "+d+".",
			"They belong to an earlier device of that name, and the new one would use them. Remove the directory (or move it away), then run the command again.")
	}
	return nil
}

// HasDevice reports whether the device has a blocks directory.
func (s *Store) HasDevice(device string) bool {
	d, err := s.levelDir(DeviceLevel(device))
	if err != nil {
		return false
	}
	_, err = os.Lstat(d)
	return err == nil
}
