package store

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The pre-store config (lib/store.sh at 0.1.16, plan 4.4): the first import
// of the live tacquito.yaml ("the flip") keeps that file as
// <legacy dir>/tacquito.yaml.pre-store.<ts> (0600: it holds the shared
// secrets and hashes). 'tacctl store rollback' puts the newest one back.

// PreStorePrefix is the name of a pre-store copy before its timestamp.
const PreStorePrefix = "tacquito.yaml.pre-store."

// PreStoreLatest is store_pre_store_latest: the path of the newest
// pre-store copy in dir (regular files only, symlinks ignored; "newest" is
// the greatest name), or false when there is none.
func PreStoreLatest(dir string) (string, bool) {
	entries, _ := os.ReadDir(dir)
	newest := ""
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), PreStorePrefix) {
			continue
		}
		f := filepath.Join(dir, e.Name())
		st, err := os.Lstat(f)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if newest == "" || f > newest {
			newest = f
		}
	}
	return newest, newest != ""
}

// KeepPreStore is store_keep_pre_store: keep a copy of src in dir as
// tacquito.yaml.pre-store.<YYYYmmdd_HHMMSS>[.<n>] (dir created 0700, the
// copy 0600) and return its path. When the newest copy already holds the
// same bytes it is reused, so a repeated or resumed import does not pile
// them up. Errors are file-system errors (Report prints them).
func KeepPreStore(src, dir string, now time.Time) (string, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", &osError{err}
	}
	if newest, ok := PreStoreLatest(dir); ok {
		if cur, err := os.ReadFile(newest); err == nil && bytes.Equal(cur, data) {
			return newest, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", &osError{err}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", &osError{err}
	}
	base := filepath.Join(dir, PreStorePrefix+now.Format("20060102_150405"))
	dest := base
	for n := 1; ; n++ {
		f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			dest = base + "." + strconv.Itoa(n)
			continue
		}
		if err != nil {
			return "", &osError{err}
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = os.Chmod(dest, 0o600)
		}
		if werr != nil {
			_ = os.Remove(dest)
			return "", &osError{werr}
		}
		return dest, nil
	}
}
