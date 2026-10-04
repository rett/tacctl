package store_test

import (
	"os"
	"syscall"
)

func statIno(st os.FileInfo) uint64 {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}
