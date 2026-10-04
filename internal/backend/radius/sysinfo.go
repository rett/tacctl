package radius

import (
	"os"
	"syscall"
)

// blocksOf is the disk space a file occupies, as du counts it: its 512-byte
// blocks (the apparent size where the system does not say).
func blocksOf(st os.FileInfo) int64 {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Blocks * 512
	}
	return st.Size()
}
