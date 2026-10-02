//go:build darwin

package link

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// BPF_ALIGNMENT is sizeof(int32_t) on macOS.
const bpfAlignment = 4

func setInbound(fd int) error {
	// Do not capture the packets we send.
	if err := ioctlUint32(fd, unix.BIOCSSEESENT, 0); err != nil {
		return fmt.Errorf("link: BIOCSSEESENT: %w", err)
	}
	return nil
}
