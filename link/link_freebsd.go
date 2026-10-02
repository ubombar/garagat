//go:build freebsd

package link

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// BPF_ALIGNMENT is sizeof(long) on FreeBSD.
const bpfAlignment = 8

// BPF_D_IN from net/bpf.h.
const bpfDirectionIn = 0

func setInbound(fd int) error {
	if err := ioctlUint32(fd, unix.BIOCSDIRECTION, bpfDirectionIn); err != nil {
		return fmt.Errorf("link: BIOCSDIRECTION: %w", err)
	}
	return nil
}
