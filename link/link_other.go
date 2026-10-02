//go:build !linux && !darwin && !freebsd

package link

import (
	"fmt"
	"runtime"
)

func open(name string, opts Options, filter FilterFunc) (Handle, error) {
	return nil, fmt.Errorf("link: raw sockets are not supported on %s", runtime.GOOS)
}
