//go:build !linux && !darwin && !freebsd

package neighbors

import (
	"fmt"
	"runtime"
)

func defaultRoutes() (v4, v6 Route, err error) {
	return v4, v6, fmt.Errorf("default routes are not supported on %s", runtime.GOOS)
}
