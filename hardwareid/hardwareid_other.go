//go:build !linux && !windows

package hardwareid

import (
	"fmt"
	"runtime"
)

// Current 在未实现平台上返回错误，避免误用不稳定的主机名或 MAC 地址。
func Current() (string, error) {
	return "", fmt.Errorf("%w: platform %s is unsupported", ErrUnavailable, runtime.GOOS)
}
