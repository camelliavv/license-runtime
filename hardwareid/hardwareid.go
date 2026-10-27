// Package hardwareid 提供跨平台的客户设备身份读取实现。
package hardwareid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const hardwareIDFormatVersion = "hw1"

// ErrUnavailable 表示当前平台无法读取稳定的宿主机身份。
var ErrUnavailable = errors.New("hardware id unavailable")

// derive 将平台原始身份规范化并转换为不暴露原始值的 HardwareID。
func derive(platform, source, value string) (string, error) {
	platform = strings.ToLower(strings.TrimSpace(platform))
	source = strings.ToLower(strings.TrimSpace(source))
	value = strings.ToLower(strings.TrimSpace(value))
	if platform == "" || source == "" || value == "" {
		return "", fmt.Errorf("%w: empty platform, source or value", ErrUnavailable)
	}
	canonical := platform + ":" + source + ":" + value
	digest := sha256.Sum256([]byte(canonical))
	return hardwareIDFormatVersion + "-" + platform + "-" + source + "-" + hex.EncodeToString(digest[:]), nil
}
