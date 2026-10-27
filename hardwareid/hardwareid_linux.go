//go:build linux

package hardwareid

import (
	"fmt"
	"os"
	"strings"
)

const (
	// dockerHostMachineIDPath 是 Docker 容器中约定的宿主机 machine-id 挂载路径。
	dockerHostMachineIDPath = "/run/license/host-machine-id"
	linuxMachineIDPath      = "/etc/machine-id"
	linuxDBusMachineIDPath  = "/var/lib/dbus/machine-id"
)

// Current 读取 Linux 宿主机的 machine-id，并返回稳定的 HardwareID。
// Docker 中必须将宿主机 /etc/machine-id 只读挂载到 dockerHostMachineIDPath，
// 不读取容器镜像内部可能被复制的 /etc/machine-id。
func Current() (string, error) {
	paths := []string{dockerHostMachineIDPath}

	inContainer := runningInContainer()
	if !inContainer {
		paths = append(paths, linuxMachineIDPath, linuxDBusMachineIDPath)
	}

	var lastErr error
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			lastErr = err
			continue
		}
		machineID := strings.ToLower(strings.TrimSpace(string(raw)))
		if len(machineID) != 32 || !isHex(machineID) {
			lastErr = fmt.Errorf("invalid machine-id in %s", path)
			continue
		}
		return derive("linux", "machine-id", machineID)
	}

	if inContainer {
		return "", fmt.Errorf("%w: Docker must mount host /etc/machine-id at %s", ErrUnavailable, dockerHostMachineIDPath)
	}
	return "", fmt.Errorf("%w: cannot read Linux machine-id: %v", ErrUnavailable, lastErr)
}

func runningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if raw, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		value := strings.ToLower(string(raw))
		return strings.Contains(value, "docker") || strings.Contains(value, "containerd") || strings.Contains(value, "kubepods") || strings.Contains(value, "podman")
	}
	return false
}

func isHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
