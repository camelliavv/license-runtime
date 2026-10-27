//go:build windows

package hardwareid

import (
	"fmt"
	"syscall"
	"unsafe"
)

const machineGuidRegistryPath = `SOFTWARE\Microsoft\Cryptography`

// Current 读取 Windows 机器级 MachineGuid，并返回稳定的 HardwareID。
func Current() (string, error) {
	value, err := readMachineGUID(syscall.KEY_WOW64_64KEY)
	if err != nil {
		// 32 位 Windows 或没有 64 位注册表视图时，回退到默认视图。
		value, err = readMachineGUID(0)
	}
	if err != nil {
		return "", fmt.Errorf("%w: read Windows MachineGuid: %v", ErrUnavailable, err)
	}
	return derive("windows", "machine-guid", value)
}

func readMachineGUID(view uint32) (string, error) {
	path, err := syscall.UTF16PtrFromString(machineGuidRegistryPath)
	if err != nil {
		return "", err
	}
	name, err := syscall.UTF16PtrFromString("MachineGuid")
	if err != nil {
		return "", err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_READ|view, &key); err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(key)

	var valueType uint32
	var valueSize uint32
	if err := syscall.RegQueryValueEx(key, name, nil, &valueType, nil, &valueSize); err != nil {
		return "", err
	}
	if valueType != syscall.REG_SZ && valueType != syscall.REG_EXPAND_SZ || valueSize == 0 {
		return "", fmt.Errorf("MachineGuid has unsupported registry type %d", valueType)
	}
	buffer := make([]uint16, valueSize/2+1)
	byteBuffer := (*byte)(unsafe.Pointer(&buffer[0]))
	if err := syscall.RegQueryValueEx(key, name, nil, &valueType, byteBuffer, &valueSize); err != nil {
		return "", err
	}
	value := syscall.UTF16ToString(buffer)
	if value == "" {
		return "", fmt.Errorf("MachineGuid is empty")
	}
	return value, nil
}
