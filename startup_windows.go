package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const startupKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// Per-user login registration; no administrator rights or shell process needed.
func setStartup(enabled bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return writeStartup(startupKey, "FileShare", exe, enabled)
}

func writeStartup(keyPath, name, exe string, enabled bool) error {
	dll := syscall.NewLazyDLL("advapi32.dll")
	path, err := syscall.UTF16PtrFromString(keyPath)
	if err != nil {
		return err
	}
	value, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var key syscall.Handle
	code, _, _ := dll.NewProc("RegCreateKeyExW").Call(uintptr(syscall.HKEY_CURRENT_USER), uintptr(unsafe.Pointer(path)), 0, 0, 0, 0x20006, 0, uintptr(unsafe.Pointer(&key)), 0)
	if code != 0 {
		return syscall.Errno(code)
	}
	defer syscall.RegCloseKey(key)
	if !enabled {
		code, _, _ = dll.NewProc("RegDeleteValueW").Call(uintptr(key), uintptr(unsafe.Pointer(value)))
		if code == 2 {
			return nil
		}
	} else {
		command := `"` + exe + `"`
		if len(command) > 260 {
			return fmt.Errorf("실행 파일 경로가 너무 깁니다. 짧은 경로로 옮겨주세요")
		}
		data, e := syscall.UTF16FromString(command)
		if e != nil {
			return e
		}
		code, _, _ = dll.NewProc("RegSetValueExW").Call(uintptr(key), uintptr(unsafe.Pointer(value)), 0, 1, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
	}
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}
