package main

import (
	"syscall"
	"testing"
	"unsafe"
)

func TestStartupRegistryRoundtrip(t *testing.T) {
	// Use a disposable non-Run key so tests never enable login startup.
	path := `Software\FileShareTest-` + randomHex(8)
	p, _ := syscall.UTF16PtrFromString(path)
	defer syscall.NewLazyDLL("advapi32.dll").NewProc("RegDeleteKeyW").Call(uintptr(syscall.HKEY_CURRENT_USER), uintptr(unsafe.Pointer(p)))
	exe := `C:\폴더 with spaces\FileShare.exe`
	if err := writeStartup(path, "FileShare", exe, true); err != nil {
		t.Fatal(err)
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, p, 0, syscall.KEY_READ, &key); err != nil {
		t.Fatal(err)
	}
	defer syscall.RegCloseKey(key)
	name, _ := syscall.UTF16PtrFromString("FileShare")
	data := make([]uint16, 512)
	n := uint32(len(data) * 2)
	var kind uint32
	if err := syscall.RegQueryValueEx(key, name, nil, &kind, (*byte)(unsafe.Pointer(&data[0])), &n); err != nil {
		t.Fatal(err)
	}
	if got := syscall.UTF16ToString(data); got != `"`+exe+`"` {
		t.Fatalf("wrong command %q", got)
	}
	if err := writeStartup(path, "FileShare", exe, false); err != nil {
		t.Fatal(err)
	}
	if err := syscall.RegQueryValueEx(key, name, nil, &kind, nil, &n); err != syscall.ERROR_FILE_NOT_FOUND {
		t.Fatalf("value still present: %v", err)
	}
}
