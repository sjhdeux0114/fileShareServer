package main

import (
	"context"
	"runtime"
	"syscall"
	"unsafe"
)

type comGUID struct {
	A    uint32
	B, C uint16
	D    [8]byte
}

type comObject struct{ VTable *[29]uintptr }

func comMethod(object *comObject, index int, args ...uintptr) uintptr {
	result, _, _ := syscall.SyscallN(object.VTable[index], append([]uintptr{uintptr(unsafe.Pointer(object))}, args...)...)
	return result
}
func chooseFolder(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ole := syscall.NewLazyDLL("ole32.dll")
	result, _, _ := ole.NewProc("CoInitializeEx").Call(0, 6)
	if int32(result) < 0 {
		return "", problem(500, "폴더 선택기를 초기화하지 못했습니다.")
	}
	defer ole.NewProc("CoUninitialize").Call()
	class := comGUID{0xdc1c5a9c, 0xe88a, 0x4dde, [8]byte{0xa5, 0xa1, 0x60, 0xf8, 0x2a, 0x20, 0xae, 0xf7}}
	iface := comGUID{0xd57c7288, 0xd4ad, 0x4768, [8]byte{0xbe, 0x02, 0x9d, 0x96, 0x95, 0x32, 0xd9, 0x60}}
	var dialog *comObject
	result, _, _ = ole.NewProc("CoCreateInstance").Call(uintptr(unsafe.Pointer(&class)), 0, 1, uintptr(unsafe.Pointer(&iface)), uintptr(unsafe.Pointer(&dialog)))
	if int32(result) < 0 {
		return "", problem(500, "폴더 선택 창을 열지 못했습니다.")
	}
	defer comMethod(dialog, 2)
	var options uint32
	if int32(comMethod(dialog, 10, uintptr(unsafe.Pointer(&options)))) < 0 {
		return "", problem(500, "폴더 선택 옵션을 읽지 못했습니다.")
	}
	if int32(comMethod(dialog, 9, uintptr(options|0x20|0x40|0x800))) < 0 {
		return "", problem(500, "폴더 선택 옵션을 설정하지 못했습니다.")
	}
	comMethod(dialog, 17, uintptr(unsafe.Pointer(wide("FileShare · 공유할 폴더를 선택하세요"))))
	result = comMethod(dialog, 3, 0)
	if uint32(result) == 0x800704c7 {
		return "", nil
	}
	if int32(result) < 0 {
		return "", problem(500, "폴더 선택 창을 열지 못했습니다.")
	}
	var item *comObject
	if int32(comMethod(dialog, 20, uintptr(unsafe.Pointer(&item)))) < 0 {
		return "", problem(500, "선택한 폴더를 읽지 못했습니다.")
	}
	defer comMethod(item, 2)
	var text *uint16
	if int32(comMethod(item, 5, 0x80058000, uintptr(unsafe.Pointer(&text)))) < 0 {
		return "", problem(500, "폴더 경로를 읽지 못했습니다.")
	}
	defer ole.NewProc("CoTaskMemFree").Call(uintptr(unsafe.Pointer(text)))
	units := make([]uint16, 0, 260)
	for i := 0; i < 32768; i++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(text), uintptr(i)*2))
		if c == 0 {
			break
		}
		units = append(units, c)
	}
	return syscall.UTF16ToString(units), nil
}
