package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var trayUser32 = syscall.NewLazyDLL("user32.dll")
var trayShell32 = syscall.NewLazyDLL("shell32.dll")

type windowClass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Name                         *uint16
	SmallIcon                          uintptr
}
type trayData struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Version             uint32
	Title               [64]uint16
	InfoFlags           uint32
	GUID                [16]byte
	Balloon             uintptr
}
type winPoint struct{ X, Y int32 }
type winMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          winPoint
	Private        uint32
}

func wide(text string) *uint16 { p, _ := syscall.UTF16PtrFromString(text); return p }
func showStartupError(message string) {
	log.Print(message)
	if os.Getenv("FILESHARE_NO_TRAY") == "1" {
		return
	}
	trayUser32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(wide(message))), uintptr(unsafe.Pointer(wide("FileShare"))), 0x10)
}

func runTray(settings, folder, stop func()) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	instance, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)
	andMask := make([]byte, 128)
	pixels := make([]byte, 32*32*4)
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			i := (y*32 + x) * 4
			pixels[i], pixels[i+1], pixels[i+2], pixels[i+3] = 40, 28, 16, 255
			if (y >= 8 && y <= 11 && x >= 7 && x <= 24) || (x >= 20 && x <= 24 && y >= 5 && y <= 14 && absInt(y-9) <= 24-x) || (y >= 20 && y <= 23 && x >= 7 && x <= 24) || (x >= 7 && x <= 11 && y >= 17 && y <= 26 && absInt(y-21) <= x-7) {
				pixels[i], pixels[i+1], pixels[i+2] = 107, 243, 201
			}
		}
	}
	icon, _, _ := trayUser32.NewProc("CreateIcon").Call(instance, 32, 32, 1, 32, uintptr(unsafe.Pointer(&andMask[0])), uintptr(unsafe.Pointer(&pixels[0])))
	if icon == 0 {
		icon, _, _ = trayUser32.NewProc("LoadIconW").Call(0, 32512)
	} else {
		defer trayUser32.NewProc("DestroyIcon").Call(icon)
	}
	var data trayData
	notify := trayShell32.NewProc("Shell_NotifyIconW")
	taskbarCreated, _, _ := trayUser32.NewProc("RegisterWindowMessageW").Call(uintptr(unsafe.Pointer(wide("TaskbarCreated"))))
	addIcon := func() { notify.Call(0, uintptr(unsafe.Pointer(&data))); notify.Call(4, uintptr(unsafe.Pointer(&data))) }
	callback := syscall.NewCallback(func(hwnd uintptr, msg uint32, wp, lp uintptr) uintptr {
		if msg == uint32(taskbarCreated) {
			addIcon()
			return 0
		}
		switch msg {
		case 0x8001:
			event := uint32(lp) & 0xffff
			if event == 0x203 {
				go settings()
				return 0
			}
			if event == 0x205 || event == 0x7b {
				menu, _, _ := trayUser32.NewProc("CreatePopupMenu").Call()
				defer trayUser32.NewProc("DestroyMenu").Call(menu)
				appendMenu := trayUser32.NewProc("AppendMenuW")
				appendMenu.Call(menu, 2, 0, uintptr(unsafe.Pointer(wide("FileShare · 서버 실행 중"))))
				appendMenu.Call(menu, 0x800, 0, 0)
				appendMenu.Call(menu, 0, 1, uintptr(unsafe.Pointer(wide("설정 열기…"))))
				appendMenu.Call(menu, 0, 2, uintptr(unsafe.Pointer(wide("공유 폴더 열기"))))
				appendMenu.Call(menu, 0x800, 0, 0)
				appendMenu.Call(menu, 0, 3, uintptr(unsafe.Pointer(wide("서버 종료"))))
				var point winPoint
				trayUser32.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&point)))
				trayUser32.NewProc("SetForegroundWindow").Call(hwnd)
				choice, _, _ := trayUser32.NewProc("TrackPopupMenu").Call(menu, 0x100|0x2, uintptr(point.X), uintptr(point.Y), 0, hwnd, 0)
				trayUser32.NewProc("PostMessageW").Call(hwnd, 0, 0, 0)
				switch choice {
				case 1:
					go settings()
				case 2:
					go folder()
				case 3:
					trayUser32.NewProc("DestroyWindow").Call(hwnd)
				}
			}
			return 0
		case 0x10:
			trayUser32.NewProc("DestroyWindow").Call(hwnd)
			return 0
		case 0x2:
			notify.Call(2, uintptr(unsafe.Pointer(&data)))
			stop()
			trayUser32.NewProc("PostQuitMessage").Call(0)
			return 0
		}
		result, _, _ := trayUser32.NewProc("DefWindowProcW").Call(hwnd, uintptr(msg), wp, lp)
		return result
	})
	name := wide("FileShare.Tray." + randomHex(4))
	class := windowClass{Proc: callback, Instance: instance, Name: name}
	class.Size = uint32(unsafe.Sizeof(class))
	atom, _, err := trayUser32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&class)))
	if atom == 0 {
		return fmt.Errorf("register tray: %v", err)
	}
	defer trayUser32.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(name)), instance)
	hwnd, _, err := trayUser32.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(wide("FileShare Tray"))), 0, 0, 0, 0, 0, 0, 0, instance, 0)
	if hwnd == 0 {
		return fmt.Errorf("create tray: %v", err)
	}
	// Consume a hidden startup ShowWindow hint on our invisible owner, not on later folder dialogs.
	trayUser32.NewProc("ShowWindow").Call(hwnd, 0)
	data = trayData{Window: hwnd, ID: 1, Flags: 7, Callback: 0x8001, Icon: icon}
	data.Size = uint32(unsafe.Sizeof(data))
	tip, _ := syscall.UTF16FromString("FileShare · 우클릭: 설정 / 공유 폴더 / 종료")
	copy(data.Tip[:], tip)
	result, _, err := notify.Call(0, uintptr(unsafe.Pointer(&data)))
	if result == 0 {
		trayUser32.NewProc("DestroyWindow").Call(hwnd)
		return fmt.Errorf("add tray icon: %v", err)
	}
	notify.Call(4, uintptr(unsafe.Pointer(&data)))
	log.Print("Tray icon registered")
	defer notify.Call(2, uintptr(unsafe.Pointer(&data)))
	var msg winMessage
	for {
		value, _, err := trayUser32.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(value) == -1 {
			return err
		}
		if value == 0 {
			break
		}
		trayUser32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&msg)))
		trayUser32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&msg)))
	}
	return nil
}
func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
