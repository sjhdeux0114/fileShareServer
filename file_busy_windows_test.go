package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRenameRetriesReleasedWindowsHandle(t *testing.T) {
	a, err := newApp(t.TempDir(), "", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.root.Close() }()
	if err = a.root.WriteFile("locked.txt", []byte("bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	filename, _ := syscall.UTF16PtrFromString(filepath.Join(a.config.SharedRoot, "locked.txt"))
	file, err := syscall.CreateFile(filename, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { time.Sleep(180 * time.Millisecond); syscall.CloseHandle(file); close(closed) }()
	defer func() { <-closed }()
	r := httptest.NewRequest("POST", "http://localhost/api/operations", strings.NewReader(`{"action":"rename","path":"locked.txt","name":"released.txt"}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-FileShare", "1")
	r.AddCookie(&http.Cookie{Name: "session", Value: a.token()})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("temporary Windows lock: %d %s", w.Code, w.Body.String())
	}
}
