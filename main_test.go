package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenameCaseOnlyAndCollision(t *testing.T) {
	a, err := newApp(t.TempDir(), "", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.root.Close() }()
	a.root.WriteFile("Report.TXT", []byte("original"), 0600)
	call := func(name string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"action": "rename", "path": "Report.TXT", "name": name})
		r := httptest.NewRequest("POST", "http://localhost/api/operations", strings.NewReader(string(body)))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("X-FileShare", "1")
		r.AddCookie(&http.Cookie{Name: "session", Value: a.token()})
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	a.root.WriteFile("existing.txt", []byte("keep"), 0600)
	if w := call("existing.txt"); w.Code != 409 {
		t.Fatalf("collision: %d", w.Code)
	}
	if w := call("report.txt"); w.Code != 200 {
		t.Fatalf("case-only rename failed: %d %s", w.Code, w.Body.String())
	}
	b, err := a.root.ReadFile("report.txt")
	if err != nil || string(b) != "original" {
		t.Fatal("renamed content changed")
	}
}
func TestRenameWaitsForShortReader(t *testing.T) {
	a, err := newApp(t.TempDir(), "", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.root.Close() }()
	a.root.WriteFile("old.txt", []byte("original"), 0600)
	a.filesystem.RLock()
	go func() { time.Sleep(150 * time.Millisecond); a.filesystem.RUnlock() }()
	r := httptest.NewRequest("POST", "http://localhost/api/operations", strings.NewReader(`{"action":"rename","path":"old.txt","name":"new.txt"}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-FileShare", "1")
	r.AddCookie(&http.Cookie{Name: "session", Value: a.token()})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("short reader caused rename failure: %d %s", w.Code, w.Body.String())
	}
}

func TestDesktopFirstRunSetup(t *testing.T) {
	a, err := newApp(t.TempDir(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.root.Close() }()
	request := func(route, body, address, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost"+route, strings.NewReader(body))
		r.RemoteAddr = address
		r.Header.Set("X-FileShare", "1")
		if token != "" {
			r.AddCookie(&http.Cookie{Name: "session", Value: token})
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if !a.config.NeedsSetup {
		t.Fatal("new desktop install should require setup")
	}
	if w := request("/api/login", `{"password":"`+a.initial+`"}`, "192.168.1.10:1234", ""); w.Code != 403 {
		t.Fatalf("remote login before setup: %d", w.Code)
	}
	if w := request("/api/desktop-session", `{"key":"wrong"}`, "127.0.0.1:1234", ""); w.Code != 401 {
		t.Fatalf("wrong desktop key: %d", w.Code)
	}
	body := `{"key":"` + a.desktopKey + `"}`
	if w := request("/api/desktop-session", body, "192.168.1.10:1234", ""); w.Code != 403 {
		t.Fatalf("remote desktop access: %d", w.Code)
	}
	w := request("/api/desktop-session", body, "127.0.0.1:1234", "")
	if w.Code != 200 {
		t.Fatalf("desktop launch: %d", w.Code)
	}
	cookie := w.Result().Cookies()[0].Value
	if w = request("/api/settings", `{}`, "127.0.0.1:1234", cookie); w.Code != 400 {
		t.Fatalf("incomplete setup: %d", w.Code)
	}
	if w = request("/api/pick-folder", `{}`, "192.168.1.10:1234", cookie); w.Code != 403 {
		t.Fatalf("remote native picker: %d", w.Code)
	}
	shared := t.TempDir()
	payload, _ := json.Marshal(map[string]string{"sharedRoot": shared, "password": "desktop-password"})
	w = request("/api/settings", string(payload), "127.0.0.1:1234", cookie)
	if w.Code != 200 {
		t.Fatalf("save setup: %d %s", w.Code, w.Body.String())
	}
	if a.config.NeedsSetup {
		t.Fatal("setup flag not cleared")
	}
	if w = request("/api/login", `{"password":"desktop-password"}`, "192.168.1.10:1234", ""); w.Code != 200 {
		t.Fatalf("phone login after setup: %d", w.Code)
	}
}

func TestRootSandbox(t *testing.T) {
	a, err := newApp(t.TempDir(), "", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.root.Close() }()
	for _, p := range []string{"../secret", "a/../../secret", "/etc/passwd", "C:/Windows", "a\\b", "foo/.", "foo/..", "foo "} {
		if _, err = a.safe(p, true); err == nil {
			t.Fatalf("allowed unsafe path %q", p)
		}
	}
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0600)
	if err = os.Symlink(outside, filepath.Join(a.config.SharedRoot, "link")); err == nil {
		if _, err = a.safe("link/secret", false); err == nil {
			t.Fatal("symlink escaped")
		}
	}
}
func TestRemoteSettingsDenied(t *testing.T) {
	a, err := newApp(t.TempDir(), "", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.root.Close() }()
	req := httptest.NewRequest("POST", "http://local/api/settings", strings.NewReader(`{"password":"new-password"}`))
	req.RemoteAddr = "192.168.1.20:1234"
	req.Header.Set("X-FileShare", "1")
	req.AddCookie(&http.Cookie{Name: "session", Value: a.token()})
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("remote settings status=%d", rec.Code)
	}
}
func TestTokenTamperAndExpiry(t *testing.T) {
	a, err := newApp(t.TempDir(), "", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.root.Close() }()
	token := a.token()
	if !a.validToken(token) {
		t.Fatal("valid token rejected")
	}
	if a.validToken(token + "a") {
		t.Fatal("tamper accepted")
	}
	a.config.Key = "different-key"
	if a.validToken(token) {
		t.Fatal("old token accepted after rotation")
	}
}
