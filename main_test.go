package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootSandbox(t *testing.T) {
	a, err := newApp(t.TempDir(), "", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	defer a.root.Close()
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
	defer a.root.Close()
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
	defer a.root.Close()
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
