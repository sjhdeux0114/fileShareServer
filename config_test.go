package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestINIRoundtrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "FileShare.ini")
	c := Config{SharedRoot: `C:\공유 폴더\a=b`, Port: 9123, Salt: randomHex(16), Key: randomHex(32), Revoked: map[string]int64{"old": 123}}
	c.PasswordHash = derive("test-password", c.Salt)
	if err := writeINI(file, c); err != nil {
		t.Fatal(err)
	}
	got, err := readINI(file)
	if err != nil {
		t.Fatal(err)
	}
	if got.SharedRoot != c.SharedRoot || got.Port != c.Port || got.PasswordHash != c.PasswordHash || got.Revoked["old"] != 123 {
		t.Fatalf("bad roundtrip: %+v", got)
	}
	raw, _ := os.ReadFile(file)
	if strings.Contains(string(raw), "test-password") {
		t.Fatal("plaintext persisted")
	}
}
func TestINIPlainPasswordConverted(t *testing.T) {
	file := filepath.Join(t.TempDir(), "FileShare.ini")
	os.WriteFile(file, []byte("[server]\nSharedFolder = C:\\Shared\nPort = 8787\n[security]\nPassword = new-password\n"), 0600)
	c, err := readINI(file)
	if err != nil {
		t.Fatal(err)
	}
	if c.PasswordHash != derive("new-password", c.Salt) {
		t.Fatal("password not hashed")
	}
	if err = writeINI(file, c); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	if strings.Contains(string(raw), "new-password") {
		t.Fatal("plaintext not removed")
	}
}
