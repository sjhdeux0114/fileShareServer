package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readINI(name string) (Config, error) {
	var c Config
	data, err := os.ReadFile(name)
	if err != nil {
		return c, err
	}
	values := map[string]string{}
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff")))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return c, fmt.Errorf("invalid INI line: %s", line)
		}
		value := strings.TrimSpace(parts[1])
		if strings.HasPrefix(value, `"`) {
			decoded, e := strconv.Unquote(value)
			if e != nil {
				return c, fmt.Errorf("invalid INI quoted value")
			}
			value = decoded
		}
		values[section+"."+strings.ToLower(strings.TrimSpace(parts[0]))] = value
	}
	if err = scanner.Err(); err != nil {
		return c, err
	}
	c.SharedRoot = values["server.sharedfolder"]
	c.Port = 8787
	if value := values["server.port"]; value != "" {
		c.Port, err = strconv.Atoi(value)
		if err != nil || c.Port < 1 || c.Port > 65535 {
			return c, fmt.Errorf("INI Port must be 1-65535")
		}
	}
	c.NeedsSetup = values["server.needssetup"] == "true"
	c.Salt = values["security.salt"]
	c.PasswordHash = values["security.passwordhash"]
	c.Key = values["security.sessionkey"]
	if plaintext := values["security.password"]; plaintext != "" {
		if len([]rune(plaintext)) < 8 {
			return c, fmt.Errorf("INI Password must contain at least 8 characters")
		}
		c.Salt = randomHex(16)
		c.PasswordHash = derive(plaintext, c.Salt)
		c.Key = randomHex(32)
		c.NeedsSetup = c.SharedRoot == ""
	}
	if c.PasswordHash != "" && (!fingerprintPattern.MatchString(c.PasswordHash) || !idPattern.MatchString(c.Salt) || !fingerprintPattern.MatchString(c.Key)) {
		return c, fmt.Errorf("invalid INI security record")
	}
	c.Revoked = map[string]int64{}
	if revoked := values["security.revoked"]; revoked != "" {
		if err = json.Unmarshal([]byte(revoked), &c.Revoked); err != nil {
			return c, fmt.Errorf("invalid INI revoked sessions")
		}
	}
	return c, nil
}

func writeINI(name string, c Config) error {
	if c.Port == 0 {
		c.Port = 8787
	}
	revoked, err := json.Marshal(c.Revoked)
	if err != nil {
		return err
	}
	text := fmt.Sprintf("; FileShare connection settings. Change via tray > Settings.\n; An optional Password field is hashed and removed on next start.\n[server]\nSharedFolder = %s\nPort = %d\nNeedsSetup = %t\n\n[security]\nPasswordHash = %s\nSalt = %s\nSessionKey = %s\nRevoked = %s\n", strconv.Quote(c.SharedRoot), c.Port, c.NeedsSetup, c.PasswordHash, c.Salt, c.Key, revoked)
	if err = os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(name+".tmp", []byte(text), 0600); err != nil {
		return err
	}
	return os.Rename(name+".tmp", name)
}
