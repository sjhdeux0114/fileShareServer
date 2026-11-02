package main

import (
	"archive/zip"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed public/*
var web embed.FS

const chunkSize int64 = 16 << 20
const maxSize int64 = 1 << 40

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type apiError struct {
	status  int
	message string
}

func (e apiError) Error() string               { return e.message }
func problem(status int, message string) error { return apiError{status, message} }

type Config struct {
	AutoStart    bool             `json:"autoStart"`
	Port         int              `json:"port"`
	NeedsSetup   bool             `json:"needsSetup"`
	SharedRoot   string           `json:"sharedRoot"`
	Salt         string           `json:"salt"`
	PasswordHash string           `json:"passwordHash"`
	Key          string           `json:"key"`
	Revoked      map[string]int64 `json:"revoked"`
}
type Upload struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	Fingerprint string `json:"fingerprint"`
	Target      string `json:"target"`
	Root        string `json:"root"`
	Path        string `json:"path,omitempty"`
	Created     int64  `json:"created"`
	Complete    bool   `json:"complete"`
	Offset      int64  `json:"offset"`
}
type attempt struct {
	count int
	until time.Time
}
type App struct {
	configPath  string
	desktopKey  string
	picker      sync.Mutex
	data        string
	root        *os.Root
	config      Config
	auth        sync.Mutex
	filesystem  sync.RWMutex
	uploads     sync.Mutex
	uploadLocks sync.Map
	attempts    map[string]attempt
	initial     string
	thumbnails  chan struct{}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func derive(password, salt string) string {
	b, err := pbkdf2.Key(sha256.New, password, []byte(salt), 600000, 32)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func newApp(data, shared, password string) (*App, error) {
	data, err := filepath.Abs(data)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Join(data, "uploads"), 0700); err != nil {
		return nil, err
	}
	// macOS temporary paths may use /var while the resolved path is /private/var.
	// Compare canonical roots so a shared folder cannot expose private settings.
	data, err = filepath.EvalSymlinks(data)
	if err != nil {
		return nil, err
	}
	a := &App{data: data, attempts: map[string]attempt{}, thumbnails: make(chan struct{}, 2), desktopKey: randomHex(32)}
	a.configPath = os.Getenv("FILESHARE_CONFIG")
	if a.configPath == "" {
		a.configPath = filepath.Join(data, "settings.ini")
	}
	a.configPath, err = filepath.Abs(a.configPath)
	if err != nil {
		return nil, err
	}
	a.config, err = readINI(a.configPath)
	if os.IsNotExist(err) {
		if raw, e := os.ReadFile(filepath.Join(data, "settings.json")); e == nil {
			err = json.Unmarshal(raw, &a.config)
		} else if os.IsNotExist(e) {
			err = nil
		} else {
			err = e
		}
	}
	if err != nil {
		return nil, err
	}
	if a.config.Port == 0 {
		a.config.Port = 8787
	}
	if shared == "" {
		shared = a.config.SharedRoot
	}
	if shared == "" {
		shared = filepath.Join(data, "shared")
	}
	if err = os.MkdirAll(shared, 0755); err != nil {
		return nil, err
	}
	shared, err = filepath.Abs(shared)
	if err != nil {
		return nil, err
	}
	shared, err = filepath.EvalSymlinks(shared)
	if err != nil {
		return nil, err
	}
	if containsPath(shared, data) || containsPath(shared, a.configPath) {
		return nil, fmt.Errorf("shared folder must not contain private settings directory")
	}
	a.root, err = os.OpenRoot(shared)
	if err != nil {
		return nil, err
	}
	a.config.SharedRoot = shared
	if a.config.PasswordHash == "" {
		a.config.NeedsSetup = password == ""
		if password == "" {
			b := make([]byte, 8)
			if _, err = rand.Read(b); err != nil {
				return nil, err
			}
			for i := range b {
				b[i] = '0' + b[i]%10
			}
			password = string(b)
			a.initial = password
		}
		a.config.Salt = randomHex(16)
		a.config.PasswordHash = derive(password, a.config.Salt)
		a.config.Key = randomHex(32)
	}
	if a.config.Revoked == nil {
		a.config.Revoked = map[string]int64{}
	}
	for token, expiry := range a.config.Revoked {
		if expiry < time.Now().Unix() {
			delete(a.config.Revoked, token)
		}
	}
	if err = a.saveConfig(); err != nil {
		a.root.Close()
		return nil, err
	}
	return a, nil
}
func containsPath(parent, child string) bool {
	r, e := filepath.Rel(parent, child)
	return e == nil && (r == "." || r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) && !filepath.IsAbs(r))
}
func (a *App) saveConfig() error {
	return writeINI(a.configPath, a.config)
}
func (a *App) token() string {
	payload := randomHex(16) + "." + strconv.FormatInt(time.Now().Add(30*24*time.Hour).Unix(), 10)
	mac := hmac.New(sha256.New, []byte(a.config.Key))
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func (a *App) validToken(token string) bool {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return false
	}
	expiry, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil || expiry < time.Now().Unix() {
		return false
	}
	if _, ok := a.config.Revoked[tokenHash(token)]; ok {
		return false
	}
	signature, err := hex.DecodeString(p[2])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(a.config.Key))
	mac.Write([]byte(p[0] + "." + p[1]))
	return hmac.Equal(signature, mac.Sum(nil))
}
func setCookie(w http.ResponseWriter, token string) {
	age := 30 * 86400
	if token == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func local(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	return err == nil && net.ParseIP(host).IsLoopback()
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	if err := d.Decode(v); err != nil {
		return problem(400, "잘못된 요청입니다.")
	}
	var rest any
	if err := d.Decode(&rest); err != io.EOF {
		return problem(400, "잘못된 요청입니다.")
	}
	return nil
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; media-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if err := a.route(w, r); err != nil {
		status := 500
		message := "서버 오류가 발생했습니다."
		var e apiError
		if errors.As(err, &e) {
			status = e.status
			message = e.message
		} else if errors.Is(err, fs.ErrNotExist) {
			status = 404
			message = "파일 또는 폴더를 찾을 수 없습니다."
		} else if errors.Is(err, fs.ErrExist) {
			status = 409
			message = "같은 이름의 항목이 있습니다."
		} else if errors.Is(err, fs.ErrPermission) {
			status = 403
			message = "파일 접근 권한이 없습니다."
		} else {
			log.Printf("request error: %v", err)
		}
		reply(w, status, map[string]any{"error": message})
	}
}
func (a *App) route(w http.ResponseWriter, r *http.Request) error {
	route := r.URL.Path
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
		return problem(403, "다른 사이트의 요청은 허용하지 않습니다.")
	}
	if r.Method == "POST" || r.Method == "PATCH" || r.Method == "DELETE" {
		if r.Header.Get("X-FileShare") != "1" {
			return problem(403, "요청 헤더가 필요합니다.")
		}
	}
	if r.Method == "GET" && (route == "/" || route == "/style.css" || route == "/app.js" || route == "/transfer.js") {
		file := strings.TrimPrefix(route, "/")
		if file == "" {
			file = "index.html"
		}
		data, err := web.ReadFile("public/" + file)
		if err != nil {
			return err
		}
		kind := "text/html"
		if strings.HasSuffix(file, ".css") {
			kind = "text/css"
		}
		if strings.HasSuffix(file, ".js") {
			kind = "text/javascript"
		}
		w.Header().Set("Content-Type", kind+"; charset=utf-8")
		w.Write(data)
		return nil
	}
	if route == "/api/desktop-session" && r.Method == "POST" {
		if !local(r) {
			return problem(403, "PC 설정 화면은 서버 PC에서만 사용할 수 있습니다.")
		}
		var body struct {
			Key string `json:"key"`
		}
		if err := decode(w, r, &body); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(body.Key), []byte(a.desktopKey)) != 1 {
			return problem(401, "PC 실행 인증이 만료되었습니다. EXE를 다시 실행하세요.")
		}
		a.auth.Lock()
		defer a.auth.Unlock()
		setCookie(w, a.token())
		reply(w, 200, map[string]bool{"ok": true})
		return nil
	}
	if route == "/api/login" && r.Method == "POST" {
		var body struct {
			Password string `json:"password"`
			Pin      string `json:"pin"`
		}
		if err := decode(w, r, &body); err != nil {
			return err
		}
		if body.Password == "" {
			body.Password = body.Pin
		}
		a.auth.Lock()
		defer a.auth.Unlock()
		if a.config.NeedsSetup {
			return problem(403, "서버 PC에서 공유 폴더와 비밀번호를 먼저 설정하세요.")
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		now := time.Now()
		for k, v := range a.attempts {
			if v.until.Before(now) {
				delete(a.attempts, k)
			}
		}
		entry := a.attempts[host]
		if entry.until.Before(now) {
			entry = attempt{until: now.Add(time.Minute)}
		}
		if entry.count >= 10 {
			return problem(429, "접속 시도가 많습니다. 1분 후 다시 시도하세요.")
		}
		entry.count++
		a.attempts[host] = entry
		if len(body.Password) > 512 || subtle.ConstantTimeCompare([]byte(derive(body.Password, a.config.Salt)), []byte(a.config.PasswordHash)) != 1 {
			return problem(401, "접속 비밀번호가 일치하지 않습니다.")
		}
		delete(a.attempts, host)
		setCookie(w, a.token())
		reply(w, 200, map[string]bool{"ok": true})
		return nil
	}
	cookie, err := r.Cookie("session")
	a.auth.Lock()
	valid := err == nil && a.validToken(cookie.Value)
	a.auth.Unlock()
	if !valid {
		return problem(401, "접속 비밀번호를 입력하세요.")
	}
	if route == "/api/pick-folder" && r.Method == "POST" {
		if !local(r) {
			return problem(403, "폴더 선택은 서버 PC에서만 가능합니다.")
		}
		if !a.picker.TryLock() {
			return problem(409, "이미 폴더 선택 창이 열려 있습니다.")
		}
		defer a.picker.Unlock()
		folder, err := chooseFolder(r.Context())
		if err != nil {
			return err
		}
		reply(w, 200, map[string]string{"path": folder})
		return nil
	}
	if route == "/api/logout" && r.Method == "POST" {
		a.auth.Lock()
		defer a.auth.Unlock()
		parts := strings.Split(cookie.Value, ".")
		expiry, _ := strconv.ParseInt(parts[1], 10, 64)
		a.config.Revoked[tokenHash(cookie.Value)] = expiry
		if err := a.saveConfig(); err != nil {
			return err
		}
		setCookie(w, "")
		reply(w, 200, map[string]bool{"ok": true})
		return nil
	}
	write := route == "/api/settings" || route == "/api/operations" || strings.HasSuffix(route, "/complete")
	if write {
		if strings.HasSuffix(route, "/complete") {
			a.filesystem.Lock()
		} else {
			deadline := time.Now().Add(2 * time.Second)
			for !a.filesystem.TryLock() {
				if time.Now().After(deadline) {
					return problem(423, "다운로드·미리보기 또는 다른 파일 작업이 진행 중입니다. 해당 작업을 끝낸 뒤 다시 시도하세요.")
				}
				select {
				case <-r.Context().Done():
					return problem(408, "요청이 취소되었습니다.")
				case <-time.After(20 * time.Millisecond):
				}
			}
		}
		defer a.filesystem.Unlock()
	} else {
		a.filesystem.RLock()
		defer a.filesystem.RUnlock()
	}
	switch {
	case route == "/api/info" && r.Method == "GET":
		result := map[string]any{"version": "0.3.0", "chunkSize": 2 << 20, "maxFileSize": maxSize, "freeBytes": diskFree(a.config.SharedRoot), "canConfigure": local(r), "folderName": filepath.Base(a.config.SharedRoot), "passwordConfigured": true}
		if local(r) {
			result["sharedRoot"] = a.config.SharedRoot
			result["configuredPort"] = a.config.Port
			result["configFile"] = a.configPath
			result["autoStart"] = a.config.AutoStart
			result["autoStartSupported"] = runtime.GOOS == "windows"
			result["needsSetup"] = a.config.NeedsSetup
			_, port, _ := net.SplitHostPort(r.Host)
			addresses := []string{}
			interfaces, _ := net.InterfaceAddrs()
			for _, addr := range interfaces {
				ip, _, err := net.ParseCIDR(addr.String())
				if err == nil && ip.To4() != nil && !ip.IsLoopback() {
					addresses = append(addresses, "http://"+net.JoinHostPort(ip.String(), port))
				}
			}
			result["phoneUrls"] = addresses
		}
		reply(w, 200, result)
		return nil
	case route == "/api/settings" && r.Method == "POST":
		return a.settings(w, r)
	case route == "/api/entries" && r.Method == "GET":
		return a.entries(w, r)
	case route == "/api/operations" && r.Method == "POST":
		return a.operation(w, r)
	case route == "/api/content" && (r.Method == "GET" || r.Method == "HEAD"):
		return a.content(w, r)
	case route == "/api/zip" && r.Method == "GET":
		return a.zipFolder(w, r)
	case route == "/api/thumbnail" && r.Method == "GET":
		return a.thumbnail(w, r)
	case route == "/api/uploads" && r.Method == "POST":
		return a.beginUpload(w, r)
	case strings.HasPrefix(route, "/api/uploads/"):
		return a.upload(w, r)
	}
	return problem(404, "찾을 수 없는 요청입니다.")
}
func (a *App) settings(w http.ResponseWriter, r *http.Request) error {
	if !local(r) {
		return problem(403, "설정은 서버 PC의 localhost 주소에서만 변경할 수 있습니다.")
	}
	var body struct {
		AutoStart  *bool   `json:"autoStart"`
		Port       *int    `json:"port"`
		SharedRoot *string `json:"sharedRoot"`
		Password   *string `json:"password"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	a.auth.Lock()
	defer a.auth.Unlock()
	next := a.config
	if next.NeedsSetup && (body.Password == nil || body.SharedRoot == nil) {
		return problem(400, "공유 폴더와 접속 비밀번호를 모두 설정하세요.")
	}
	newRoot := a.root
	if body.SharedRoot != nil {
		if !filepath.IsAbs(*body.SharedRoot) {
			return problem(400, "폴더의 절대 경로를 입력하세요.")
		}
		full, err := filepath.EvalSymlinks(*body.SharedRoot)
		if err != nil {
			return err
		}
		if containsPath(full, a.data) || containsPath(full, a.configPath) {
			return problem(400, "인증 설정 폴더를 포함하는 경로는 공유할 수 없습니다.")
		}
		root, err := os.OpenRoot(full)
		if err != nil {
			return err
		}
		newRoot = root
		next.SharedRoot = full
		defer func() {
			if a.root != newRoot {
				newRoot.Close()
			}
		}()
	}
	if body.Password != nil {
		if n := len([]rune(*body.Password)); n < 4 || n > 128 {
			return problem(400, "비밀번호는 4~128자로 입력하세요.")
		}
		next.Salt = randomHex(16)
		next.PasswordHash = derive(*body.Password, next.Salt)
		next.Key = randomHex(32)
		next.Revoked = map[string]int64{}
	}
	if body.Port != nil {
		if *body.Port < 1 || *body.Port > 65535 {
			return problem(400, "포트는 1~65535 사이로 입력하세요.")
		}
		next.Port = *body.Port
	}
	if body.AutoStart != nil {
		if err := setStartup(*body.AutoStart); err != nil {
			return problem(500, "자동 시작 설정 실패: "+err.Error())
		}
		next.AutoStart = *body.AutoStart
	}
	old := a.config
	next.NeedsSetup = false
	a.config = next
	if err := a.saveConfig(); err != nil {
		a.config = old
		if body.AutoStart != nil {
			_ = setStartup(old.AutoStart)
		}
		return err
	}
	if a.root != newRoot {
		a.root.Close()
		a.root = newRoot
	}
	if body.Password != nil {
		setCookie(w, a.token())
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
func cleanPath(relative string) (string, error) {
	if strings.ContainsAny(relative, "\\\x00:") || strings.HasPrefix(relative, "/") {
		return "", problem(403, "공유 폴더 밖에는 접근할 수 없습니다.")
	}
	if relative == "" {
		return ".", nil
	}
	for _, p := range strings.Split(relative, "/") {
		if p == "" || p == "." || p == ".." || strings.HasSuffix(p, ".") || strings.HasSuffix(p, " ") {
			return "", problem(403, "잘못된 경로입니다.")
		}
	}
	return relative, nil
}
func (a *App) safe(relative string, missing bool) (string, error) {
	p, err := cleanPath(relative)
	if err != nil {
		return "", err
	}
	if p == "." {
		return p, nil
	}
	parts := strings.Split(p, "/")
	for i := range parts {
		name := strings.Join(parts[:i+1], "/")
		stat, e := a.root.Lstat(name)
		if e != nil {
			if missing && i == len(parts)-1 && os.IsNotExist(e) {
				return p, nil
			}
			return "", e
		}
		if stat.Mode()&os.ModeSymlink != 0 {
			return "", problem(403, "심볼릭 링크에는 접근할 수 없습니다.")
		}
		if i < len(parts)-1 && !stat.IsDir() {
			return "", problem(400, "상위 경로가 폴더가 아닙니다.")
		}
	}
	return p, nil
}
func validName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 220 || strings.ContainsAny(name, "<>:\"/\\|?*\x00") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return problem(400, "올바른 이름을 입력하세요. (UTF-8 220바이트 이내)")
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return problem(400, "이름에 제어 문자를 사용할 수 없습니다.")
		}
	}
	base := strings.ToLower(strings.Split(name, ".")[0])
	reserved := regexp.MustCompile(`^(con|prn|aux|nul|com[1-9]|lpt[1-9])$`)
	if reserved.MatchString(base) {
		return problem(400, "예약된 파일 이름입니다.")
	}
	return nil
}
func (a *App) entries(w http.ResponseWriter, r *http.Request) error {
	relative := r.URL.Query().Get("path")
	p, err := a.safe(relative, false)
	if err != nil {
		return err
	}
	dir, err := a.root.Open(p)
	if err != nil {
		return err
	}
	defer dir.Close()
	items, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	entries := []map[string]any{}
	for _, item := range items {
		if item.Type()&os.ModeSymlink != 0 {
			continue
		}
		stat, e := item.Info()
		if e != nil || (!stat.IsDir() && !stat.Mode().IsRegular()) {
			continue
		}
		entries = append(entries, map[string]any{"name": item.Name(), "path": path.Join(relative, item.Name()), "directory": stat.IsDir(), "size": stat.Size(), "modified": stat.ModTime().UnixMilli()})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i]["directory"] != entries[j]["directory"] {
			return entries[i]["directory"].(bool)
		}
		return strings.ToLower(entries[i]["name"].(string)) < strings.ToLower(entries[j]["name"].(string))
	})
	reply(w, 200, map[string]any{"path": relative, "entries": entries})
	return nil
}
func (a *App) treeSafe(p string) error {
	stat, err := a.root.Lstat(p)
	if err != nil {
		return err
	}
	if stat.Mode()&os.ModeSymlink != 0 || !stat.IsDir() && !stat.Mode().IsRegular() {
		return problem(403, "링크 또는 특수 파일이 포함되어 있습니다.")
	}
	if stat.IsDir() {
		dir, e := a.root.Open(p)
		if e != nil {
			return e
		}
		items, e := dir.ReadDir(-1)
		dir.Close()
		if e != nil {
			return e
		}
		for _, item := range items {
			if err = a.treeSafe(path.Join(p, item.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
func (a *App) copyTree(source, dest string) error {
	stat, err := a.root.Lstat(source)
	if err != nil {
		return err
	}
	if stat.Mode()&os.ModeSymlink != 0 {
		return problem(403, "링크는 복사할 수 없습니다.")
	}
	if stat.IsDir() {
		if err = a.root.Mkdir(dest, 0755); err != nil {
			return err
		}
		dir, e := a.root.Open(source)
		if e != nil {
			return e
		}
		items, e := dir.ReadDir(-1)
		dir.Close()
		if e != nil {
			return e
		}
		for _, item := range items {
			if err = a.copyTree(path.Join(source, item.Name()), path.Join(dest, item.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if !stat.Mode().IsRegular() {
		return problem(403, "일반 파일만 복사할 수 있습니다.")
	}
	in, err := a.root.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := a.root.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, err = io.CopyBuffer(out, in, make([]byte, 256<<10))
	if e := out.Close(); err == nil {
		err = e
	}
	return err
}
func (a *App) operation(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Action      string `json:"action"`
		Path        string `json:"path"`
		Parent      string `json:"parent"`
		Name        string `json:"name"`
		Destination string `json:"destination"`
	}
	if err := decode(w, r, &b); err != nil {
		return err
	}
	if b.Action == "mkdir" {
		if err := validName(b.Name); err != nil {
			return err
		}
		parent, err := a.safe(b.Parent, false)
		if err != nil {
			return err
		}
		if err = a.root.Mkdir(path.Join(parent, b.Name), 0755); err != nil {
			return err
		}
		reply(w, 200, map[string]bool{"ok": true})
		return nil
	}
	if b.Path == "" {
		return problem(403, "공유 폴더 자체는 변경할 수 없습니다.")
	}
	source, err := a.safe(b.Path, false)
	if err != nil {
		return err
	}
	if err = a.treeSafe(source); err != nil {
		return err
	}
	if b.Action == "delete" {
		err = a.root.RemoveAll(source)
	} else {
		dest := ""
		switch b.Action {
		case "rename":
			if err = validName(b.Name); err != nil {
				return err
			}
			dest = path.Join(path.Dir(source), b.Name)
		case "copy", "move":
			parent, e := a.safe(b.Destination, false)
			if e != nil {
				return e
			}
			stat, e := a.root.Stat(parent)
			if e != nil {
				return e
			}
			if !stat.IsDir() {
				return problem(400, "대상 폴더가 아닙니다.")
			}
			dest = path.Join(parent, path.Base(source))
		default:
			return problem(400, "지원하지 않는 작업입니다.")
		}
		compareSource, compareDest := source, dest
		caseRename := b.Action == "rename" && source != dest && strings.EqualFold(source, dest)
		if b.Action == "rename" && source == dest {
			reply(w, 200, map[string]bool{"ok": true})
			return nil
		}
		if runtime.GOOS == "windows" {
			compareSource = strings.ToLower(source)
			compareDest = strings.ToLower(dest)
		}
		if (compareDest == compareSource && !caseRename) || strings.HasPrefix(compareDest, compareSource+"/") {
			return problem(409, "자기 자신 또는 하위 폴더로 작업할 수 없습니다.")
		}
		if target, e := a.root.Lstat(dest); e == nil {
			original, statErr := a.root.Lstat(source)
			if !caseRename || statErr != nil || !os.SameFile(original, target) {
				return problem(409, "같은 이름의 항목이 있습니다.")
			}
			// A distinct case-sensitive directory entry is still a collision, even for hard links.
			dir, readErr := a.root.Open(path.Dir(dest))
			if readErr != nil {
				return readErr
			}
			items, readErr := dir.ReadDir(-1)
			dir.Close()
			if readErr != nil {
				return readErr
			}
			for _, item := range items {
				if item.Name() == path.Base(dest) {
					return problem(409, "같은 이름의 항목이 있습니다.")
				}
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		if b.Action == "copy" {
			err = a.copyTree(source, dest)
			if err != nil {
				a.root.RemoveAll(dest)
			}
		} else {
			for attempt := 0; attempt < 6; attempt++ {
				err = a.root.Rename(source, dest)
				if err == nil || !fileIsBusy(err) {
					break
				}
				time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
			}
			if fileIsBusy(err) {
				return problem(423, "다른 프로그램이 파일을 사용 중입니다. 재생·다운로드 또는 파일을 연 프로그램을 닫고 다시 시도하세요.")
			}
		}
	}
	if err != nil {
		return err
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}

var mediaTypes = map[string]string{".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp", ".heic": "image/heic", ".mp4": "video/mp4", ".mov": "video/quicktime", ".m4v": "video/mp4", ".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".wav": "audio/wav", ".ogg": "audio/ogg"}

func attachment(w http.ResponseWriter, name string, inline bool) {
	mode := "attachment"
	if inline {
		mode = "inline"
	}
	w.Header().Set("Content-Disposition", mode+`; filename="download"; filename*=UTF-8''`+strings.ReplaceAll(url.QueryEscape(name), "+", "%20"))
}
func (a *App) content(w http.ResponseWriter, r *http.Request) error {
	p, err := a.safe(r.URL.Query().Get("path"), false)
	if err != nil {
		return err
	}
	file, err := a.root.Open(p)
	if err != nil {
		return err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() {
		return problem(400, "폴더는 ZIP 다운로드를 사용하세요.")
	}
	kind := mediaTypes[strings.ToLower(path.Ext(p))]
	inline := r.URL.Query().Get("preview") == "1" && kind != ""
	if !inline {
		kind = "application/octet-stream"
	}
	w.Header().Set("Content-Type", kind)
	attachment(w, path.Base(p), inline)
	if strings.Contains(r.Header.Get("Range"), ",") || r.Header.Get("Range") == "bytes=-0" {
		return problem(416, "한 번에 하나의 범위만 요청할 수 있습니다.")
	}
	http.ServeContent(w, r, path.Base(p), stat.ModTime(), file)
	return nil
}
func (a *App) zipFolder(w http.ResponseWriter, r *http.Request) error {
	p, err := a.safe(r.URL.Query().Get("path"), false)
	if err != nil {
		return err
	}
	stat, err := a.root.Stat(p)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return problem(400, "폴더만 ZIP으로 받을 수 있습니다.")
	}
	if err = a.treeSafe(p); err != nil {
		return err
	}
	name := path.Base(p)
	if p == "." {
		name = filepath.Base(a.config.SharedRoot)
	}
	w.Header().Set("Content-Type", "application/zip")
	attachment(w, name+".zip", false)
	z := zip.NewWriter(w)
	var walk func(string, string) error
	walk = func(src, entry string) error {
		f, e := a.root.Open(src)
		if e != nil {
			return e
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil {
			return e
		}
		header, e := zip.FileInfoHeader(st)
		if e != nil {
			return e
		}
		header.Name = entry
		header.Method = zip.Store
		if st.IsDir() {
			header.Name += "/"
		}
		writer, e := z.CreateHeader(header)
		if e != nil {
			return e
		}
		if st.IsDir() {
			items, e := f.ReadDir(-1)
			if e != nil {
				return e
			}
			for _, item := range items {
				if e = walk(path.Join(src, item.Name()), path.Join(entry, item.Name())); e != nil {
					return e
				}
			}
			return nil
		}
		_, e = io.Copy(writer, f)
		return e
	}
	if err = walk(p, name); err != nil {
		log.Printf("ZIP stream interrupted: %v", err)
		panic(http.ErrAbortHandler)
	}
	if err = z.Close(); err != nil {
		panic(http.ErrAbortHandler)
	}
	return nil
}
func (a *App) thumbnail(w http.ResponseWriter, r *http.Request) error {
	p, err := a.safe(r.URL.Query().Get("path"), false)
	if err != nil {
		return err
	}
	ext := strings.ToLower(path.Ext(p))
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" {
		return problem(415, "썸네일 미지원 형식입니다.")
	}
	select {
	case a.thumbnails <- struct{}{}:
		defer func() { <-a.thumbnails }()
	default:
		return problem(429, "썸네일 생성 중입니다.")
	}
	f, err := a.root.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if stat.Size() > 20<<20 {
		return problem(413, "미리보기를 생략한 큰 이미지입니다.")
	}
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return problem(415, "이미지를 읽을 수 없습니다.")
	}
	if int64(cfg.Width)*int64(cfg.Height) > 8000000 || cfg.Width <= 0 || cfg.Height <= 0 {
		return problem(413, "큰 이미지는 열기를 사용하세요.")
	}
	f.Seek(0, 0)
	src, _, err := image.Decode(f)
	if err != nil {
		return err
	}
	thumb := image.NewRGBA(image.Rect(0, 0, 80, 80))
	b := src.Bounds()
	for y := 0; y < 80; y++ {
		for x := 0; x < 80; x++ {
			thumb.Set(x, y, src.At(b.Min.X+x*b.Dx()/80, b.Min.Y+y*b.Dy()/80))
		}
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "private, max-age=120")
	return jpeg.Encode(w, thumb, &jpeg.Options{Quality: 75})
}
func (a *App) uploadDir(id string) string { return filepath.Join(a.data, "uploads", id) }
func (a *App) readUpload(id string) (Upload, error) {
	var u Upload
	b, err := os.ReadFile(filepath.Join(a.uploadDir(id), "meta.json"))
	if err == nil {
		err = json.Unmarshal(b, &u)
	}
	return u, err
}
func (a *App) saveUpload(u Upload) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	p := filepath.Join(a.uploadDir(u.ID), "meta.json")
	if err = os.WriteFile(p+".tmp", b, 0600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}
func (a *App) beginUpload(w http.ResponseWriter, r *http.Request) error {
	var u Upload
	if err := decode(w, r, &u); err != nil {
		return err
	}
	if err := validName(u.Name); err != nil {
		return err
	}
	if u.Size < 0 || u.Size > maxSize || !fingerprintPattern.MatchString(u.Fingerprint) {
		return problem(400, "파일 크기 또는 식별자가 잘못되었습니다.")
	}
	target, err := a.safe(u.Target, false)
	if err != nil {
		return err
	}
	st, err := a.root.Stat(target)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return problem(400, "업로드 대상이 폴더가 아닙니다.")
	}
	a.uploads.Lock()
	defer a.uploads.Unlock()
	entries, err := os.ReadDir(filepath.Join(a.data, "uploads"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !idPattern.MatchString(entry.Name()) {
			continue
		}
		old, e := a.readUpload(entry.Name())
		if e != nil || old.Complete {
			continue
		}
		if old.Root == a.config.SharedRoot && old.Target == u.Target && old.Name == u.Name && old.Size == u.Size && old.Fingerprint == u.Fingerprint {
			lock, _ := a.uploadLocks.LoadOrStore(old.ID, &sync.Mutex{})
			mu := lock.(*sync.Mutex)
			mu.Lock()
			st, e := os.Stat(filepath.Join(a.uploadDir(old.ID), "body"))
			mu.Unlock()
			if e != nil {
				return e
			}
			old.Offset = st.Size()
			reply(w, 200, old)
			return nil
		}
	}
	if diskFree(a.data) < u.Size+chunkSize || diskFree(a.config.SharedRoot) < u.Size+chunkSize {
		return problem(507, "저장 공간이 부족합니다.")
	}
	u.ID = randomHex(16)
	u.Root = a.config.SharedRoot
	u.Created = time.Now().UnixMilli()
	u.Path = ""
	u.Complete = false
	u.Offset = 0
	if err = os.Mkdir(a.uploadDir(u.ID), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(a.uploadDir(u.ID), "body"), nil, 0600); err != nil {
		return err
	}
	if err = a.saveUpload(u); err != nil {
		return err
	}
	reply(w, 201, u)
	return nil
}
func (a *App) upload(w http.ResponseWriter, r *http.Request) error {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/uploads/"), "/")
	id := parts[0]
	if !idPattern.MatchString(id) || len(parts) > 2 {
		return problem(404, "전송을 찾을 수 없습니다.")
	}
	complete := len(parts) == 2 && parts[1] == "complete"
	if len(parts) == 2 && !complete {
		return problem(404, "잘못된 요청입니다.")
	}
	lock, _ := a.uploadLocks.LoadOrStore(id, &sync.Mutex{})
	mu := lock.(*sync.Mutex)
	if !mu.TryLock() {
		return problem(409, "같은 파일을 전송 중입니다.")
	}
	defer mu.Unlock()
	u, err := a.readUpload(id)
	if err != nil {
		return err
	}
	if u.Root != a.config.SharedRoot {
		return problem(409, "공유 폴더가 변경되었습니다. 원래 폴더에서 이어 올리세요.")
	}
	if u.Complete {
		if (complete && r.Method == "POST") || (!complete && r.Method == "GET") {
			reply(w, 200, u)
			return nil
		}
		return problem(409, "이미 완료된 전송입니다.")
	}
	body := filepath.Join(a.uploadDir(id), "body")
	st, err := os.Stat(body)
	if err != nil {
		return err
	}
	u.Offset = st.Size()
	switch {
	case r.Method == "GET" && !complete:
		reply(w, 200, u)
		return nil
	case r.Method == "DELETE" && !complete:
		if err = os.RemoveAll(a.uploadDir(id)); err != nil {
			return err
		}
		reply(w, 200, map[string]bool{"ok": true})
		return nil
	case r.Method == "PATCH" && !complete:
		offset, e := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
		if e != nil || offset != u.Offset {
			return problem(409, "전송 위치가 다릅니다. 다시 이어 올리세요.")
		}
		length := r.ContentLength
		if length <= 0 || length > chunkSize || length > u.Size-offset {
			return problem(413, "잘못된 조각 크기입니다.")
		}
		if diskFree(a.data) < length+1<<20 {
			return problem(507, "저장 공간이 부족합니다.")
		}
		file, e := os.OpenFile(body, os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer file.Close()
		if _, e = file.Seek(offset, io.SeekStart); e != nil {
			return e
		}
		n, e := io.CopyN(file, r.Body, length)
		if e != nil || n != length {
			file.Truncate(offset)
			return problem(400, "전송이 중단되었습니다. 이어 올리세요.")
		}
		if e = file.Sync(); e != nil {
			file.Truncate(offset)
			return e
		}
		reply(w, 200, map[string]int64{"offset": offset + n})
		return nil
	case r.Method == "POST" && complete:
		if u.Offset != u.Size {
			return problem(409, "아직 전송이 완료되지 않았습니다.")
		}
		parent, e := a.safe(u.Target, false)
		if e != nil {
			return e
		}
		name := u.Name
		ext := path.Ext(name)
		base := strings.TrimSuffix(name, ext)
		for i := 0; i < 10000; i++ {
			if i > 0 {
				name = fmt.Sprintf("%s (%d)%s", base, i, ext)
			}
			dest := path.Join(parent, name)
			out, e := a.root.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if errors.Is(e, fs.ErrExist) {
				continue
			}
			if e != nil {
				return e
			}
			in, e := os.Open(body)
			if e != nil {
				out.Close()
				a.root.Remove(dest)
				return e
			}
			_, e = io.Copy(out, in)
			in.Close()
			if e == nil {
				e = out.Sync()
			}
			closeErr := out.Close()
			if e == nil {
				e = closeErr
			}
			if e != nil {
				a.root.Remove(dest)
				return e
			}
			u.Path = dest
			u.Name = name
			u.Complete = true
			if e = a.saveUpload(u); e != nil {
				a.root.Remove(dest)
				return e
			}
			os.Remove(body)
			reply(w, 200, u)
			return nil
		}
		return problem(409, "같은 이름의 파일이 너무 많습니다.")
	}
	return problem(405, "지원하지 않는 요청입니다.")
}
func main() {
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	base := filepath.Dir(exe)
	data := os.Getenv("FILESHARE_DATA")
	if data == "" {
		data = filepath.Join(base, "data")
		if os.Getenv("FILESHARE_CONFIG") == "" {
			os.Setenv("FILESHARE_CONFIG", filepath.Join(base, "FileShare.ini"))
		}
	}
	a, err := newApp(data, os.Getenv("FILESHARE_ROOT"), os.Getenv("FILESHARE_PASSWORD"))
	if err != nil {
		showStartupError(err.Error())
		return
	}
	defer func() { a.root.Close() }()
	if a.config.AutoStart && os.Getenv("FILESHARE_NO_TRAY") != "1" {
		if err := setStartup(true); err != nil {
			log.Printf("Auto-start registration: %v", err)
		}
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = strconv.Itoa(a.config.Port)
	}
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		if os.Getenv("FILESHARE_NO_BROWSER") != "1" {
			if saved, e := os.ReadFile(filepath.Join(a.data, "desktop-url.txt")); e == nil {
				address := strings.TrimSpace(string(saved))
				prefix := "http://localhost:" + port + "/#desktop="
				if strings.HasPrefix(address, prefix) && fingerprintPattern.MatchString(strings.TrimPrefix(address, prefix)) {
					body := strings.NewReader(`{"key":"` + strings.TrimPrefix(address, prefix) + `"}`)
					req, _ := http.NewRequest("POST", "http://localhost:"+port+"/api/desktop-session", body)
					req.Header.Set("X-FileShare", "1")
					client := http.Client{Timeout: 2 * time.Second}
					res, e := client.Do(req)
					if e == nil {
						res.Body.Close()
						if res.StatusCode == http.StatusOK {
							openDesktop(address)
							return
						}
					}
				}
			}
		}
		showStartupError(err.Error())
		return
	}
	port = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	desktopURL := "http://localhost:" + port + "/#desktop=" + a.desktopKey
	if err := os.WriteFile(filepath.Join(a.data, "desktop-url.txt"), []byte(desktopURL), 0600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nFileShare v0.3.0 | Go native server\n\nPC: http://localhost:%s\n", port)
	interfaces, _ := net.InterfaceAddrs()
	for _, addr := range interfaces {
		ip, _, e := net.ParseCIDR(addr.String())
		if e == nil && ip.To4() != nil && !ip.IsLoopback() {
			fmt.Printf("Phone: http://%s:%s\n", ip.String(), port)
		}
	}
	if a.initial != "" {
		fmt.Printf("Initial password: %s\n", a.initial)
	} else {
		fmt.Println("Password: use your saved password")
	}
	fmt.Printf("Shared folder: %s\nPrivate data: %s\nKeep this window open. Ctrl+C to stop.\nTrusted Wi-Fi only; HTTP is not encrypted.\nREADY http://127.0.0.1:%s\n", a.config.SharedRoot, a.data, port)
	if os.Getenv("FILESHARE_NO_BROWSER") != "1" && a.config.NeedsSetup {
		openDesktop(desktopURL)
	}
	server := &http.Server{Handler: a, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
	if runtime.GOOS == "windows" && os.Getenv("FILESHARE_NO_TRAY") != "1" {
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				showStartupError(err.Error())
			}
		}()
		if err := runTray(func() { openDesktop(desktopURL) }, func() {
			a.filesystem.RLock()
			folder := a.config.SharedRoot
			a.filesystem.RUnlock()
			exec.Command("explorer.exe", folder).Start()
		}, func() { server.Close() }); err != nil {
			showStartupError(err.Error())
		}
		return
	}
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		showStartupError(err.Error())
	}
}

func openDesktop(address string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", address)
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", address)
	}
	if cmd != nil {
		if err := cmd.Start(); err == nil {
			go cmd.Wait()
		}
	}
}
