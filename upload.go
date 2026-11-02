package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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
			if !mu.TryLock() {
				return problem(409, "같은 파일을 전송 중입니다. 잠시 후 다시 시도하세요.")
			}
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

// Refresh the deadline on every read: a slow but progressing upload is valid,
// while a vanished mobile connection must not hold the upload lock indefinitely.
type uploadReader struct {
	body       io.Reader
	controller *http.ResponseController
	idle       time.Duration
	progress   *activeUpload
}

type activeUpload struct {
	root     string
	start    int64
	received atomic.Int64
	storing  atomic.Bool
}

func (r uploadReader) Read(p []byte) (int, error) {
	if err := r.controller.SetReadDeadline(time.Now().Add(r.idle)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	n, err := r.body.Read(p)
	if r.progress != nil {
		r.progress.received.Add(int64(n))
	}
	return n, err
}

func (a *App) upload(w http.ResponseWriter, r *http.Request) error {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/uploads/"), "/")
	id := parts[0]
	if !idPattern.MatchString(id) || len(parts) > 2 {
		return problem(404, "전송을 찾을 수 없습니다.")
	}
	complete := len(parts) == 2 && parts[1] == "complete"
	chunkPost := len(parts) == 2 && parts[1] == "chunks" && r.Method == "POST"
	if len(parts) == 2 && parts[1] == "progress" && r.Method == "GET" {
		if value, ok := a.uploadProgress.Load(id); ok {
			p := value.(*activeUpload)
			if p.root != a.config.SharedRoot {
				return problem(409, "공유 폴더가 변경되었습니다.")
			}
			// Live received bytes are diagnostic, never an offset for resuming.
			reply(w, 200, map[string]any{"active": true, "received": p.start + p.received.Load(), "storing": p.storing.Load()})
		} else {
			lock, _ := a.uploadLocks.LoadOrStore(id, &sync.Mutex{})
			mu := lock.(*sync.Mutex)
			if !mu.TryLock() {
				return problem(409, "전송 상태를 갱신 중입니다.")
			}
			defer mu.Unlock()
			u, err := a.readUpload(id)
			if err != nil {
				return err
			}
			if u.Root != a.config.SharedRoot {
				return problem(409, "공유 폴더가 변경되었습니다.")
			}
			if u.Complete {
				u.Offset = u.Size
			} else {
				st, err := os.Stat(filepath.Join(a.uploadDir(id), "body"))
				if err != nil {
					return err
				}
				u.Offset = st.Size()
			}
			// Only the idle, locked snapshot is authoritative for acknowledgement.
			reply(w, 200, map[string]any{"active": false, "offset": u.Offset, "complete": u.Complete})
		}
		return nil
	}
	if len(parts) == 2 && !complete && !chunkPost {
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
	case (r.Method == "PATCH" && !complete) || chunkPost:
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
		progress := &activeUpload{root: u.Root, start: offset}
		a.uploadProgress.Store(id, progress)
		defer a.uploadProgress.Delete(id)
		receiveStarted := time.Now()
		file, e := os.OpenFile(body, os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer file.Close()
		if _, e = file.Seek(offset, io.SeekStart); e != nil {
			return e
		}
		controller := http.NewResponseController(w)
		n, e := io.CopyN(file, uploadReader{r.Body, controller, 15 * time.Second, progress}, length)
		if e != nil || n != length {
			// Do not reuse or drain an incomplete request after its read deadline.
			w.Header().Set("Connection", "close")
			if err := file.Truncate(offset); err != nil {
				return err
			}
			return problem(408, "전송이 중단되었습니다. 이어 올리세요.")
		}
		_ = controller.SetReadDeadline(time.Time{})
		receiveElapsed := time.Since(receiveStarted)
		progress.storing.Store(true)
		closeStarted := time.Now()
		// A temporary chunk is acknowledged after writing and closing, without
		// forcing a disk flush at every 2 MiB boundary. The completed destination
		// is still Sync'd before marking the upload complete below.
		if e = file.Close(); e != nil {
			if rollbackErr := os.Truncate(body, offset); rollbackErr != nil {
				return fmt.Errorf("close upload: %v; rollback: %w", e, rollbackErr)
			}
			return e
		}
		closeElapsed := time.Since(closeStarted)
		w.Header().Set("Server-Timing", fmt.Sprintf("receive;dur=%.3f, close;dur=%.3f", float64(receiveElapsed.Microseconds())/1000, float64(closeElapsed.Microseconds())/1000))
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
