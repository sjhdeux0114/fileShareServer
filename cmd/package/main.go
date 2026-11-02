package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type entry struct {
	Name string
	Data []byte
	Mode int64
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(name string) []byte { b, e := os.ReadFile(name); must(e); return b }
func archive(filename, prefix string, entries []entry) {
	f, e := os.Create(filename)
	must(e)
	defer f.Close()
	if strings.HasSuffix(filename, ".zip") {
		z := zip.NewWriter(f)
		for _, item := range entries {
			h := &zip.FileHeader{Name: prefix + item.Name, Method: zip.Deflate}
			h.SetMode(os.FileMode(item.Mode))
			w, e := z.CreateHeader(h)
			must(e)
			_, e = w.Write(item.Data)
			must(e)
		}
		must(z.Close())
		return
	}
	g := gzip.NewWriter(f)
	t := tar.NewWriter(g)
	for _, item := range entries {
		must(t.WriteHeader(&tar.Header{Name: prefix + item.Name, Mode: item.Mode, Size: int64(len(item.Data))}))
		_, e = t.Write(item.Data)
		must(e)
	}
	must(t.Close())
	must(g.Close())
}
func main() {
	must(os.MkdirAll("release", 0755))
	must(os.MkdirAll(".cache/build", 0755))
	for _, target := range []struct{ OS, Arch, Label string }{{"windows", "amd64", "windows-x64"}, {"windows", "arm64", "windows-arm64"}, {"darwin", "arm64", "macos-arm64"}, {"darwin", "amd64", "macos-x64"}} {
		binary := "FileShare"
		launcher := "start-macos.command"
		extension := ".tar.gz"
		if target.OS == "windows" {
			binary += ".exe"
			launcher = ""
			extension = ".zip"
		}
		dest := filepath.Join(".cache/build", target.Label+"-"+binary)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", dest, ".")
		cmd.Env = append(os.Environ(), "GOOS="+target.OS, "GOARCH="+target.Arch, "CGO_ENABLED=0")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Println("Building", target.Label)
		must(cmd.Run())
		files := []entry{{binary, read(dest), 0755}, {"README.md", read("README.md"), 0644}, {"GO-LICENSE.txt", read(filepath.Join(runtime.GOROOT(), "LICENSE")), 0644}}
		if launcher != "" {
			files = append(files, entry{launcher, read(launcher), 0755})
		}
		if target.OS == "windows" {
			must(os.WriteFile(filepath.Join("release", "FileShare-0.1.0-"+target.Label+".exe"), read(dest), 0755))
		}
		for _, name := range []string{"VALIDATION.md", "large-file-test.json"} {
			b, e := os.ReadFile(filepath.Join("release", name))
			if e == nil {
				files = append(files, entry{"release/" + name, b, 0644})
			}
		}
		name := "FileShare-0.1.0-" + target.Label
		archive(filepath.Join("release", name+extension), name+"/", files)
	}
	var source []entry
	for _, name := range []string{"main.go", "main_test.go", "disk_windows.go", "disk_unix.go", "go.mod", "README.md", "package.json", "start-macos.command", "public", "test", "cmd", ".github", ".gitattributes", ".gitignore", "release/VALIDATION.md", "release/large-file-test.json"} {
		must(filepath.WalkDir(name, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				return nil
			}
			mode := int64(0644)
			if strings.HasSuffix(p, ".command") {
				mode = 0755
			}
			source = append(source, entry{filepath.ToSlash(p), read(p), mode})
			return nil
		}))
	}
	archive("release/FileShare-0.1.0-source.zip", "FileShare-0.1.0/", source)
	entries, e := os.ReadDir("release")
	must(e)
	var sums []string
	for _, item := range entries {
		if !strings.HasSuffix(item.Name(), ".zip") && !strings.HasSuffix(item.Name(), ".tar.gz") && !strings.HasSuffix(item.Name(), ".exe") {
			continue
		}
		f, e := os.Open(filepath.Join("release", item.Name()))
		must(e)
		h := sha256.New()
		_, e = io.Copy(h, f)
		f.Close()
		must(e)
		sums = append(sums, hex.EncodeToString(h.Sum(nil))+"  "+item.Name())
	}
	sort.Strings(sums)
	must(os.WriteFile("release/SHA256SUMS.txt", []byte(strings.Join(sums, "\n")+"\n"), 0644))
	fmt.Println("Packages and checksums ready.")
}
