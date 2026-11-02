package main

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func chooseFolder(parent context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "osascript", "-e", `try
POSIX path of (choose folder with prompt "FileShare: 공유할 폴더를 선택하세요")
on error number -128
return ""
end try`).Output()
	if err != nil {
		return "", problem(500, "폴더 선택 창을 열지 못했습니다. 경로를 직접 입력하세요.")
	}
	return strings.TrimSpace(string(out)), nil
}
