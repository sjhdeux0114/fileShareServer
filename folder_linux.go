package main

import "context"

func chooseFolder(context.Context) (string, error) {
	return "", problem(400, "이 환경에서는 공유 폴더의 전체 경로를 입력하세요.")
}
