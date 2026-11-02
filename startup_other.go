//go:build !windows

package main

import "fmt"

func setStartup(enabled bool) error {
	if enabled {
		return fmt.Errorf("자동 시작은 Windows에서 지원합니다")
	}
	return nil
}
