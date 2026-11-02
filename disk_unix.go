//go:build darwin || linux

package main

import "syscall"

func diskFree(path string) int64 {
	var stat syscall.Statfs_t
	if syscall.Statfs(path, &stat) != nil {
		return 0
	}
	return int64(stat.Bavail) * int64(stat.Bsize)
}
