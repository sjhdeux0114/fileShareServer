package main

import (
	"errors"
	"syscall"
)

func fileIsBusy(err error) bool {
	return errors.Is(err, syscall.Errno(32)) || errors.Is(err, syscall.Errno(33))
}
