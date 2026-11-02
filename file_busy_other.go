//go:build !windows

package main

import (
	"errors"
	"syscall"
)

func fileIsBusy(err error) bool {
	return errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.ETXTBSY)
}
