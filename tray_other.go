//go:build !windows

package main

import "log"

func showStartupError(message string)             { log.Print(message) }
func runTray(settings, folder, stop func()) error { return nil }
