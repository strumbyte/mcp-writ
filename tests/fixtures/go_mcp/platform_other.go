//go:build !linux

package main

import "runtime"

func linuxInfo() *LinuxInfo { return nil }

// Windows arms the descendant-lifetime boundary through the Job Object;
// platforms without any kernel mechanism (macOS) must declare the
// documented waiver.
func lifetimeBoundarySatisfiable() bool { return runtime.GOOS == "windows" }
