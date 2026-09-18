package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func linuxInfo() *LinuxInfo {
	i := &LinuxInfo{ThreadID: unix.Gettid()}
	if i.ThreadID <= 0 {
		i.Error = fmt.Sprintf("gettid returned %d (check the seccomp syscall mapping)", i.ThreadID)
	}
	for _, query := range []struct {
		option uintptr
		dest   *int
	}{
		{unix.PR_GET_SECCOMP, &i.Seccomp},
		{unix.PR_GET_NO_NEW_PRIVS, &i.NoNewPrivs},
	} {
		value, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, query.option, 0, 0, 0, 0, 0)
		if errno != 0 {
			i.Error += fmt.Sprintf(" prctl(%d): %v", query.option, errno)
		} else {
			*query.dest = int(value)
		}
	}
	return i
}
