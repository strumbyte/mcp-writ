package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

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

// lifetimeBoundarySatisfiable probes the launcher's ability to arm the
// kernel-enforced descendant-lifetime boundary `sandbox
// require_lifetime_boundary` demands: create a private cgroup under the
// v2 root and migrate a member into it (which also requires write
// access on the common ancestor's cgroup.procs). GitHub-hosted runners
// expose the hierarchy but withhold both permissions — false there
// means the fixture policy must declare the documented waiver rather
// than let every supervised launch be refused.
func lifetimeBoundarySatisfiable() bool {
	const cgroupRoot = "/sys/fs/cgroup"
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return false
	}
	dir := filepath.Join(cgroupRoot, fmt.Sprintf("mcp-writ-boundary-probe-%d", os.Getpid()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		return false
	}
	defer os.Remove(dir)
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		return false
	}
	defer func() {
		child.Process.Kill()
		child.Wait()
	}()
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"),
		[]byte(strconv.Itoa(child.Process.Pid)), 0o644) == nil
}
