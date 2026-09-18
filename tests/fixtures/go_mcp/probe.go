package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func probe(args []string) (probeErr error) {
	f := flag.NewFlagSet("probe", flag.ContinueOnError)
	guard := f.String("guard", "", "mcp-writ executable; omit to test the fixture directly")
	policy := f.String("policy", "", "exact policy to test; default: generate a fixture-only policy")
	protocol := f.String("protocol", "2025-11-25", "MCP version: 2025-11-25 or 2026-07-28")
	output := f.String("output", "target/go-runtime-results", "parent directory for a new results directory")
	limit := f.Duration("timeout", 30*time.Second, "deadline for the complete probe")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 || *limit <= 0 || (*protocol != "2025-11-25" && *protocol != "2026-07-28") {
		return fmt.Errorf("unexpected arguments, invalid protocol, or non-positive timeout")
	}
	if *policy != "" && *guard == "" {
		return fmt.Errorf("-policy requires -guard")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*output, 0755); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(*output, "probe-")
	if err != nil {
		return err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	fmt.Printf("Results: %s\n", dir)
	defer func() {
		report := struct {
			Passed   bool   `json:"passed"`
			Protocol string `json:"requestedProtocol"`
			Guard    string `json:"guard,omitempty"`
			Policy   string `json:"policy,omitempty"`
			Error    string `json:"error,omitempty"`
		}{Passed: probeErr == nil, Protocol: *protocol, Guard: *guard, Policy: *policy}
		if probeErr != nil {
			report.Error = probeErr.Error()
		}
		data, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "result.json"), append(data, '\n'), 0600)
		}
		if err != nil && probeErr == nil {
			probeErr = fmt.Errorf("save result: %w", err)
		}
	}()
	progress, err := os.Create(filepath.Join(dir, "checks.log"))
	if err != nil {
		return err
	}
	defer progress.Close()
	out := io.MultiWriter(os.Stdout, progress)
	stderr, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		return err
	}
	defer stderr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	guarded := *guard != ""
	if guarded {
		if *policy == "" {
			*policy = filepath.Join(dir, "policy.kdl")
			if err := os.WriteFile(*policy, []byte(fixturePolicy(filepath.Dir(exe))), 0600); err != nil {
				return err
			}
		}
		cmd = exec.CommandContext(ctx, *guard, "run", "--policy", *policy,
			"--audit-log", filepath.Join(dir, "audit.jsonl"), "--", exe)
		// A user's ambient bypass must never turn this into a false sandbox pass.
		cmd.Env = withoutSandboxBypass(os.Environ())
	}
	cmd.Stderr = io.MultiWriter(os.Stderr, stderr)
	client := mcp.NewClient(&mcp.Implementation{Name: "go-runtime-probe", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: time.Second},
		&mcp.ClientSessionOptions{ProtocolVersion: *protocol})
	if err != nil {
		return fmt.Errorf("FAIL connect: %w (stderr: %s)", err, filepath.Join(dir, "stderr.log"))
	}
	checkErr := checkSession(ctx, session, guarded, *protocol, out)
	closeErr := session.Close()
	if checkErr != nil {
		return checkErr
	}
	if closeErr != nil {
		return fmt.Errorf("FAIL shutdown: %w", closeErr)
	}
	fmt.Fprintln(out, "PASS shutdown; all requested checks passed")
	return nil
}

func withoutSandboxBypass(env []string) []string {
	clean := make([]string, 0, len(env))
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		if !strings.EqualFold(key, "MCP_WRIT_SKIP_SANDBOX") {
			clean = append(clean, item)
		}
	}
	return clean
}

func checkSession(ctx context.Context, s *mcp.ClientSession, guarded bool, protocol string, out io.Writer) error {
	init := s.InitializeResult()
	if init == nil || init.ServerInfo == nil || init.ServerInfo.Name != fixtureName {
		return fmt.Errorf("FAIL connect: unexpected server identity")
	}
	if init.ProtocolVersion != protocol {
		return fmt.Errorf("FAIL connect: requested protocol %s, negotiated %s", protocol, init.ProtocolVersion)
	}
	fmt.Fprintf(out, "PASS connect (protocol %s)\n", init.ProtocolVersion)
	tools, err := s.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("FAIL tools/list: %w", err)
	}
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	for _, name := range []string{"echo", "blocked_echo", "runtime_info", "runtime_stress"} {
		if !names[name] {
			return fmt.Errorf("FAIL tools/list: missing %s", name)
		}
	}
	fmt.Fprintln(out, "PASS tools/list")
	var info RuntimeInfo
	if err := call(ctx, s, "runtime_info", struct{}{}, &info); err != nil {
		return err
	}
	encoded, _ := json.Marshal(info)
	fmt.Fprintf(out, "Runtime: %s\n", encoded)
	if info.OS == "linux" {
		if info.Linux == nil || info.Linux.ThreadID <= 0 || info.Linux.Error != "" {
			return fmt.Errorf("FAIL Linux runtime syscalls: %s", encoded)
		}
		if guarded && (info.Linux.Seccomp != 2 || info.Linux.NoNewPrivs != 1) {
			return fmt.Errorf("FAIL Linux sandbox: expected seccomp=2 and noNewPrivs=1, got %s", encoded)
		}
	}
	if err := parallelEcho(ctx, s); err != nil {
		return err
	}
	fmt.Fprintln(out, "PASS 16 concurrent echo calls")
	input := StressInput{Workers: 8, Rounds: 8, AllocKiB: 64}
	var stressResult StressOutput
	if err := call(ctx, s, "runtime_stress", input, &stressResult); err != nil {
		return err
	}
	// Every 256 consecutive byte values sum to 32640, independent of the seed.
	expectedChecksum := uint64(8*8) * uint64((33*1024+64*1024)/256*32640)
	if stressResult.Workers != 8 || stressResult.Iterations != 64 || stressResult.AllocatedBytes != 4*1024*1024 || stressResult.GCCycles == 0 || stressResult.Checksum != expectedChecksum {
		return fmt.Errorf("FAIL runtime_stress: unexpected result %+v", stressResult)
	}
	fmt.Fprintf(out, "PASS runtime_stress (8 threads, 64 iterations, 4 MiB, %d GC cycles)\n", stressResult.GCCycles)
	invalid, err := s.CallTool(ctx, &mcp.CallToolParams{Name: "runtime_stress", Arguments: StressInput{Workers: 1000, Rounds: 1, AllocKiB: 1}})
	if err != nil || invalid == nil || !invalid.IsError {
		return fmt.Errorf("FAIL workload bounds: expected a tool error, got result=%+v err=%v", invalid, err)
	}
	fmt.Fprintln(out, "PASS workload bounds")
	if guarded {
		_, err := s.CallTool(ctx, &mcp.CallToolParams{Name: "blocked_echo", Arguments: Echo{Message: "denial sentinel"}})
		var rpcErr *jsonrpc.Error
		if !errors.As(err, &rpcErr) || rpcErr.Code != -32001 || !strings.Contains(rpcErr.Message, "Policy violation") {
			return fmt.Errorf("FAIL Auditor denial: expected policy error -32001, got %v", err)
		}
		fmt.Fprintln(out, "PASS Auditor denied blocked_echo (this is not an OS-denial test)")
		// Even the executable path granted to the process must not become an
		// allowed argument for these path-free tools. No file is opened here.
		binaryPath, err := os.Executable()
		if err != nil {
			return err
		}
		_, err = s.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: Echo{Message: binaryPath}})
		var pathErr *jsonrpc.Error
		if !errors.As(err, &pathErr) || pathErr.Code != -32001 || !strings.Contains(pathErr.Message, "not in tool fs allowed paths") {
			return fmt.Errorf("FAIL path-free contract: expected path argument denial, got %v", err)
		}
		fmt.Fprintln(out, "PASS Auditor denied bootstrap path as a tool argument")
	} else {
		var reply Echo
		if err := call(ctx, s, "blocked_echo", Echo{Message: "denial sentinel"}, &reply); err != nil {
			return err
		}
		if reply.Message != "denial sentinel" {
			return fmt.Errorf("FAIL direct blocked_echo response")
		}
	}
	var reply Echo
	if err := call(ctx, s, "echo", Echo{Message: "still alive"}, &reply); err != nil {
		return err
	}
	if reply.Message != "still alive" {
		return fmt.Errorf("FAIL post-stress echo")
	}
	fmt.Fprintln(out, "PASS post-stress liveness")
	return nil
}

func call(ctx context.Context, s *mcp.ClientSession, name string, input, output any) error {
	r, err := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: input})
	if err != nil {
		return fmt.Errorf("FAIL %s: %w", name, err)
	}
	if r == nil || r.IsError || r.StructuredContent == nil {
		return fmt.Errorf("FAIL %s: unsuccessful or missing structured result: %+v", name, r)
	}
	b, err := json.Marshal(r.StructuredContent)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, output); err != nil {
		return fmt.Errorf("FAIL %s: invalid structured result: %w", name, err)
	}
	return nil
}

func parallelEcho(ctx context.Context, s *mcp.ClientSession) error {
	var wg sync.WaitGroup
	errors := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			want := fmt.Sprintf("echo-%d", i)
			var got Echo
			if err := call(ctx, s, "echo", Echo{Message: want}, &got); err != nil {
				errors <- err
			} else if got.Message != want {
				errors <- fmt.Errorf("FAIL echo correlation: want %q, got %q", want, got.Message)
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		return err
	}
	return nil
}

// This is a diagnostic policy for this fixture, not a production Go profile.
// Runtime bootstrap access is separate from these path-free tool arguments.
// An incompatibility must stay observable, not be hidden by a sandbox bypass.
func fixturePolicy(binaryDir string) string {
	path, _ := json.Marshal(filepath.ToSlash(binaryDir))
	return fmt.Sprintf(`policy version=1
defaults {
    filesystem {
        allow %s mode="read"
    }
    network {
        deny host="*"
    }
    syscalls {
        allow "read" "write" "close" "openat" "fstat" "newfstatat" "fcntl"
        allow "mmap" "munmap" "mprotect" "madvise" "brk"
        allow "rt_sigaction" "rt_sigprocmask" "rt_sigreturn" "sigaltstack"
        allow "clone" "clone3" "futex" "getpid" "gettid" "tgkill"
        allow "sched_getaffinity" "sched_yield" "nanosleep" "clock_gettime"
        allow "epoll_create1" "epoll_ctl" "epoll_pwait" "epoll_wait" "eventfd2"
        allow "arch_prctl" "prctl" "prlimit64" "getrandom"
        allow "set_tid_address" "set_robust_list" "rseq"
        allow "execve" "exit" "exit_group"
    }
}
profile "pathless" {
    filesystem {
        allow none=#true
        require-path #false
    }
}
server "go-runtime-fixture" {
    tool "echo" profile="pathless" side_effect="read_only"
    tool "runtime_info" profile="pathless" side_effect="read_only"
    tool "runtime_stress" profile="pathless" side_effect="read_only"
    tool "blocked_echo" deny=#true
}
`, path)
}
