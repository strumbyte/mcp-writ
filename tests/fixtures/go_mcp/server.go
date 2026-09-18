package main

import (
	"context"
	"fmt"
	"runtime"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const fixtureName = "go-runtime-fixture"

type Echo struct {
	Message string `json:"message" jsonschema:"Text to return, up to 4096 bytes"`
}

type RuntimeInfo struct {
	GoVersion string     `json:"goVersion"`
	OS        string     `json:"os"`
	Arch      string     `json:"arch"`
	Linux     *LinuxInfo `json:"linux,omitempty"`
}

// LinuxInfo contains direct syscall observations, not inferred sandbox status.
type LinuxInfo struct {
	ThreadID   int    `json:"threadId"`
	Seccomp    int    `json:"seccomp"`
	NoNewPrivs int    `json:"noNewPrivs"`
	Error      string `json:"error,omitempty"`
}

func stdioTransport() *mcp.StdioTransport {
	return &mcp.StdioTransport{MaxLineLength: 64 * 1024}
}

func newServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: fixtureName, Version: "1.0.0"}, nil)
	closedWorld := false
	annotation := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld}
	echo := func(_ context.Context, _ *mcp.CallToolRequest, in Echo) (*mcp.CallToolResult, Echo, error) {
		if len(in.Message) > 4096 {
			return nil, Echo{}, fmt.Errorf("message must be at most 4096 bytes")
		}
		return nil, in, nil
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Return the supplied text", Annotations: annotation}, echo)
	// This harmless tool succeeds directly and is denied by the probe's policy.
	mcp.AddTool(s, &mcp.Tool{Name: "blocked_echo", Description: "Return text for an allowlist test", Annotations: annotation}, echo)
	mcp.AddTool(s, &mcp.Tool{Name: "runtime_info", Description: "Report the Go runtime and process status", Annotations: annotation},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, RuntimeInfo, error) {
			return nil, RuntimeInfo{runtime.Version(), runtime.GOOS, runtime.GOARCH, linuxInfo()}, nil
		})
	// Serialize stress calls so simultaneous clients cannot multiply the resource cap.
	stressSlot := make(chan struct{}, 1)
	mcp.AddTool(s, &mcp.Tool{Name: "runtime_stress", Description: "Run a bounded thread, stack, allocation and GC test", Annotations: annotation},
		func(ctx context.Context, _ *mcp.CallToolRequest, in StressInput) (*mcp.CallToolResult, StressOutput, error) {
			select {
			case stressSlot <- struct{}{}:
				defer func() { <-stressSlot }()
			case <-ctx.Done():
				return nil, StressOutput{}, ctx.Err()
			}
			out, err := stress(ctx, in)
			return nil, out, err
		})
	return s
}
