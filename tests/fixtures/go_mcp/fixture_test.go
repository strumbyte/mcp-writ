package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPVersions(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			ct, st := mcp.NewInMemoryTransports()
			ss, err := newServer().Connect(ctx, st, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ss.Close()
			client := mcp.NewClient(&mcp.Implementation{Name: "fixture-test", Version: "1"}, nil)
			cs, err := client.Connect(ctx, ct, &mcp.ClientSessionOptions{ProtocolVersion: version})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err = checkSession(ctx, cs, false, version, &output)
			closeErr := cs.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("%s\ncheck: %v; close: %v", &output, err, closeErr)
			}
		})
	}
}

func TestStressBoundsAndCancellation(t *testing.T) {
	for _, input := range []StressInput{{0, 1, 1}, {17, 1, 1}, {1, 0, 1}, {1, 33, 1}, {1, 1, 0}, {1, 1, 257}} {
		if _, err := stress(context.Background(), input); err == nil {
			t.Errorf("accepted invalid input %+v", input)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := stress(ctx, StressInput{1, 1, 1}); err != context.Canceled {
		t.Fatalf("canceled stress: %v", err)
	}
}

func TestGuardCannotInheritBypass(t *testing.T) {
	env := withoutSandboxBypass([]string{"PATH=somewhere", "MCP_WRIT_SKIP_SANDBOX=1", "mcp_writ_skip_sandbox=true", "OTHER=value"})
	if strings.Join(env, ";") != "PATH=somewhere;OTHER=value" {
		t.Fatalf("unexpected environment: %v", env)
	}
}
