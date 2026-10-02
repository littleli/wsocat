//go:build windows

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage: wsocat.exe") {
		t.Fatalf("help output = %q, want usage", stdout.String())
	}
	if !strings.Contains(stdout.String(), "TLS") {
		t.Fatalf("help output = %q, want supported TLS address type", stdout.String())
	}
	if !strings.Contains(stdout.String(), "HVSOCK, HVSOCK-LISTEN") {
		t.Fatalf("help output = %q, want supported Hyper-V address types", stdout.String())
	}
	if !strings.Contains(stdout.String(), "HVSOCK-LISTEN, SP") {
		t.Fatalf("help output = %q, want supported serial address type", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	if got, want := strings.TrimSpace(stdout.String()), "wsocat dev"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunRequiresTwoAddresses(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no arguments"},
		{name: "one address", args: []string{"STDIO"}},
		{name: "too many arguments", args: []string{"STDIO", "TCP:localhost:80", "extra"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != 2 {
				t.Fatalf("run() exit code = %d, want 2", code)
			}
			if !strings.Contains(stderr.String(), "Usage: wsocat.exe") {
				t.Fatalf("stderr = %q, want usage", stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("unexpected stdout: %q", stdout.String())
			}
		})
	}
}

func TestRunRejectsInvalidAddressRole(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runContext(context.Background(), []string{"STDIO", "TCP-LISTEN:127.0.0.1:80"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runContext() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "only valid as address1") {
		t.Fatalf("stderr = %q, want address role error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}
