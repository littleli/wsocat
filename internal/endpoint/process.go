package endpoint

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

type processStream struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	writeOnce sync.Once
	readOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

func startProcess(ctx context.Context, executable string, args []string, stderr io.Writer) (*processStream, error) {
	return newProcessStream(exec.CommandContext(ctx, executable, args...), stderr)
}

func newProcessStream(cmd *exec.Cmd, stderr io.Writer) (*processStream, error) {
	if stderr == nil {
		stderr = io.Discard
	}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open child stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open child stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("start %q: %w", cmd.Path, err)
	}
	return &processStream{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

func (s *processStream) Read(p []byte) (int, error)  { return s.stdout.Read(p) }
func (s *processStream) Write(p []byte) (int, error) { return s.stdin.Write(p) }

func (s *processStream) CloseWrite() error {
	var err error
	s.writeOnce.Do(func() { err = s.stdin.Close() })
	return err
}

func (s *processStream) CloseRead() error {
	var err error
	s.readOnce.Do(func() { err = s.stdout.Close() })
	return err
}

func (s *processStream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.CloseWrite()
		if s.cmd.Process != nil && s.cmd.ProcessState == nil {
			_ = s.cmd.Process.Kill()
		}
		_ = s.CloseRead()
		if err := s.cmd.Wait(); err != nil && s.closeErr == nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}

func findWSL() (string, error) {
	if root := os.Getenv("SystemRoot"); root != "" {
		candidate := filepath.Join(root, "System32", "wsl.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if candidate, err := exec.LookPath("wsl.exe"); err == nil {
		return candidate, nil
	}
	return "", fmt.Errorf("WSL address used, but wsl.exe was not found")
}
