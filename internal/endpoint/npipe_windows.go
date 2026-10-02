//go:build windows

package endpoint

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
)

func normalizePipePath(value string, listener bool) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "/", `\`))
	if value == "" {
		return "", fmt.Errorf("pipe name is required")
	}
	if strings.HasPrefix(value, `\\`) {
		if !strings.Contains(strings.ToLower(value), `\pipe\`) {
			return "", fmt.Errorf("full named-pipe path must include \\pipe\\")
		}
		return value, nil
	}

	server, pipeName := ".", value
	if !listener {
		if split := strings.LastIndex(value, ":"); split >= 0 {
			if split > 0 {
				server = value[:split]
			}
			pipeName = value[split+1:]
		}
	}
	if pipeName == "" || strings.ContainsAny(pipeName, `\:`) {
		return "", fmt.Errorf("invalid named-pipe name %q", pipeName)
	}
	if listener {
		server = "."
	}
	return `\\` + server + `\pipe\` + pipeName, nil
}

func dialNamedPipe(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}

func listenNamedPipe(path string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{MessageMode: true})
}
