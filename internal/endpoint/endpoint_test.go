package endpoint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestParseEndpointForms(t *testing.T) {
	tests := []struct {
		input    string
		side     Side
		kind     Kind
		listener bool
	}{
		{"STDIO", Source, Stdio, false},
		{"TCP:127.0.0.1:80", Target, TCP, false},
		{"TCP::80", Target, TCP, false},
		{"TCP-LISTEN::0", Source, TCPListen, true},
		{"TCP-LISTEN:127.0.0.1:8000", Source, TCPListen, true},
		{"NPIPE:PipeDemo", Target, Npipe, false},
		{"NPIPE:RemoteServer:RemotePipe", Source, Npipe, false},
		{"NPIPE-LISTEN:fooPipe", Source, NpipeListen, true},
		{`EXEC:"C:\Program Files\tool.exe" --flag`, Source, Exec, false},
		{`WSL:'socat STDIO unix-connect:foo.sock',distribution=Ubuntu,user=root`, Target, WSL, false},
		{`UNIX:C:\Temp\wsocat.sock`, Target, Unix, false},
		{`UNIX-LISTEN:C:\Temp\wsocat.sock`, Source, UnixListen, true},
		{"TLS:api.example.com:443", Target, TLS, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Parse(tt.input, tt.side)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got.Kind() != tt.kind || got.IsListener() != tt.listener {
				t.Fatalf("Parse() = (%s, listener=%t), want (%s, listener=%t)", got.Kind(), got.IsListener(), tt.kind, tt.listener)
			}
		})
	}
}

func TestParseTLSOptions(t *testing.T) {
	spec, err := Parse(`TLS:127.0.0.1:443,servername=api.example.com,cafile="C:\certs\corp root.pem"`, Target)
	if err != nil {
		t.Fatal(err)
	}
	if spec.serverName != "api.example.com" {
		t.Errorf("TLS server name = %q, want api.example.com", spec.serverName)
	}
	if spec.caFile != `C:\certs\corp root.pem` {
		t.Errorf("TLS CA file = %q, want %q", spec.caFile, `C:\certs\corp root.pem`)
	}
	if spec.host != "127.0.0.1" || spec.port != 443 {
		t.Errorf("TLS server = %q:%d, want 127.0.0.1:443", spec.host, spec.port)
	}

	for _, tt := range []struct {
		address string
		want    string
	}{
		{"TLS:443", "requires a server host and port"},
		{"TLS::443", "requires a server host and port"},
		{"TLS:api.example.com:0", "port must be between 1"},
		{"TLS:api.example.com:443,verify=false", "not supported"},
		{"TLS:api.example.com:443,servername=", "cannot be empty"},
		{"TLS:api.example.com:443,cafile=", "cannot be empty"},
	} {
		t.Run(tt.address, func(t *testing.T) {
			if _, err := Parse(tt.address, Target); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse(%q) error = %v, want substring %q", tt.address, err, tt.want)
			}
		})
	}
}

func TestParseTCPAddressDetails(t *testing.T) {
	tests := []struct {
		input string
		host  string
		port  int
	}{
		{"TCP:localhost:80", "localhost", 80},
		{"TCP:127.0.0.1:443", "127.0.0.1", 443},
		{"TCP:[::1]:9000", "::1", 9000},
		{"TCP::80", "0.0.0.0", 80},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			spec, err := Parse(tt.input, Target)
			if err != nil {
				t.Fatal(err)
			}
			if spec.host != tt.host || spec.port != tt.port {
				t.Fatalf("TCP address = %q:%d, want %q:%d", spec.host, spec.port, tt.host, tt.port)
			}
		})
	}
	for _, input := range []string{"TCP:host", "TCP:host:80:90", "TCP:[::1]80", "TCP:host:nope"} {
		if _, err := Parse(input, Target); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", input)
		}
	}
}

func TestParseRejectsInvalidRolesAndDeferredEndpoints(t *testing.T) {
	tests := []struct {
		input string
		side  Side
		want  string
	}{
		{"TCP-LISTEN:8000", Target, "only valid as address1"},
		{"NPIPE-LISTEN:pipe", Target, "only valid as address1"},
		{"UNIX-LISTEN:pipe.sock", Target, "only valid as address1"},
		{"UNKNOWN:payload", Source, "unsupported address type"},
		{"STDIO:unexpected", Source, "does not take an address value"},
		{"TCP:localhost:0", Target, "port must be between 1"},
		{"TCP-LISTEN:localhost:65536", Source, "port must be between 0"},
		{"TCP:host:80,foo=bar", Target, "not supported"},
		{"UNIX:", Source, "requires a socket path"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := Parse(tt.input, tt.side)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidatePair(t *testing.T) {
	stdioSource, _ := Parse("STDIO", Source)
	stdioTarget, _ := Parse("STDIO", Target)
	if err := ValidatePair(stdioSource, stdioTarget); err == nil {
		t.Fatal("ValidatePair(STDIO, STDIO) succeeded, want error")
	}
	listener, _ := Parse("TCP-LISTEN:8000", Source)
	if err := ValidatePair(listener, stdioTarget); err != nil {
		t.Fatalf("ValidatePair(listener, STDIO) error = %v", err)
	}
	tlsTarget, _ := Parse("TLS:localhost:443", Target)
	if err := ValidatePair(listener, tlsTarget); err != nil {
		t.Fatalf("ValidatePair(TCP-LISTEN, TLS) error = %v", err)
	}
}

func TestStdioOpenUsesProvidedHandles(t *testing.T) {
	spec, err := Parse("STDIO", Source)
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	stream, err := spec.Open(context.Background(), strings.NewReader("stdin bytes"), &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	input, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(input) != "stdin bytes" {
		t.Fatalf("STDIO read %q, want stdin bytes", input)
	}
	if _, err := stream.Write([]byte("stdout bytes")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "stdout bytes" {
		t.Fatalf("STDIO wrote %q, want stdout bytes", stdout.String())
	}
}

func TestNormalizeNamedPipePaths(t *testing.T) {
	tests := []struct {
		value    string
		listener bool
		want     string
	}{
		{"PipeDemo", false, `\\.\pipe\PipeDemo`},
		{":fooPipe", false, `\\.\pipe\fooPipe`},
		{"RemoteServer:RemotePipe", false, `\\RemoteServer\pipe\RemotePipe`},
		{`\\.\pipe\explicit`, false, `\\.\pipe\explicit`},
		{"fooPipe", true, `\\.\pipe\fooPipe`},
		{`\\.\pipe\explicit`, true, `\\.\pipe\explicit`},
	}
	for _, tt := range tests {
		got, err := normalizePipePath(tt.value, tt.listener)
		if err != nil {
			t.Errorf("normalizePipePath(%q) error = %v", tt.value, err)
			continue
		}
		if got != tt.want {
			t.Errorf("normalizePipePath(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
	if _, err := normalizePipePath("", false); err == nil {
		t.Fatal("empty pipe name succeeded, want error")
	}
}

func TestSplitWindowsCommandLine(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{`tool.exe one "two three"`, []string{"tool.exe", "one", "two three"}},
		{`"C:\Program Files\tool.exe" --label "a b"`, []string{`C:\Program Files\tool.exe`, "--label", "a b"}},
		{`tool.exe "" tail`, []string{"tool.exe", "", "tail"}},
		{`tool.exe a\"b`, []string{"tool.exe", `a"b`}},
		{`tool.exe "C:\path\\"`, []string{"tool.exe", `C:\path\`}},
		{`'C:\Program Files\tool.exe' --flag`, []string{`C:\Program Files\tool.exe`, "--flag"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := splitWindowsCommandLine(tt.input)
			if err != nil {
				t.Fatalf("splitWindowsCommandLine() error = %v", err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Fatalf("splitWindowsCommandLine() = %#v, want %#v", got, tt.want)
			}
		})
	}
	if _, err := splitWindowsCommandLine(`tool.exe "unfinished`); err == nil {
		t.Fatal("unmatched quote succeeded, want error")
	}
}

func TestParseWSLOptions(t *testing.T) {
	spec, err := Parse(`WSL:'socat STDIO unix-connect:foo.sock',distribution=Ubuntu,user=root`, Target)
	if err != nil {
		t.Fatal(err)
	}
	if spec.distribution != "Ubuntu" || spec.user != "root" {
		t.Fatalf("WSL options = distribution:%q user:%q", spec.distribution, spec.user)
	}
	want := []string{"socat", "STDIO", "unix-connect:foo.sock"}
	if fmt.Sprint(spec.args) != fmt.Sprint(want) {
		t.Fatalf("WSL args = %#v, want %#v", spec.args, want)
	}
	if _, err := Parse("WSL:cat,unsupported=x", Source); err == nil {
		t.Fatal("unknown WSL option succeeded, want error")
	}
}

func TestTCPDialAndListen(t *testing.T) {
	listenerSpec, err := Parse("TCP-LISTEN:127.0.0.1:0", Source)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := listenerSpec.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		_, err = io.Copy(conn, conn)
		accepted <- err
	}()

	dialSpec, err := Parse("TCP:"+listener.Addr().String(), Target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialSpec.Open(ctx, strings.NewReader(""), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if deadlineConn, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetDeadline(time.Now().Add(2 * time.Second))
	}
	if _, err := conn.Write([]byte("tcp-roundtrip")); err != nil {
		t.Fatal(err)
	}
	_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	received, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(received) != "tcp-roundtrip" {
		t.Fatalf("TCP echo = %q, want tcp-roundtrip", received)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestTCPListenerRelaysConcurrentSessions(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, acceptErr := backend.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	source, err := Parse("TCP-LISTEN:127.0.0.1:0", Source)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := source.Listen()
	if err != nil {
		t.Fatal(err)
	}
	target, err := Parse("TCP:"+backend.Addr().String(), Target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- serveListener(ctx, source, target, listener, strings.NewReader(""), io.Discard, io.Discard)
	}()

	const clients = 4
	clientResults := make(chan error, clients)
	for clientID := 0; clientID < clients; clientID++ {
		go func(clientID int) {
			conn, dialErr := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			if dialErr != nil {
				clientResults <- dialErr
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte{byte(clientID), 0, 0xFF, 0x80}, 128*1024+clientID)
			if _, writeErr := conn.Write(payload); writeErr != nil {
				clientResults <- writeErr
				return
			}
			if closeErr := conn.(*net.TCPConn).CloseWrite(); closeErr != nil {
				clientResults <- closeErr
				return
			}
			received, readErr := io.ReadAll(conn)
			if readErr != nil {
				clientResults <- readErr
				return
			}
			if !bytes.Equal(received, payload) {
				clientResults <- fmt.Errorf("client %d payload mismatch: received %d bytes, want %d", clientID, len(received), len(payload))
				return
			}
			clientResults <- nil
		}(clientID)
	}
	for range clients {
		if err := <-clientResults; err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatalf("serveListener() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serveListener() did not stop after cancellation")
	}
}

func TestStaleUnixSocketProbeErrors(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		stale bool
	}{
		{name: "Winsock connection refused", err: windows.WSAECONNREFUSED, stale: true},
		{name: "Go connection refused", err: syscall.ECONNREFUSED, stale: true},
		{name: "system not found", err: syscall.ENOENT, stale: true},
		{name: "file not found", err: os.ErrNotExist, stale: true},
		{name: "timeout", err: os.ErrDeadlineExceeded},
		{name: "permission denied", err: errors.New("access denied")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := fmt.Errorf("AF_UNIX probe: %w", tt.err)
			if got := isStaleUnixSocketProbeError(wrapped); got != tt.stale {
				t.Fatalf("isStaleUnixSocketProbeError(%v) = %t, want %t", tt.err, got, tt.stale)
			}
		})
	}
}

func TestUnixListenerRecoversFromStalePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wsocat.sock")
	staleListener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Windows AF_UNIX is unavailable: %v", err)
	}
	if unixListener, ok := staleListener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	if err := staleListener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		t.Skip("AF_UNIX provider removed the socket path on close; no stale path to recover")
	} else if err != nil {
		t.Fatal(err)
	}
	_, probeErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if probeErr == nil {
		t.Fatal("dial to a closed AF_UNIX listener succeeded")
	}
	if !isStaleUnixSocketProbeError(probeErr) {
		t.Fatalf("dial to stale socket returned %T (%v), not a recognized stale-path error", probeErr, probeErr)
	}

	spec, err := Parse("UNIX-LISTEN:"+path, Source)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := spec.Listen()
	if err != nil {
		t.Fatalf("listenUnix did not recover stale socket path: %v", err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = listener.Close()
		}
	})

	dialSpec, err := Parse("UNIX:"+path, Target)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialSpec.Open(context.Background(), strings.NewReader(""), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if _, err := conn.Write([]byte("unix")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(accepted, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "unix" {
		t.Fatalf("AF_UNIX received %q, want unix", buf)
	}
	_ = accepted.Close()
	_ = conn.Close()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path after listener close: Lstat error = %v, want not-exist", err)
	}
}

func TestUnixListenerConflictPreservesActivePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.sock")
	listener, err := listenUnix(path)
	if err != nil {
		t.Skipf("Windows AF_UNIX is unavailable: %v", err)
	}
	defer listener.Close()

	if _, err := listenUnix(path); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("second listen error = %v, want active-path conflict", err)
	}
	// The probe connects to distinguish an active path, so discard that
	// short-lived connection before checking the listener's real service.
	probeConn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = probeConn.Close()
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("active socket path after rejected bind: info=%v err=%v", info, err)
	}

	conn, err := (&net.Dialer{Timeout: time.Second}).Dial("unix", path)
	if err != nil {
		t.Fatalf("active listener stopped accepting after conflict probe: %v", err)
	}
	defer conn.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if _, err := conn.Write([]byte("active")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("active"))
	if _, err := io.ReadFull(accepted, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "active" {
		t.Fatalf("active AF_UNIX listener received %q, want active", buf)
	}
}

func TestNamedPipeDuplexAndHalfClose(t *testing.T) {
	path := fmt.Sprintf("wsocat-test-%d", os.Getpid())
	listenerSpec, err := Parse("NPIPE-LISTEN:"+path, Source)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := listenerSpec.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	dialSpec, err := Parse("NPIPE:"+path, Target)
	if err != nil {
		t.Fatal(err)
	}

	const clients = 3
	serverResult := make(chan error, 1)
	go func() {
		var sessions sync.WaitGroup
		for range clients {
			conn, err := listener.Accept()
			if err != nil {
				serverResult <- err
				return
			}
			sessions.Add(1)
			go func() {
				defer sessions.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
		sessions.Wait()
		serverResult <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientResults := make(chan error, clients)
	for clientID := 0; clientID < clients; clientID++ {
		go func(clientID int) {
			client, err := dialSpec.Open(ctx, strings.NewReader(""), io.Discard, io.Discard)
			if err != nil {
				clientResults <- err
				return
			}
			defer client.Close()
			if err := client.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				clientResults <- err
				return
			}
			payload := bytes.Repeat([]byte{byte(clientID), 0, 0xFF, 0x80}, 32*1024+clientID)
			writeResult := make(chan error, 1)
			go func() {
				if _, err := client.Write(payload); err != nil {
					writeResult <- err
					return
				}
				writeResult <- client.(interface{ CloseWrite() error }).CloseWrite()
			}()
			received, err := io.ReadAll(client)
			if err == nil {
				err = <-writeResult
			}
			if err == nil && !bytes.Equal(received, payload) {
				err = fmt.Errorf("named-pipe payload mismatch: received %d bytes, want %d", len(received), len(payload))
			}
			clientResults <- err
		}(clientID)
	}
	for range clients {
		if err := <-clientResults; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestProcessStreamRoundTrip(t *testing.T) {
	t.Setenv("WSOCAT_ECHO_CHILD", "1")
	command := fmt.Sprintf("EXEC:\"%s\" -test.run=^TestProcessEchoChild$", os.Args[0])
	spec, err := Parse(command, Source)
	if err != nil {
		t.Fatal(err)
	}
	if spec.executable != os.Args[0] || fmt.Sprint(spec.args) != "[-test.run=^TestProcessEchoChild$]" {
		t.Fatalf("parsed EXEC command = %q %#v", spec.executable, spec.args)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := spec.Open(ctx, strings.NewReader(""), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x00, 0xFF, 0x80, 'C'}, 64*1024)
	type readResult struct {
		data []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		got, err := io.ReadAll(stream)
		readDone <- readResult{data: got, err: err}
	}()
	if _, err := io.Copy(stream, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result := <-readDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	if !bytes.Equal(result.data, payload) {
		t.Fatalf("child output length = %d, want %d-byte binary payload", len(result.data), len(payload))
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProcessEchoChild(t *testing.T) {
	if os.Getenv("WSOCAT_ECHO_CHILD") != "1" {
		return
	}
	_, _ = io.Copy(os.Stdout, os.Stdin)
	os.Exit(0)
}

func TestListenUnixDoesNotRemoveRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := listenUnix(path)
	if err == nil {
		t.Fatal("listenUnix on a regular file succeeded, want error")
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("regular file was removed: %v", readErr)
	}
	if string(contents) != "keep" {
		t.Fatalf("regular file contents = %q, want keep", contents)
	}
}
