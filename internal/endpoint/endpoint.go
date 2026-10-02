package endpoint

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/Microsoft/go-winio/pkg/guid"

	"wsocat/internal/address"
	"wsocat/internal/relay"
)

type Side int

const (
	Source Side = iota
	Target
)

type Kind string

const (
	Stdio        Kind = "STDIO"
	TCP          Kind = "TCP"
	TCPListen    Kind = "TCP-LISTEN"
	Npipe        Kind = "NPIPE"
	NpipeListen  Kind = "NPIPE-LISTEN"
	Exec         Kind = "EXEC"
	WSL          Kind = "WSL"
	Unix         Kind = "UNIX"
	UnixListen   Kind = "UNIX-LISTEN"
	TLS          Kind = "TLS"
	Hvsock       Kind = "HVSOCK"
	HvsockListen Kind = "HVSOCK-LISTEN"
	Serial       Kind = "SP"
)

const MaxConcurrentSessions = 128

type Spec struct {
	kind         Kind
	raw          string
	listener     bool
	host         string
	port         int
	serverName   string
	caFile       string
	path         string
	executable   string
	args         []string
	distribution string
	user         string
	vmID         guid.GUID
	serviceID    guid.GUID
	serial       *serialSettings
}

func (s Spec) Kind() Kind       { return s.kind }
func (s Spec) IsListener() bool { return s.listener }
func (s Spec) Raw() string      { return s.raw }

func Parse(raw string, side Side) (Spec, error) {
	parsed, err := address.Parse(raw)
	if err != nil {
		return Spec{}, err
	}
	spec := Spec{kind: Kind(parsed.Tag), raw: raw}
	if side == Target {
		switch spec.kind {
		case TCPListen, NpipeListen, UnixListen, HvsockListen:
			return Spec{}, fmt.Errorf("%s is a listener and is only valid as address1", spec.kind)
		}
	}

	switch spec.kind {
	case Stdio:
		if parsed.Value != "" {
			return Spec{}, fmt.Errorf("STDIO does not take an address value")
		}
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
	case TCP:
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
		spec.host, spec.port, err = parseHostPort(parsed.Value, false)
	case TLS:
		if parsed.Value == "" || strings.HasPrefix(parsed.Value, ":") || !strings.Contains(parsed.Value, ":") {
			err = fmt.Errorf("TLS requires a server host and port")
			break
		}
		spec.host, spec.port, err = parseHostPort(parsed.Value, false)
		if err != nil {
			break
		}
		for key, value := range parsed.Options {
			switch key {
			case "servername":
				if strings.TrimSpace(value) == "" {
					err = fmt.Errorf("TLS option %q cannot be empty", key)
					break
				}
				spec.serverName = value
			case "cafile":
				if strings.TrimSpace(value) == "" {
					err = fmt.Errorf("TLS option %q cannot be empty", key)
					break
				}
				spec.caFile = value
			default:
				err = fmt.Errorf("option %q is not supported for TLS", key)
			}
			if err != nil {
				break
			}
		}
	case Hvsock:
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
		spec.vmID, spec.serviceID, err = parseHvsockAddress(parsed.Value)
	case HvsockListen:
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
		spec.listener = true
		spec.vmID, spec.serviceID, err = parseHvsockAddress(parsed.Value)
	case TCPListen:
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
		spec.listener = true
		spec.host, spec.port, err = parseHostPort(parsed.Value, true)
	case Npipe:
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
		spec.path, err = normalizePipePath(parsed.Value, false)
	case NpipeListen:
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
		spec.listener = true
		spec.path, err = normalizePipePath(parsed.Value, true)
	case Exec:
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
		spec.executable, spec.args, err = parseWindowsCommandLine(parsed.Value)
	case WSL:
		spec.executable, spec.args, err = parseWSL(parsed)
		if err == nil {
			spec.distribution = parsed.Options["distribution"]
			spec.user = parsed.Options["user"]
		}
	case Unix:
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
		if parsed.Value == "" {
			err = fmt.Errorf("UNIX requires a socket path")
		} else {
			spec.path = parsed.Value
		}
	case UnixListen:
		if err := noOptions(parsed); err != nil {
			return Spec{}, err
		}
		spec.listener = true
		if parsed.Value == "" {
			err = fmt.Errorf("UNIX-LISTEN requires a socket path")
		} else {
			spec.path = parsed.Value
		}
	case Serial:
		spec.serial, err = parseSerialSettings(parsed)
	default:
		return Spec{}, fmt.Errorf("unsupported address type %q", parsed.Tag)
	}
	if err != nil {
		return Spec{}, fmt.Errorf("invalid %s address %q: %w", spec.kind, raw, err)
	}
	return spec, nil
}

func ValidatePair(source, target Spec) error {
	if source.listener && target.listener {
		return fmt.Errorf("address2 cannot be a listener")
	}
	if source.kind == Stdio && target.kind == Stdio {
		return fmt.Errorf("STDIO cannot be used on both sides")
	}
	return nil
}

func (s Spec) Open(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) (relay.Stream, error) {
	return s.open(ctx, stdin, stdout, stderr, systemHvsockTransport{}, systemSerialAPI{})
}

func (s Spec) open(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, hvsock hvsockTransport, serial serialNativeAPI) (relay.Stream, error) {
	if s.listener {
		return nil, fmt.Errorf("%s is a listener", s.kind)
	}
	switch s.kind {
	case Stdio:
		return &relay.Duplex{Reader: stdin, Writer: stdout}, nil
	case TCP:
		addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("connect TCP %s: %w", addr, err)
		}
		return conn, nil
	case TLS:
		return s.dialTLS(ctx)
	case Hvsock:
		conn, err := hvsock.Dial(ctx, s.hvsockAddr())
		if err != nil {
			return nil, fmt.Errorf("connect Hyper-V socket %s: %w", s.hvsockAddr(), err)
		}
		return conn, nil
	case Serial:
		if s.serial == nil {
			return nil, fmt.Errorf("serial endpoint has no parsed configuration")
		}
		stream, err := openSerialPort(*s.serial, serial)
		if err != nil {
			return nil, fmt.Errorf("open serial port %s: %w", s.serial.portName, err)
		}
		return stream, nil
	case Npipe:
		conn, err := dialNamedPipe(ctx, s.path)
		if err != nil {
			return nil, fmt.Errorf("connect named pipe %s: %w", s.path, err)
		}
		return conn, nil
	case Exec:
		return startProcess(ctx, s.executable, s.args, stderr)
	case WSL:
		wslPath, err := findWSL()
		if err != nil {
			return nil, err
		}
		args := make([]string, 0, len(s.args)+4)
		if s.distribution != "" {
			args = append(args, "-d", s.distribution)
		}
		if s.user != "" {
			args = append(args, "-u", s.user)
		}
		args = append(args, s.args...)
		return startProcess(ctx, wslPath, args, stderr)
	case Unix:
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", s.path)
		if err != nil {
			return nil, fmt.Errorf("connect AF_UNIX socket %q: %w", s.path, err)
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("%s cannot be opened as a stream", s.kind)
	}
}

func (s Spec) Listen() (net.Listener, error) {
	return s.listen(systemHvsockTransport{})
}

func (s Spec) listen(hvsock hvsockTransport) (net.Listener, error) {
	if !s.listener {
		return nil, fmt.Errorf("%s is not a listener", s.kind)
	}
	switch s.kind {
	case TCPListen:
		addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("listen on TCP %s: %w", addr, err)
		}
		return listener, nil
	case NpipeListen:
		listener, err := listenNamedPipe(s.path)
		if err != nil {
			return nil, fmt.Errorf("listen on named pipe %s: %w", s.path, err)
		}
		return listener, nil
	case UnixListen:
		listener, err := listenUnix(s.path)
		if err != nil {
			return nil, fmt.Errorf("listen on AF_UNIX socket %q: %w", s.path, err)
		}
		return listener, nil
	case HvsockListen:
		listener, err := hvsock.Listen(s.hvsockAddr())
		if err != nil {
			return nil, fmt.Errorf("listen on Hyper-V socket %s: %w", s.hvsockAddr(), err)
		}
		return listener, nil
	default:
		return nil, fmt.Errorf("unsupported listener type %s", s.kind)
	}
}

func Run(ctx context.Context, source, target Spec, stdin io.Reader, stdout, stderr io.Writer) error {
	if err := ValidatePair(source, target); err != nil {
		return err
	}
	if source.listener {
		return serve(ctx, source, target, stdin, stdout, stderr)
	}
	left, err := source.Open(ctx, stdin, stdout, stderr)
	if err != nil {
		return err
	}
	right, err := target.Open(ctx, stdin, stdout, stderr)
	if err != nil {
		_ = left.Close()
		return err
	}
	return relay.Bridge(ctx, left, right)
}

func serve(ctx context.Context, source, target Spec, stdin io.Reader, stdout, stderr io.Writer) error {
	listener, err := source.Listen()
	if err != nil {
		return err
	}
	return serveListener(ctx, source, target, listener, stdin, stdout, stderr)
}

func serveListener(ctx context.Context, source, target Spec, listener net.Listener, stdin io.Reader, stdout, stderr io.Writer) error {
	stopWatcher := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopWatcher:
		}
	}()
	defer close(stopWatcher)
	defer listener.Close()

	permits := make(chan struct{}, MaxConcurrentSessions)
	var sessions sync.WaitGroup
	for {
		inbound, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				break
			}
			_ = listener.Close()
			sessions.Wait()
			return fmt.Errorf("accept on %s: %w", source.kind, acceptErr)
		}

		select {
		case permits <- struct{}{}:
		case <-ctx.Done():
			_ = inbound.Close()
			break
		}
		if ctx.Err() != nil {
			break
		}

		sessions.Add(1)
		go func(inbound relay.Stream) {
			defer sessions.Done()
			defer func() { <-permits }()
			outbound, openErr := target.Open(ctx, stdin, stdout, stderr)
			if openErr != nil {
				_ = inbound.Close()
				if ctx.Err() == nil {
					_, _ = fmt.Fprintf(stderr, "wsocat: session to %s: %v\n", target.kind, openErr)
				}
				return
			}
			if bridgeErr := relay.Bridge(ctx, inbound, outbound); bridgeErr != nil && ctx.Err() == nil {
				_, _ = fmt.Fprintf(stderr, "wsocat: %s session: %v\n", source.kind, bridgeErr)
			}
		}(inbound)
	}
	sessions.Wait()
	return nil
}

func parseHostPort(value string, listener bool) (string, int, error) {
	host, portText := "", value
	if strings.Contains(value, ":") && !strings.HasPrefix(value, "[") {
		var err error
		host, portText, err = net.SplitHostPort(value)
		if err != nil {
			return "", 0, err
		}
	} else if strings.HasPrefix(value, "[") {
		var err error
		host, portText, err = net.SplitHostPort(value)
		if err != nil {
			return "", 0, err
		}
	}
	if portText == "" {
		return "", 0, fmt.Errorf("port is required")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q", portText)
	}
	minPort := 1
	if listener {
		minPort = 0
	}
	if port < minPort || port > 65535 {
		return "", 0, fmt.Errorf("port must be between %d and 65535", minPort)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host, port, nil
}

func noOptions(parsed address.Address) error {
	if len(parsed.Options) != 0 {
		for key := range parsed.Options {
			return fmt.Errorf("option %q is not supported for %s", key, parsed.Tag)
		}
	}
	return nil
}

func parseWSL(parsed address.Address) (string, []string, error) {
	for key := range parsed.Options {
		if key != "distribution" && key != "user" {
			return "", nil, fmt.Errorf("option %q is not supported for WSL", key)
		}
	}
	commandLine := unquoteOuter(parsed.Value)
	if strings.TrimSpace(commandLine) == "" {
		return "", nil, fmt.Errorf("WSL requires a command")
	}
	args, err := splitWindowsCommandLine(commandLine)
	if err != nil {
		return "", nil, err
	}
	if len(args) == 0 || args[0] == "" {
		return "", nil, fmt.Errorf("WSL requires a command")
	}
	return args[0], args, nil
}

func unquoteOuter(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1]
	}
	return value
}
