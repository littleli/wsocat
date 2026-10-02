package endpoint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
)

func (s Spec) dialTLS(ctx context.Context) (net.Conn, error) {
	address := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	config, err := s.tlsConfig()
	if err != nil {
		return nil, fmt.Errorf("configure TLS for %s: %w", address, err)
	}

	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect TLS server %s: %w", address, err)
	}
	secureConnection := tls.Client(connection, config)
	if err := secureConnection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", address, err)
	}
	return secureConnection, nil
}

func (s Spec) tlsConfig() (*tls.Config, error) {
	serverName := s.serverName
	if serverName == "" {
		serverName = s.host
	}
	config := &tls.Config{ServerName: serverName}
	if s.caFile == "" {
		return config, nil
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificate roots: %w", err)
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	caPEM, err := os.ReadFile(s.caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", s.caFile, err)
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA file %q contains no PEM certificates", s.caFile)
	}
	config.RootCAs = roots
	return config, nil
}
