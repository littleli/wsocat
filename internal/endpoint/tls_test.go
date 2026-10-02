//go:build windows

package endpoint

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTLSClientRoundTripUsesSystemNameAndCustomCA(t *testing.T) {
	certificate, certificatePEM := makeTLSTestCertificate(t)
	caPath := filepath.Join(t.TempDir(), "test-ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	server := startTLSEchoServer(t, certificate)
	port := server.listener.Addr().(*net.TCPAddr).Port

	spec, err := Parse(fmt.Sprintf(`TLS:localhost:%d,cafile="%s"`, port, caPath), Target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	source, err := Parse("STDIO", Source)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0, 0xFF, 0x80, 'T'}, 128*1024)
	var stdout bytes.Buffer
	if err := Run(ctx, source, spec, bytes.NewReader(payload), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), payload) {
		t.Fatalf("TLS relay returned %d bytes, want %d", stdout.Len(), len(payload))
	}

	select {
	case serverName := <-server.serverNames:
		if serverName != "localhost" {
			t.Fatalf("TLS SNI = %q, want localhost", serverName)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS server did not receive a ClientHello")
	}
	if err := <-server.done; err != nil {
		t.Fatalf("TLS echo server: %v", err)
	}
}

func TestTLSClientRejectsUntrustedAndMismatchedCertificates(t *testing.T) {
	certificate, certificatePEM := makeTLSTestCertificate(t)
	caPath := filepath.Join(t.TempDir(), "test-ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		options  string
		wantType any
	}{
		{name: "untrusted authority", options: `servername=service.test`, wantType: x509.UnknownAuthorityError{}},
		{name: "hostname mismatch", options: fmt.Sprintf(`servername=wrong.test,cafile="%s"`, caPath), wantType: x509.HostnameError{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := startTLSEchoServer(t, certificate)
			port := server.listener.Addr().(*net.TCPAddr).Port
			address := fmt.Sprintf("TLS:127.0.0.1:%d,%s", port, tt.options)
			spec, err := Parse(address, Target)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = spec.Open(ctx, strings.NewReader(""), io.Discard, io.Discard)
			if err == nil {
				t.Fatal("TLS Open succeeded, want certificate verification failure")
			}
			switch want := tt.wantType.(type) {
			case x509.UnknownAuthorityError:
				var got x509.UnknownAuthorityError
				if !errors.As(err, &got) {
					t.Fatalf("TLS Open error = %v, want unknown-authority error", err)
				}
			case x509.HostnameError:
				var got x509.HostnameError
				if !errors.As(err, &got) {
					t.Fatalf("TLS Open error = %v, want hostname error", err)
				}
			default:
				t.Fatalf("unsupported expected error type %T", want)
			}
			select {
			case <-server.done:
			case <-time.After(2 * time.Second):
				t.Fatal("TLS server did not observe failed handshake cleanup")
			}
		})
	}
}

func TestTLSClientHandshakeHonorsContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_, err = io.Copy(io.Discard, conn)
		serverDone <- err
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	spec, err := Parse(fmt.Sprintf("TLS:127.0.0.1:%d", port), Target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = spec.Open(ctx, strings.NewReader(""), io.Discard, io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("TLS Open error = %v, want context deadline exceeded", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server connection did not close after TLS handshake cancellation")
	}
}

func TestTLSConfigDefaultsServerNameToDialHost(t *testing.T) {
	spec, err := Parse("TLS:api.example.com:443", Target)
	if err != nil {
		t.Fatal(err)
	}
	config, err := spec.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerName != "api.example.com" {
		t.Fatalf("TLS ServerName = %q, want api.example.com", config.ServerName)
	}
	if config.InsecureSkipVerify {
		t.Fatal("TLS certificate verification is disabled")
	}

	override, err := Parse("TLS:127.0.0.1:443,servername=service.example", Target)
	if err != nil {
		t.Fatal(err)
	}
	config, err = override.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerName != "service.example" {
		t.Fatalf("TLS ServerName override = %q, want service.example", config.ServerName)
	}
}

type tlsEchoServer struct {
	listener    net.Listener
	serverNames chan string
	done        chan error
}

func startTLSEchoServer(t *testing.T, certificate tls.Certificate) *tlsEchoServer {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &tlsEchoServer{
		listener:    nil,
		serverNames: make(chan string, 1),
		done:        make(chan error, 1),
	}
	serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}}
	serverConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		server.serverNames <- hello.ServerName
		return nil, nil
	}
	server.listener = tls.NewListener(tcpListener, serverConfig)
	t.Cleanup(func() { _ = server.listener.Close() })
	go func() {
		conn, err := server.listener.Accept()
		if err != nil {
			server.done <- err
			return
		}
		defer conn.Close()
		_, err = io.Copy(conn, conn)
		server.done <- err
	}()
	return server
}

func makeTLSTestCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", "service.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, certificatePEM
}
