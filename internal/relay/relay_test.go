package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestBridgeCopiesBothDirections(t *testing.T) {
	leftPeer, leftRelay := net.Pipe()
	rightPeer, rightRelay := net.Pipe()
	defer leftPeer.Close()
	defer rightPeer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	bridgeResult := make(chan error, 1)
	go func() { bridgeResult <- Bridge(ctx, leftRelay, rightRelay) }()

	peerResult := make(chan error, 2)
	go exchange(leftPeer, []byte("from-left"), []byte("from-right"), peerResult)
	go exchange(rightPeer, []byte("from-right"), []byte("from-left"), peerResult)

	for range 2 {
		if err := <-peerResult; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-bridgeResult; err != nil {
		t.Fatalf("Bridge() error = %v", err)
	}
}

func TestBridgeCopiesLargeBinaryPayloadsBothDirections(t *testing.T) {
	leftPeer, leftRelay := tcpPair(t)
	rightPeer, rightRelay := tcpPair(t)
	defer leftPeer.Close()
	defer rightPeer.Close()

	leftPayload := bytes.Repeat([]byte{0x00, 0xFF, 0x80, 'L'}, 256*1024+13)
	rightPayload := bytes.Repeat([]byte{0xFE, 0x00, 'R', 0x81, 0x7F}, 190*1024+29)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bridgeResult := make(chan error, 1)
	go func() { bridgeResult <- Bridge(ctx, leftRelay, rightRelay) }()

	peerResult := make(chan error, 2)
	go exchangeHalfClosed(leftPeer, leftPayload, rightPayload, peerResult)
	go exchangeHalfClosed(rightPeer, rightPayload, leftPayload, peerResult)
	for range 2 {
		if err := <-peerResult; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-bridgeResult; err != nil {
		t.Fatalf("Bridge() error = %v", err)
	}
}

func TestBridgeCancellationClosesStreams(t *testing.T) {
	leftPeer, leftRelay := net.Pipe()
	rightPeer, rightRelay := net.Pipe()
	defer leftPeer.Close()
	defer rightPeer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- Bridge(ctx, leftRelay, rightRelay) }()
	cancel()

	select {
	case err := <-result:
		if err != context.Canceled {
			t.Fatalf("Bridge() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Bridge() did not stop after cancellation")
	}

	_ = leftPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := leftPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer read succeeded after relay cancellation")
	}
}

func exchange(conn net.Conn, sent, expected []byte, result chan<- error) {
	if _, err := conn.Write(sent); err != nil {
		result <- err
		return
	}
	received := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, received); err != nil {
		result <- err
		return
	}
	if string(received) != string(expected) {
		result <- io.ErrUnexpectedEOF
		return
	}
	result <- conn.Close()
}

func exchangeHalfClosed(conn net.Conn, sent, expected []byte, result chan<- error) {
	if _, err := conn.Write(sent); err != nil {
		result <- err
		return
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		result <- err
		return
	}
	received, err := io.ReadAll(conn)
	if err != nil {
		result <- err
		return
	}
	if !bytes.Equal(received, expected) {
		result <- io.ErrUnexpectedEOF
		return
	}
	result <- conn.Close()
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErr:
		_ = client.Close()
		t.Fatal(err)
	}
	return nil, nil
}
