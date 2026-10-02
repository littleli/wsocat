package relay

import (
	"context"
	"io"
	"sync"
)

// Stream is a bidirectional byte stream. Network connections, process pipes,
// and a pair of stdin/stdout handles can all implement this interface.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
}

// WriteCloser is implemented by streams that can signal EOF to their peer
// without closing their read side.
type WriteCloser interface {
	CloseWrite() error
}

// Bridge copies bytes in both directions. When one direction reaches EOF, it
// half-closes the destination's write side when that capability is available,
// allowing a response to flow back before the whole connection is closed.
func Bridge(ctx context.Context, left, right Stream) error {
	results := make(chan error, 2)
	go func() { results <- copyDirection(right, left) }()
	go func() { results <- copyDirection(left, right) }()

	var closeOnce sync.Once
	closeBoth := func() error {
		var firstErr error
		closeOnce.Do(func() {
			if err := left.Close(); err != nil {
				firstErr = err
			}
			if err := right.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		})
		return firstErr
	}

	completed := 0
	for completed < 2 {
		select {
		case err := <-results:
			completed++
			if err != nil {
				_ = closeBoth()
				return err
			}
		case <-ctx.Done():
			_ = closeBoth()
			return ctx.Err()
		}
	}
	return closeBoth()
}

func copyDirection(dst, src Stream) error {
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	if halfCloser, ok := dst.(WriteCloser); ok {
		return halfCloser.CloseWrite()
	}
	return nil
}

// Duplex adapts distinct input and output handles into a Stream. A nil close
// function deliberately leaves process-wide handles such as stdio open.
type Duplex struct {
	Reader    io.Reader
	Writer    io.Writer
	CloseFunc func() error
}

func (d *Duplex) Read(p []byte) (int, error)  { return d.Reader.Read(p) }
func (d *Duplex) Write(p []byte) (int, error) { return d.Writer.Write(p) }
func (d *Duplex) Close() error {
	if d.CloseFunc != nil {
		return d.CloseFunc()
	}
	return nil
}
