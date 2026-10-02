//go:build windows

package endpoint

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
)

func TestParseHvsockEndpoints(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		vmID      string
		serviceID string
		listener  bool
	}{
		{"literal GUIDs", "HVSOCK:0cb41c0b-fd26-4a41-8370-dccb048e216e:00000ac9-facb-11e6-bd58-64006a7986d3", "0cb41c0b-fd26-4a41-8370-dccb048e216e", "00000ac9-facb-11e6-bd58-64006a7986d3", false},
		{"compact and parenthesized GUIDs", "HVSOCK:e0e16197dd564a1091955ee7a155a838:(00000000-0000-0000-0000-000000000000)", "e0e16197-dd56-4a10-9195-5ee7a155a838", "00000000-0000-0000-0000-000000000000", false},
		{"braced GUIDs", "HVSOCK:{0cb41c0b-fd26-4a41-8370-dccb048e216e}:{00000ac9-facb-11e6-bd58-64006a7986d3}", "0cb41c0b-fd26-4a41-8370-dccb048e216e", "00000ac9-facb-11e6-bd58-64006a7986d3", false},
		{"zero alias", "HVSOCK:ZERO:VSOCK-0", "00000000-0000-0000-0000-000000000000", "00000000-facb-11e6-bd58-64006a7986d3", false},
		{"wildcard alias and case", "hvsock:wIlDcArD:VsOcK-2761", "00000000-0000-0000-0000-000000000000", "00000ac9-facb-11e6-bd58-64006a7986d3", false},
		{"broadcast alias", "HVSOCK:BROADCAST:VSOCK-1", "ffffffff-ffff-ffff-ffff-ffffffffffff", "00000001-facb-11e6-bd58-64006a7986d3", false},
		{"children alias", "HVSOCK:CHILDREN:VSOCK-2147483647", "90db8b89-0d35-4f79-8ce9-49ea0ac8b7cd", "7fffffff-facb-11e6-bd58-64006a7986d3", false},
		{"loopback alias", "HVSOCK:LOOPBACK:VSOCK-0", "e0e16197-dd56-4a10-9195-5ee7a155a838", "00000000-facb-11e6-bd58-64006a7986d3", false},
		{"parent alias listener", "HVSOCK-LISTEN:PARENT:VSOCK-2761", "a42e7cda-d03f-480c-9cc2-a4de20abb878", "00000ac9-facb-11e6-bd58-64006a7986d3", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			side := Target
			if tt.listener {
				side = Source
			}
			spec, err := Parse(tt.address, side)
			if err != nil {
				t.Fatal(err)
			}
			wantVMID := mustTestGUID(t, tt.vmID)
			wantServiceID := mustTestGUID(t, tt.serviceID)
			if spec.vmID != wantVMID || spec.serviceID != wantServiceID {
				t.Fatalf("parsed Hyper-V endpoint = %s:%s, want %s:%s", spec.vmID, spec.serviceID, wantVMID, wantServiceID)
			}
			if spec.IsListener() != tt.listener {
				t.Fatalf("listener = %t, want %t", spec.IsListener(), tt.listener)
			}
			if tt.listener && spec.Kind() != HvsockListen || !tt.listener && spec.Kind() != Hvsock {
				t.Fatalf("kind = %s, listener = %t", spec.Kind(), spec.IsListener())
			}
		})
	}
}

func TestParseHvsockRejectsInvalidAddresses(t *testing.T) {
	tests := []struct {
		address string
		want    string
	}{
		{"HVSOCK:", "VM-ID:service-ID"},
		{"HVSOCK:ZERO", "VM-ID:service-ID"},
		{"HVSOCK::VSOCK-80", "VM-ID:service-ID"},
		{"HVSOCK:ZERO:", "VM-ID:service-ID"},
		{"HVSOCK:UNKNOWN:VSOCK-1", "invalid VM ID"},
		{"HVSOCK:ZERO:not-a-guid", "invalid service ID"},
		{"HVSOCK:ZERO:VSOCK-", "VSOCK port"},
		{"HVSOCK:ZERO:VSOCK--1", "VSOCK port"},
		{"HVSOCK:ZERO:VSOCK-2147483648", "VSOCK port"},
		{"HVSOCK:ZERO:VSOCK-0x10", "VSOCK port"},
		{"HVSOCK:ZERO:VSOCK-80,foo=bar", `option "foo" is not supported`},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			if _, err := Parse(tt.address, Source); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse(%q) error = %v, want substring %q", tt.address, err, tt.want)
			}
		})
	}

	if _, err := Parse("HVSOCK-LISTEN:ZERO:VSOCK-80", Target); err == nil || !strings.Contains(err.Error(), "only valid as address1") {
		t.Fatalf("listener as address2 error = %v, want role error", err)
	}
}

func TestHvsockOpenPassesAddressAndContextToTransport(t *testing.T) {
	spec, err := Parse("HVSOCK:CHILDREN:VSOCK-2761", Target)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	transport := &fakeHvsockTransport{conn: left}

	got, err := spec.open(ctx, strings.NewReader(""), nil, nil, transport, systemSerialAPI{})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if got != left {
		t.Fatal("Open did not return the transport connection")
	}
	if transport.dialContext != ctx {
		t.Fatal("Open did not pass its context to the Hyper-V transport")
	}
	assertHvsockAddress(t, transport.dialAddress, "90db8b89-0d35-4f79-8ce9-49ea0ac8b7cd", "00000ac9-facb-11e6-bd58-64006a7986d3")
}

func TestHvsockListenPassesAddressToTransport(t *testing.T) {
	spec, err := Parse("HVSOCK-LISTEN:WILDCARD:VSOCK-80", Source)
	if err != nil {
		t.Fatal(err)
	}
	listener := &fakeHvsockListener{}
	transport := &fakeHvsockTransport{listener: listener}

	got, err := spec.listen(transport)
	if err != nil {
		t.Fatal(err)
	}
	if got != listener {
		t.Fatal("Listen did not return the transport listener")
	}
	assertHvsockAddress(t, transport.listenAddress, "00000000-0000-0000-0000-000000000000", "00000050-facb-11e6-bd58-64006a7986d3")
}

func TestHvsockTransportErrorsAreWrapped(t *testing.T) {
	providerErr := errors.New("Hyper-V provider unavailable")
	t.Run("dial", func(t *testing.T) {
		spec, _ := Parse("HVSOCK:PARENT:VSOCK-80", Target)
		_, err := spec.open(context.Background(), nil, nil, nil, &fakeHvsockTransport{dialErr: providerErr}, systemSerialAPI{})
		if !errors.Is(err, providerErr) || !strings.Contains(err.Error(), "connect Hyper-V socket") {
			t.Fatalf("Open error = %v, want wrapped provider error", err)
		}
	})
	t.Run("listen", func(t *testing.T) {
		spec, _ := Parse("HVSOCK-LISTEN:ZERO:VSOCK-80", Source)
		_, err := spec.listen(&fakeHvsockTransport{listenErr: providerErr})
		if !errors.Is(err, providerErr) || !strings.Contains(err.Error(), "listen on Hyper-V socket") {
			t.Fatalf("Listen error = %v, want wrapped provider error", err)
		}
	})
}

func mustTestGUID(t *testing.T, value string) guid.GUID {
	t.Helper()
	parsed, err := guid.FromString(value)
	if err != nil {
		t.Fatalf("invalid test GUID %q: %v", value, err)
	}
	return parsed
}

func assertHvsockAddress(t *testing.T, got *winio.HvsockAddr, vmID, serviceID string) {
	t.Helper()
	if got == nil {
		t.Fatal("transport received a nil Hyper-V address")
	}
	if got.VMID != mustTestGUID(t, vmID) || got.ServiceID != mustTestGUID(t, serviceID) {
		t.Fatalf("transport address = %s, want %s:%s", got, vmID, serviceID)
	}
}

type fakeHvsockTransport struct {
	dialAddress   *winio.HvsockAddr
	dialContext   context.Context
	dialErr       error
	conn          net.Conn
	listenAddress *winio.HvsockAddr
	listenErr     error
	listener      net.Listener
}

func (f *fakeHvsockTransport) Dial(ctx context.Context, addr *winio.HvsockAddr) (net.Conn, error) {
	f.dialContext = ctx
	f.dialAddress = addr
	return f.conn, f.dialErr
}

func (f *fakeHvsockTransport) Listen(addr *winio.HvsockAddr) (net.Listener, error) {
	f.listenAddress = addr
	return f.listener, f.listenErr
}

type fakeHvsockListener struct{}

func (*fakeHvsockListener) Accept() (net.Conn, error) { return nil, errors.New("unexpected Accept") }
func (*fakeHvsockListener) Close() error              { return nil }
func (*fakeHvsockListener) Addr() net.Addr            { return &net.TCPAddr{} }
