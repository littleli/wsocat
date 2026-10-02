//go:build windows

package endpoint

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
)

type hvsockTransport interface {
	Dial(context.Context, *winio.HvsockAddr) (net.Conn, error)
	Listen(*winio.HvsockAddr) (net.Listener, error)
}

type systemHvsockTransport struct{}

func (systemHvsockTransport) Dial(ctx context.Context, addr *winio.HvsockAddr) (net.Conn, error) {
	return winio.Dial(ctx, addr)
}

func (systemHvsockTransport) Listen(addr *winio.HvsockAddr) (net.Listener, error) {
	return winio.ListenHvsock(addr)
}

func (s Spec) hvsockAddr() *winio.HvsockAddr {
	return &winio.HvsockAddr{VMID: s.vmID, ServiceID: s.serviceID}
}

func parseHvsockAddress(value string) (guid.GUID, guid.GUID, error) {
	separator := strings.LastIndex(value, ":")
	if separator <= 0 || separator == len(value)-1 {
		return guid.GUID{}, guid.GUID{}, fmt.Errorf("expected VM-ID:service-ID")
	}

	vmText := strings.TrimSpace(value[:separator])
	serviceText := strings.TrimSpace(value[separator+1:])
	vmID, err := parseHvsockVMID(vmText)
	if err != nil {
		return guid.GUID{}, guid.GUID{}, fmt.Errorf("invalid VM ID %q: %w", vmText, err)
	}
	serviceID, err := parseHvsockServiceID(serviceText)
	if err != nil {
		return guid.GUID{}, guid.GUID{}, fmt.Errorf("invalid service ID %q: %w", serviceText, err)
	}
	return vmID, serviceID, nil
}

func parseHvsockVMID(value string) (guid.GUID, error) {
	switch strings.ToUpper(value) {
	case "ZERO", "WILDCARD":
		return guid.GUID{}, nil
	case "BROADCAST":
		return parseHvsockGUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
	case "CHILDREN":
		return parseHvsockGUID("90db8b89-0d35-4f79-8ce9-49ea0ac8b7cd")
	case "LOOPBACK":
		return parseHvsockGUID("e0e16197-dd56-4a10-9195-5ee7a155a838")
	case "PARENT":
		return parseHvsockGUID("a42e7cda-d03f-480c-9cc2-a4de20abb878")
	default:
		return parseHvsockGUID(value)
	}
}

func parseHvsockServiceID(value string) (guid.GUID, error) {
	if strings.HasPrefix(strings.ToLower(value), "vsock-") {
		portText := value[len("vsock-"):]
		port, err := strconv.ParseUint(portText, 10, 31)
		if err != nil {
			return guid.GUID{}, fmt.Errorf("VSOCK port must be a decimal value from 0 to 2147483647")
		}
		return winio.VsockServiceID(uint32(port)), nil
	}
	return parseHvsockGUID(value)
}

// parseHvsockGUID accepts the dashed, compact, braced, and parenthesized GUID
// forms used by the reference implementation and its tests.
func parseHvsockGUID(value string) (guid.GUID, error) {
	original := value
	value = strings.TrimSpace(value)
	if len(value) == 38 && ((value[0] == '{' && value[37] == '}') || (value[0] == '(' && value[37] == ')')) {
		value = value[1:37]
	}
	if len(value) == 32 {
		value = value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:]
	}
	parsed, err := guid.FromString(value)
	if err != nil {
		return guid.GUID{}, fmt.Errorf("invalid GUID %q", original)
	}
	return parsed, nil
}
