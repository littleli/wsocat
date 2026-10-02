//go:build windows

package endpoint

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestParseSerialSettings(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want serialSettings
	}{
		{
			name: "reference defaults",
			addr: "SP:COM1",
			want: serialSettings{portName: "COM1", baudRate: 9600, parity: serialParityNone, dataBits: 8, stopBits: serialStopOne},
		},
		{
			name: "reference option names and values",
			addr: "SP:com10,baudrate=12500,parity=Odd,databits=5,stopbits=OnePointFive",
			want: serialSettings{portName: "COM10", baudRate: 12500, parity: serialParityOdd, dataBits: 5, stopBits: serialStopOnePoint5},
		},
		{
			name: "numeric enum values and device path",
			addr: `SP:\\.\COM7,baudrate=115200,parity=4,databits=8,stopbits=2`,
			want: serialSettings{portName: "COM7", baudRate: 115200, parity: serialParitySpace, dataBits: 8, stopBits: serialStopTwo},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := Parse(tt.addr, Target)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Kind() != Serial || spec.serial == nil {
				t.Fatalf("parsed endpoint = %#v, want serial configuration", spec)
			}
			if *spec.serial != tt.want {
				t.Fatalf("serial settings = %#v, want %#v", *spec.serial, tt.want)
			}
		})
	}
}

func TestParseSerialSettingsRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"SP:COM1,baudrate=0", "baudrate must be a positive"},
		{"SP:COM1,baudrate=2147483648", "baudrate must be a positive"},
		{"SP:COM1,baudrate=fast", "baudrate must be a positive"},
		{"SP:COM1,parity=5", "parity must be"},
		{"SP:COM1,databits=4", "databits must be between 5 and 8"},
		{"SP:COM1,databits=16", "databits must be between 5 and 8"},
		{"SP:COM1,databits=5,stopbits=Two", "5 data bits cannot be combined with 2 stop bits"},
		{"SP:COM1,databits=8,stopbits=OnePointFive", "1.5 stop bits require 5 data bits"},
		{"SP:COM1,stopbits=0", "stopbits None is not supported"},
		{"SP:COM1,stopbits=9", "stopbits must be"},
		{"SP:COM1,unsupported=value", "not supported for SP"},
		{"SP:COMX", "port name must be COM followed by a port number"},
		{"SP:COM1,baudrate=9600,baudrate=19200", "duplicate option"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			_, err := Parse(tt.addr, Source)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse(%q) error = %v, want substring %q", tt.addr, err, tt.want)
			}
		})
	}
}

func TestConfigureSerialDCB(t *testing.T) {
	if got := unsafe.Sizeof(serialDCB{}); got != 28 {
		t.Fatalf("serial DCB size = %d, want Win32 DCB size 28", got)
	}
	tests := []struct {
		name     string
		parity   uint8
		wantFlag uint32
		wantChar uint8
	}{
		{name: "none", parity: serialParityNone, wantFlag: serialFlagBinary},
		{name: "odd", parity: serialParityOdd, wantFlag: serialFlagBinary | serialFlagParity | serialFlagErrorChar, wantChar: serialParityReplace},
		{name: "mark", parity: serialParityMark, wantFlag: serialFlagBinary | serialFlagParity | serialFlagErrorChar, wantChar: serialParityReplace},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configured := configureSerialDCB(serialDCB{
				Flags:      ^uint32(0),
				WReserved:  55,
				ByteSize:   8,
				WReserved1: 66,
			}, serialSettings{baudRate: 57600, parity: tt.parity, dataBits: 7, stopBits: serialStopTwo})
			if configured.DCBlength != 28 || configured.BaudRate != 57600 || configured.ByteSize != 7 || configured.Parity != tt.parity || configured.StopBits != serialStopTwo {
				t.Fatalf("configured DCB = %#v, settings were not applied", configured)
			}
			if configured.Flags != tt.wantFlag || configured.ErrorChar != tt.wantChar {
				t.Fatalf("DCB flags/error char = %#x/%#x, want %#x/%#x", configured.Flags, configured.ErrorChar, tt.wantFlag, tt.wantChar)
			}
			if configured.WReserved != 0 || configured.WReserved1 != 0 {
				t.Fatalf("reserved DCB fields = %d/%d, want zero", configured.WReserved, configured.WReserved1)
			}
		})
	}
}

func TestOpenSerialPortConfiguresExclusiveOverlappedCOMDevice(t *testing.T) {
	spec, err := Parse("SP:COM10,baudrate=19200,parity=Even,databits=7,stopbits=Two", Source)
	if err != nil {
		t.Fatal(err)
	}
	api := newFakeSerialAPI()
	stream, err := spec.open(context.Background(), nil, nil, nil, systemHvsockTransport{}, api)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := api.createPath, `\\.\COM10`; got != want {
		t.Fatalf("CreateFile path = %q, want %q", got, want)
	}
	if api.access != windows.GENERIC_READ|windows.GENERIC_WRITE || api.shareMode != 0 || api.disposition != windows.OPEN_EXISTING || api.flags != windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED {
		t.Fatalf("CreateFile parameters = access %#x, share %#x, disposition %#x, flags %#x", api.access, api.shareMode, api.disposition, api.flags)
	}
	if got := api.setState; got == nil || got.BaudRate != 19200 || got.ByteSize != 7 || got.Parity != serialParityEven || got.StopBits != serialStopTwo {
		t.Fatalf("SetCommState received %#v, want requested configuration", got)
	}
	if api.timeouts != (windows.CommTimeouts{
		ReadIntervalTimeout:         ^uint32(0),
		ReadTotalTimeoutMultiplier:  ^uint32(0),
		ReadTotalTimeoutConstant:    ^uint32(1),
		WriteTotalTimeoutMultiplier: 0,
		WriteTotalTimeoutConstant:   0,
	}) {
		t.Fatalf("COMMTIMEOUTS = %#v, want reference-compatible infinite defaults", api.timeouts)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if !containsHandle(api.closedHandles(), 100) {
		t.Fatalf("closed handles = %v, want serial device handle closed", api.closedHandles())
	}
}

func TestOpenSerialPortClosesDeviceWhenConfigurationFails(t *testing.T) {
	setupErr := errors.New("driver rejected DCB")
	api := newFakeSerialAPI()
	api.failSetState = setupErr
	_, err := openSerialPort(serialSettings{portName: "COM3", baudRate: 9600, parity: serialParityNone, dataBits: 8, stopBits: serialStopOne}, api)
	if !errors.Is(err, setupErr) {
		t.Fatalf("openSerialPort error = %v, want wrapped setup error", err)
	}
	if !containsHandle(api.closedHandles(), 100) {
		t.Fatalf("closed handles = %v, want device closed after setup failure", api.closedHandles())
	}
}

func TestSerialStreamReadsAndWritesBytes(t *testing.T) {
	api := newFakeSerialAPI()
	api.readData = []byte{0, 1, 2, 0xff}
	api.writeLimit = 2
	stream, err := openSerialPort(defaultTestSerialSettings(), api)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	buffer := make([]byte, 16)
	n, err := stream.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(buffer[:n], api.readData) {
		t.Fatalf("Read() bytes = %v, want %v", buffer[:n], api.readData)
	}
	written := []byte{9, 0, 8, 0xff, 7}
	n, err = stream.Write(written)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(written) || !reflect.DeepEqual(api.writtenBytes(), written) {
		t.Fatalf("Write() = (%d, %v), output %v; want all bytes %v", n, err, api.writtenBytes(), written)
	}
}

func TestSerialStreamCloseCancelsPendingRead(t *testing.T) {
	api := newFakeSerialAPI()
	api.blockRead = true
	stream, err := openSerialPort(defaultTestSerialSettings(), api)
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 8))
		readDone <- err
	}()
	select {
	case <-api.readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not reach pending overlapped completion")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("pending Read() error = %v, want os.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not finish after Close canceled its I/O")
	}
}

func defaultTestSerialSettings() serialSettings {
	return serialSettings{portName: "COM1", baudRate: 9600, parity: serialParityNone, dataBits: 8, stopBits: serialStopOne}
}

type fakeSerialResult struct {
	n       uint32
	err     error
	pending bool
}

type fakeSerialAPI struct {
	mu sync.Mutex

	createPath   string
	access       uint32
	shareMode    uint32
	disposition  uint32
	flags        uint32
	currentState serialDCB
	setState     *serialDCB
	timeouts     windows.CommTimeouts
	failSetState error
	failTimeouts error

	nextEvent   windows.Handle
	results     map[*windows.Overlapped]fakeSerialResult
	readData    []byte
	written     []byte
	writeLimit  int
	blockRead   bool
	readStarted chan struct{}
	cancelled   chan struct{}
	cancelOnce  sync.Once
	closed      []windows.Handle
}

func newFakeSerialAPI() *fakeSerialAPI {
	return &fakeSerialAPI{
		currentState: serialDCB{DCBlength: 28, XonLim: 1, XoffLim: 2},
		nextEvent:    200,
		results:      make(map[*windows.Overlapped]fakeSerialResult),
		readStarted:  make(chan struct{}),
		cancelled:    make(chan struct{}),
	}
}

func (f *fakeSerialAPI) CreateFile(path string, access, shareMode, disposition, flags uint32) (windows.Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createPath, f.access, f.shareMode, f.disposition, f.flags = path, access, shareMode, disposition, flags
	return 100, nil
}

func (f *fakeSerialAPI) GetCommState(_ windows.Handle, state *serialDCB) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	*state = f.currentState
	return nil
}

func (f *fakeSerialAPI) SetCommState(_ windows.Handle, state *serialDCB) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	copyOfState := *state
	f.setState = &copyOfState
	return f.failSetState
}

func (f *fakeSerialAPI) SetCommTimeouts(_ windows.Handle, timeouts *windows.CommTimeouts) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.timeouts = *timeouts
	return f.failTimeouts
}

func (f *fakeSerialAPI) CreateEvent() (windows.Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextEvent++
	return f.nextEvent, nil
}

func (f *fakeSerialAPI) ReadFile(_ windows.Handle, buffer []byte, overlapped *windows.Overlapped) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blockRead {
		f.results[overlapped] = fakeSerialResult{pending: true}
		return windows.ERROR_IO_PENDING
	}
	n := copy(buffer, f.readData)
	f.results[overlapped] = fakeSerialResult{n: uint32(n)}
	return nil
}

func (f *fakeSerialAPI) WriteFile(_ windows.Handle, buffer []byte, overlapped *windows.Overlapped) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(buffer)
	if f.writeLimit > 0 && n > f.writeLimit {
		n = f.writeLimit
	}
	f.written = append(f.written, buffer[:n]...)
	f.results[overlapped] = fakeSerialResult{n: uint32(n)}
	return nil
}

func (f *fakeSerialAPI) GetOverlappedResult(_ windows.Handle, overlapped *windows.Overlapped, transferred *uint32, _ bool) error {
	f.mu.Lock()
	result := f.results[overlapped]
	if result.pending {
		f.mu.Unlock()
		select {
		case <-f.readStarted:
		default:
			close(f.readStarted)
		}
		<-f.cancelled
		return windows.ERROR_OPERATION_ABORTED
	}
	f.mu.Unlock()
	*transferred = result.n
	return result.err
}

func (f *fakeSerialAPI) CancelIoEx(_ windows.Handle, _ *windows.Overlapped) error {
	f.cancelOnce.Do(func() { close(f.cancelled) })
	return nil
}

func (f *fakeSerialAPI) CloseHandle(handle windows.Handle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, handle)
	return nil
}

func (f *fakeSerialAPI) writtenBytes() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.written...)
}

func (f *fakeSerialAPI) closedHandles() []windows.Handle {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]windows.Handle(nil), f.closed...)
}

func containsHandle(handles []windows.Handle, want windows.Handle) bool {
	for _, handle := range handles {
		if handle == want {
			return true
		}
	}
	return false
}

var _ io.ReadWriteCloser = (*serialStream)(nil)
var _ serialNativeAPI = (*fakeSerialAPI)(nil)
