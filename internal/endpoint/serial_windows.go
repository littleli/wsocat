//go:build windows

package endpoint

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"wsocat/internal/address"
)

const (
	serialParityNone  uint8 = 0
	serialParityOdd   uint8 = 1
	serialParityEven  uint8 = 2
	serialParityMark  uint8 = 3
	serialParitySpace uint8 = 4

	serialStopOne       uint8 = 0 // Win32 ONESTOPBIT; .NET StopBits.One is 1.
	serialStopOnePoint5 uint8 = 1 // Win32 ONE5STOPBITS; .NET StopBits.OnePointFive is 3.
	serialStopTwo       uint8 = 2

	serialFlagBinary         uint32 = 1 << 0
	serialFlagParity         uint32 = 1 << 1
	serialFlagOutxCtsFlow    uint32 = 1 << 2
	serialFlagOutxDsrFlow    uint32 = 1 << 3
	serialFlagDtrControl     uint32 = 3 << 4
	serialFlagDsrSensitivity uint32 = 1 << 6
	serialFlagTXContinue     uint32 = 1 << 7
	serialFlagOutX           uint32 = 1 << 8
	serialFlagInX            uint32 = 1 << 9
	serialFlagErrorChar      uint32 = 1 << 10
	serialFlagNull           uint32 = 1 << 11
	serialFlagRtsControl     uint32 = 3 << 12
	serialFlagAbortOnError   uint32 = 1 << 14
	serialParityReplace      uint8  = '?'
)

type serialSettings struct {
	portName string
	baudRate uint32
	parity   uint8
	dataBits uint8
	stopBits uint8
}

func parseSerialSettings(parsed address.Address) (*serialSettings, error) {
	portName, err := normalizeSerialPortName(parsed.Value)
	if err != nil {
		return nil, err
	}
	settings := &serialSettings{
		portName: portName,
		baudRate: 9600,
		parity:   serialParityNone,
		dataBits: 8,
		stopBits: serialStopOne,
	}
	for key, value := range parsed.Options {
		value = strings.TrimSpace(value)
		switch key {
		case "baudrate":
			baud, parseErr := strconv.ParseInt(value, 10, 32)
			if parseErr != nil || baud <= 0 {
				return nil, fmt.Errorf("baudrate must be a positive 32-bit integer")
			}
			settings.baudRate = uint32(baud)
		case "parity":
			settings.parity, err = parseSerialParity(value)
			if err != nil {
				return nil, err
			}
		case "databits":
			dataBits, parseErr := strconv.ParseInt(value, 10, 32)
			if parseErr != nil || dataBits < 5 || dataBits > 8 {
				return nil, fmt.Errorf("databits must be between 5 and 8")
			}
			settings.dataBits = uint8(dataBits)
		case "stopbits":
			settings.stopBits, err = parseSerialStopBits(value)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("option %q is not supported for SP", key)
		}
	}
	if err := validateSerialSettings(*settings); err != nil {
		return nil, err
	}
	return settings, nil
}

func validateSerialSettings(settings serialSettings) error {
	if settings.baudRate == 0 {
		return fmt.Errorf("baudrate must be a positive 32-bit integer")
	}
	if settings.dataBits < 5 || settings.dataBits > 8 {
		return fmt.Errorf("databits must be between 5 and 8")
	}
	if settings.parity > serialParitySpace {
		return fmt.Errorf("parity must be None, Odd, Even, Mark, Space, or a number from 0 to 4")
	}
	if settings.stopBits > serialStopTwo {
		return fmt.Errorf("stopbits must be One, OnePointFive, Two, or a number from 1 to 3")
	}
	if settings.dataBits == 5 && settings.stopBits == serialStopTwo {
		return fmt.Errorf("5 data bits cannot be combined with 2 stop bits")
	}
	if settings.dataBits != 5 && settings.stopBits == serialStopOnePoint5 {
		return fmt.Errorf("1.5 stop bits require 5 data bits")
	}
	return nil
}

func normalizeSerialPortName(value string) (string, error) {
	name := strings.ToUpper(strings.TrimSpace(value))
	if strings.HasPrefix(name, `\\.\`) {
		name = name[4:]
	}
	if !strings.HasPrefix(name, "COM") || len(name) == 3 {
		return "", fmt.Errorf("port name must be COM followed by a port number")
	}
	for _, digit := range name[3:] {
		if digit < '0' || digit > '9' {
			return "", fmt.Errorf("port name must be COM followed by a port number")
		}
	}
	return name, nil
}

func parseSerialParity(value string) (uint8, error) {
	switch strings.ToLower(value) {
	case "none", "0":
		return serialParityNone, nil
	case "odd", "1":
		return serialParityOdd, nil
	case "even", "2":
		return serialParityEven, nil
	case "mark", "3":
		return serialParityMark, nil
	case "space", "4":
		return serialParitySpace, nil
	default:
		return 0, fmt.Errorf("parity must be None, Odd, Even, Mark, Space, or a number from 0 to 4")
	}
}

func parseSerialStopBits(value string) (uint8, error) {
	switch strings.ToLower(value) {
	case "one", "1":
		return serialStopOne, nil
	case "onepointfive", "3":
		return serialStopOnePoint5, nil
	case "two", "2":
		return serialStopTwo, nil
	case "none", "0":
		return 0, fmt.Errorf("stopbits None is not supported; use One, OnePointFive, or Two")
	default:
		return 0, fmt.Errorf("stopbits must be One, OnePointFive, Two, or a number from 1 to 3")
	}
}

type serialNativeAPI interface {
	CreateFile(path string, access, shareMode, disposition, flags uint32) (windows.Handle, error)
	GetCommState(windows.Handle, *serialDCB) error
	SetCommState(windows.Handle, *serialDCB) error
	SetCommTimeouts(windows.Handle, *windows.CommTimeouts) error
	CreateEvent() (windows.Handle, error)
	ReadFile(windows.Handle, []byte, *windows.Overlapped) error
	WriteFile(windows.Handle, []byte, *windows.Overlapped) error
	GetOverlappedResult(windows.Handle, *windows.Overlapped, *uint32, bool) error
	CancelIoEx(windows.Handle, *windows.Overlapped) error
	CloseHandle(windows.Handle) error
}

type serialDCB struct {
	DCBlength  uint32
	BaudRate   uint32
	Flags      uint32
	WReserved  uint16
	XonLim     uint16
	XoffLim    uint16
	ByteSize   uint8
	Parity     uint8
	StopBits   uint8
	XonChar    uint8
	XoffChar   uint8
	ErrorChar  uint8
	EofChar    uint8
	EvtChar    uint8
	WReserved1 uint16
}

func configureSerialDCB(current serialDCB, settings serialSettings) serialDCB {
	current.DCBlength = uint32(unsafe.Sizeof(serialDCB{}))
	current.BaudRate = settings.baudRate
	current.ByteSize = settings.dataBits
	current.Parity = settings.parity
	current.StopBits = settings.stopBits
	current.Flags = serialFlagBinary
	if settings.parity != serialParityNone {
		current.Flags |= serialFlagParity | serialFlagErrorChar
		current.ErrorChar = serialParityReplace
	} else {
		current.ErrorChar = 0
	}
	current.WReserved = 0
	current.WReserved1 = 0
	return current
}

func openSerialPort(settings serialSettings, api serialNativeAPI) (*serialStream, error) {
	if err := validateSerialSettings(settings); err != nil {
		return nil, err
	}
	path := `\\.\` + settings.portName
	handle, err := api.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", settings.portName, err)
	}
	if handle == windows.InvalidHandle {
		return nil, fmt.Errorf("open %s returned an invalid handle", settings.portName)
	}
	closeOnError := func(primary error) error {
		if closeErr := api.CloseHandle(handle); closeErr != nil {
			return errors.Join(primary, fmt.Errorf("close serial port after setup failure: %w", closeErr))
		}
		return primary
	}

	state := serialDCB{DCBlength: uint32(unsafe.Sizeof(serialDCB{}))}
	if err := api.GetCommState(handle, &state); err != nil {
		return nil, closeOnError(fmt.Errorf("get current communication settings: %w", err))
	}
	state = configureSerialDCB(state, settings)
	if err := api.SetCommState(handle, &state); err != nil {
		return nil, closeOnError(fmt.Errorf("set communication settings: %w", err))
	}
	// Match .NET SerialPort's infinite read timeout for its BaseStream. The
	// MAXDWORD interval sentinel lets ReadFile complete when data arrives,
	// instead of waiting for the full caller buffer to fill.
	timeouts := windows.CommTimeouts{
		ReadIntervalTimeout:         ^uint32(0),
		ReadTotalTimeoutMultiplier:  ^uint32(0),
		ReadTotalTimeoutConstant:    ^uint32(1), // .NET uses -2 to represent infinite.
		WriteTotalTimeoutMultiplier: 0,
		WriteTotalTimeoutConstant:   0,
	}
	if err := api.SetCommTimeouts(handle, &timeouts); err != nil {
		return nil, closeOnError(fmt.Errorf("set communication timeouts: %w", err))
	}
	return &serialStream{api: api, handle: handle, portName: settings.portName, closeDone: make(chan struct{})}, nil
}

type serialStream struct {
	api      serialNativeAPI
	handle   windows.Handle
	portName string

	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
	active    sync.WaitGroup
	readMu    sync.Mutex
	writeMu   sync.Mutex
}

func (s *serialStream) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()

	handle, overlapped, event, err := s.startIO(buffer, false)
	if err != nil {
		return 0, fmt.Errorf("read serial port %s: %w", s.portName, err)
	}
	n, ioErr := s.finishIO(handle, overlapped, event)
	if ioErr != nil {
		return n, fmt.Errorf("read serial port %s: %w", s.portName, s.operationError(ioErr))
	}
	if n == 0 {
		return 0, fmt.Errorf("read serial port %s: %w", s.portName, io.ErrNoProgress)
	}
	return n, nil
}

func (s *serialStream) Write(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	total := 0
	for len(buffer) > 0 {
		chunk := buffer
		if uint64(len(chunk)) > uint64(^uint32(0)) {
			chunk = chunk[:int(^uint32(0))]
		}
		handle, overlapped, event, err := s.startIO(chunk, true)
		if err != nil {
			return total, fmt.Errorf("write serial port %s: %w", s.portName, err)
		}
		n, ioErr := s.finishIO(handle, overlapped, event)
		total += n
		if ioErr != nil {
			return total, fmt.Errorf("write serial port %s: %w", s.portName, s.operationError(ioErr))
		}
		if n == 0 {
			return total, fmt.Errorf("write serial port %s: %w", s.portName, io.ErrNoProgress)
		}
		buffer = buffer[n:]
	}
	return total, nil
}

func (s *serialStream) startIO(buffer []byte, write bool) (windows.Handle, *windows.Overlapped, windows.Handle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, nil, 0, os.ErrClosed
	}
	event, err := s.api.CreateEvent()
	if err != nil {
		return 0, nil, 0, fmt.Errorf("create I/O event: %w", err)
	}
	overlapped := &windows.Overlapped{HEvent: event}
	s.active.Add(1)
	if write {
		err = s.api.WriteFile(s.handle, buffer, overlapped)
	} else {
		err = s.api.ReadFile(s.handle, buffer, overlapped)
	}
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		s.active.Done()
		if closeErr := s.api.CloseHandle(event); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close I/O event: %w", closeErr))
		}
		return 0, nil, 0, err
	}
	return s.handle, overlapped, event, nil
}

func (s *serialStream) finishIO(handle windows.Handle, overlapped *windows.Overlapped, event windows.Handle) (int, error) {
	var transferred uint32
	err := s.api.GetOverlappedResult(handle, overlapped, &transferred, true)
	closeErr := s.api.CloseHandle(event)
	s.active.Done()
	if err != nil && closeErr != nil {
		return int(transferred), errors.Join(err, fmt.Errorf("close I/O event: %w", closeErr))
	}
	if err != nil {
		return int(transferred), err
	}
	if closeErr != nil {
		return int(transferred), fmt.Errorf("close I/O event: %w", closeErr)
	}
	return int(transferred), nil
}

func (s *serialStream) operationError(err error) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed && errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		return os.ErrClosed
	}
	return err
}

func (s *serialStream) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		handle := s.handle
		cancelErr := s.api.CancelIoEx(handle, nil)
		s.mu.Unlock()

		if errors.Is(cancelErr, windows.ERROR_NOT_FOUND) {
			cancelErr = nil
		}
		if cancelErr != nil {
			closeErr := s.api.CloseHandle(handle)
			s.active.Wait()
			if closeErr != nil {
				s.closeErr = errors.Join(cancelErr, fmt.Errorf("close serial port %s: %w", s.portName, closeErr))
			} else {
				s.closeErr = cancelErr
			}
		} else {
			s.active.Wait()
			if err := s.api.CloseHandle(handle); err != nil {
				s.closeErr = fmt.Errorf("close serial port %s: %w", s.portName, err)
			}
		}
		close(s.closeDone)
	})
	<-s.closeDone
	return s.closeErr
}

var (
	serialKernel32     = windows.NewLazySystemDLL("kernel32.dll")
	serialGetCommState = serialKernel32.NewProc("GetCommState")
	serialSetCommState = serialKernel32.NewProc("SetCommState")
	serialReadFile     = serialKernel32.NewProc("ReadFile")
	serialWriteFile    = serialKernel32.NewProc("WriteFile")
)

type systemSerialAPI struct{}

func (systemSerialAPI) CreateFile(path string, access, shareMode, disposition, flags uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, access, shareMode, nil, disposition, flags, 0)
}

func (systemSerialAPI) GetCommState(handle windows.Handle, state *serialDCB) error {
	err := serialBoolCall(serialGetCommState.Call(uintptr(handle), uintptr(unsafe.Pointer(state))))
	runtime.KeepAlive(state)
	return err
}

func (systemSerialAPI) SetCommState(handle windows.Handle, state *serialDCB) error {
	err := serialBoolCall(serialSetCommState.Call(uintptr(handle), uintptr(unsafe.Pointer(state))))
	runtime.KeepAlive(state)
	return err
}

func (systemSerialAPI) SetCommTimeouts(handle windows.Handle, timeouts *windows.CommTimeouts) error {
	return windows.SetCommTimeouts(handle, timeouts)
}

func (systemSerialAPI) CreateEvent() (windows.Handle, error) {
	return windows.CreateEvent(nil, 1, 0, nil)
}

func (systemSerialAPI) ReadFile(handle windows.Handle, buffer []byte, overlapped *windows.Overlapped) error {
	return serialOverlappedCall(serialReadFile, handle, buffer, overlapped)
}

func (systemSerialAPI) WriteFile(handle windows.Handle, buffer []byte, overlapped *windows.Overlapped) error {
	return serialOverlappedCall(serialWriteFile, handle, buffer, overlapped)
}

func (systemSerialAPI) GetOverlappedResult(handle windows.Handle, overlapped *windows.Overlapped, transferred *uint32, wait bool) error {
	return windows.GetOverlappedResult(handle, overlapped, transferred, wait)
}

func (systemSerialAPI) CancelIoEx(handle windows.Handle, overlapped *windows.Overlapped) error {
	return windows.CancelIoEx(handle, overlapped)
}

func (systemSerialAPI) CloseHandle(handle windows.Handle) error {
	return windows.CloseHandle(handle)
}

func serialBoolCall(result uintptr, _ uintptr, callErr error) error {
	if result != 0 {
		return nil
	}
	if callErr == nil || errors.Is(callErr, syscall.Errno(0)) {
		return windows.ERROR_GEN_FAILURE
	}
	return callErr
}

func serialOverlappedCall(proc *windows.LazyProc, handle windows.Handle, buffer []byte, overlapped *windows.Overlapped) error {
	if len(buffer) == 0 {
		return nil
	}
	result, _, callErr := proc.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(uint32(len(buffer))),
		0, // For overlapped I/O, obtain the byte count via GetOverlappedResult.
		uintptr(unsafe.Pointer(overlapped)),
	)
	runtime.KeepAlive(buffer)
	runtime.KeepAlive(overlapped)
	if result != 0 {
		return nil
	}
	if callErr == nil || errors.Is(callErr, syscall.Errno(0)) {
		return windows.ERROR_GEN_FAILURE
	}
	return callErr
}
