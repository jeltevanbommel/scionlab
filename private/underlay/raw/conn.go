package raw

import (
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	errors "github.com/scionproto/scion/pkg/private/serrors"
)

const SOCKETNAME = "scn_raw_sock"

// Conn describes the API for an underlay socket
type Conn interface {
	Protocol() Protocol
	ReadFrom([]byte) (int, unix.Sockaddr, error)
	ReadBatch([]Mmsghdr) (int, error)
	Write([]byte) (int, error)
	WriteTo([]byte, unix.Sockaddr) (int, error)
	WriteBatch([]Mmsghdr, int) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SetDeadline(time.Time) error
	Close() error
}

var _ Conn = RawSocketConn{}

type RawSocketConn struct {
	protocol Protocol
	f        *os.File
	c        syscall.RawConn
}

func New(intfIndex int, protocol Protocol) (RawSocketConn, error) {
	if runtime.GOOS != "linux" {
		return RawSocketConn{}, errors.New("Raw underlay is only supported on linux targets.")
	}
	proto, protoNs := protocol.EtherType()
	// Open a (non-IP) socket
	s, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		int(proto))
	if err != nil {
		return RawSocketConn{}, errors.WrapStr("Could not open raw underlay socket: ", err)
	}

	// Obtain a file descriptor for the opened socket
	f := os.NewFile(uintptr(s), SOCKETNAME)
	if f == nil {
		_ = unix.Close(s)
		return RawSocketConn{}, errors.New("Could not open raw underlay socket: invalid file descriptor")
	}

	// Get the raw socket connection
	c, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return RawSocketConn{}, err
	}

	// Bind the socket to the interface
	var bindErr error
	addr := &unix.SockaddrLinklayer{
		Protocol: protoNs,
		Ifindex:  intfIndex,
	}
	if err := c.Control(func(fd uintptr) {
		bindErr = unix.Bind(int(fd), addr)
	}); err != nil {
		return RawSocketConn{}, errors.WrapStr("Error occurred when executing socket control function: ", err)
	}
	if bindErr != nil {
		return RawSocketConn{}, errors.WrapStr("Binding raw underlay failed:", bindErr)
	}

	return RawSocketConn{f: f, c: c, protocol: protocol}, nil
}

func (m RawSocketConn) ReadFrom(bytes []byte) (n int, addr unix.Sockaddr, err error) {
	// For performance optimization we could opt to remove passing in the function, and rather just
	// have a constant function for recvfrom etc. The downside would be that we can no longer return the exact
	// cause of an error if an error happens.
	var readErr error
	if err = m.c.Read(func(fd uintptr) (done bool) {
		n, addr, readErr = unix.Recvfrom(int(fd), bytes, unix.MSG_DONTWAIT)
		return readErr == nil
	}); err != nil {
		return 0, nil, err
	}
	if readErr != nil {
		err = errors.WrapStr("Receiving from raw socket: ", readErr)
	}
	return n, addr, err
}

func (m RawSocketConn) ReadBatch(messages []Mmsghdr) (int, error) {
	var readErr error
	var n uintptr
	if err := m.c.Read(func(fd uintptr) (done bool) {
		var errno syscall.Errno
		n, _, errno = unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&messages[0])),
			uintptr(len(messages)), uintptr(unix.MSG_DONTWAIT), 0, 0)
		if errno == 0 { // Reset the readerr, it can already be set due to previous retries.
			readErr = nil
		} else {
			readErr = errno
		}
		return !(readErr != nil && errno.Temporary())
	}); err != nil {
		return 0, err
	}
	if readErr != nil {
		return int(n), errors.WrapStr("Reading from raw socket: ", readErr)
	}
	return int(n), nil
}
func (m RawSocketConn) Write(bytes []byte) (int, error) {
	return m.f.Write(bytes)
}

func (m RawSocketConn) WriteTo(bytes []byte, addr unix.Sockaddr) (n int, err error) {
	var writeErr error
	if err = m.c.Write(func(fd uintptr) (done bool) {
		n, writeErr = unix.SendmsgN(int(fd), bytes, []byte{}, addr, unix.MSG_DONTWAIT)
		e, ok := writeErr.(unix.Errno)
		return !ok || !e.Temporary()
	}); err != nil {
		return 0, err
	}
	if writeErr != nil {
		err = errors.WrapStr("Writing to raw socket: ", writeErr)
	}
	return n, err
}

func (m RawSocketConn) WriteBatch(messages []Mmsghdr, flags int) (int, error) {
	var writeErr error
	var n uintptr
	if err := m.c.Write(func(fd uintptr) (done bool) {
		var errno unix.Errno
		n, _, errno = unix.Syscall6(unix.SYS_SENDMMSG, fd, uintptr(unsafe.Pointer(&messages[0])),
			uintptr(len(messages)), uintptr(flags|unix.MSG_DONTWAIT), 0, 0)
		if errno != 0 {
			writeErr = errno
		}
		return !errno.Temporary()
	}); err != nil {
		return 0, err
	}
	if writeErr != nil {
		return int(n), errors.WrapStr("Writing to raw socket: ", writeErr)
	}
	return int(n), nil
}

func (m RawSocketConn) SetReadDeadline(t time.Time) error {
	return m.f.SetReadDeadline(t)
}

func (m RawSocketConn) SetWriteDeadline(t time.Time) error {
	return m.f.SetWriteDeadline(t)
}

func (m RawSocketConn) SetDeadline(t time.Time) error {
	return m.f.SetDeadline(t)
}

func (m RawSocketConn) Close() error {
	return m.f.Close()
}

func (m RawSocketConn) Protocol() Protocol {
	return m.protocol
}
