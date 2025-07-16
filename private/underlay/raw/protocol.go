package raw

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/log"
)

type Protocol interface {
	// Name Returns the name of the protocol in human-readable form
	Name() string
	// EtherType returns the value that is used in the Ethernet Header to indicate which protocol is
	// encapsulated in the Ethernet frame. The first return value is in big endian, whereas the
	// second value is in little endian byte order.
	EtherType() (uint16, uint16)
	// ParsePacket parses the headers specific to this protocol from the raw packet. The function
	// returns the offset to the SCION common packet header, as well as the UDP source address if
	// the underlay has an IP/UDP component. Errors when the packet is not parseable with this
	// protocol.
	ParsePacket(packet []byte) (uint, *net.UDPAddr, uint16, error)
	// AllocateSenderBufs allocates buffers that are necessary to serialize the header of this
	// specific protocol. This will typically be used to allocate the buffers to send one batch
	// of packets.
	AllocateSenderBufs(numBufs int) [][]byte
	// HeaderLength returns the maximum length of the header for this protocol.
	HeaderLength() int
	// Serializer creates a serialization function that serializes the protocol's header to a
	// provided/byte array. Mandatory options can differ between protocol,
	// check that the call to this method satisfies the requirements of the specific protocol.
	// Initial sending options take precedence over options specified at the time of calling the
	// sending function.
	Serializer(sendingOptions *SendingOptions) SerializeFn
	// RequiresUDPSourceValidation returns whether the protocol uses a UDP address
	// of which the sender must be verified.
	RequiresUDPSourceValidation() bool
	// Register registers a software link to the protocol, i.e. a specific src IP, port, dst IP,
	// dst port that belongs to a specific sofware interface id.
	Register(swIfId uint16, options *RegisterOptions) error
}

type ForwardingArgs struct {
	// The next hop's address on the link layer. In IP/UDP based protocols these can be retrieved
	// via mechanisms such as ARP.
	NextHopLL *unix.RawSockaddrLinklayer
	// The protocol's specific forwarding arguments that are used when serializing the header.
	// TODO(jvanbommel): make these also options. ForwardingOptions
	ProtocolArgs interface{}
}

// SerializeFn returns the HeaderLength and an error
type SerializeFn func(args *ForwardingArgs, hdrBuf []byte, payload []byte) (int, error)

func GetInterfaceByIP(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		log.Info("Interface", "iface", iface.Name, "addrs", addrs)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.Contains(ip) {
				return &iface, nil
			}
		}
	}
	return nil, errors.New(fmt.Sprintf("No interface was found for the IP %s", ip.String()))
}

type SendingOptions struct {
	DstIPAddr     *net.UDPAddr
	SrcIPAddr     *net.UDPAddr
	NextHopMac    *unix.RawSockaddrLinklayer
	MplsSendLabel *uint32
	MplsNextHops  map[uint32]*unix.RawSockaddrLinklayer
}

// TODO(jvanbommel): make like path.go options?

func NewSendingOptions() *SendingOptions {
	return &SendingOptions{}
}
func (o *SendingOptions) WithNextHopMac(mplsNextHop *unix.RawSockaddrLinklayer) *SendingOptions {
	o.NextHopMac = mplsNextHop
	return o
}
func (o *SendingOptions) WithDstIpAddr(ip *net.UDPAddr) *SendingOptions {
	o.DstIPAddr = ip
	return o
}
func (o *SendingOptions) WithSrcIpAddr(ip *net.UDPAddr) *SendingOptions {
	o.SrcIPAddr = ip
	return o
}
func (o *SendingOptions) WithMplsSendLabel(label *uint32) *SendingOptions {
	o.MplsSendLabel = label
	return o
}
func (s *SendingOptions) WithMplsNextHops(mplsNextHop map[uint32]*unix.
	RawSockaddrLinklayer) *SendingOptions {
	s.MplsNextHops = mplsNextHop
	return s
}

type RegisterOptions struct {
	LocalIp  *net.UDPAddr
	RemoteIp *net.UDPAddr
}

func NewRegisterOptions() *RegisterOptions {
	return &RegisterOptions{}
}

func (r *RegisterOptions) WithLocalIp(ip *net.UDPAddr) *RegisterOptions {
	r.LocalIp = ip
	return r
}

func (r *RegisterOptions) WithRemoteIp(ip *net.UDPAddr) *RegisterOptions {
	r.RemoteIp = ip
	return r
}
