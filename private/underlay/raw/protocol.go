package raw

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/private/topology"
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
	ParsePacket(packet []byte) (uint, *net.UDPAddr, error)
	// AllocateSenderBufs allocates buffers that are necessary to serialize the header of this
	// specific protocol. This will typically be used to allocate the buffers to send one batch
	// of packets.
	AllocateSenderBufs(numBufs int) [][]byte
	// HeaderLength returns the maximum length of the header for this protocol.
	HeaderLength() int
	// Prebake creates a sender function that serializes the protocol's header to a provided byte
	// array. Arguments can differ between protocol, check that the call to this method satisfies
	// the requirements of the specific protocol.
	Prebake(prebakeArgs interface{}) SendingFunc
	// RequiresUDPSourceValidation returns whether the protocol uses a UDP address
	// of which the sender must be verified.
	RequiresUDPSourceValidation() bool
	// NewPrebakeArgs Constructs new arguments to pass to the Prebake method.
	NewPrebakeArgs(args map[string]interface{}) PrebakeArgs
	// Register registeres a software link to the protocol, i.e. a specific src IP, port, dst IP,
	// dst port that belongs to a specific sofware interface id.
	Register(swIfId uint16, info LinkInfo) error
}

// LinkInfo contains the information about a link between an internal and
// external router.
type LinkInfo struct {
	Local  LinkEnd
	Remote LinkEnd
	LinkTo topology.LinkType
	MTU    int
}

// LinkEnd represents one end of a link.
type LinkEnd struct {
	IA   addr.IA
	Addr *net.UDPAddr
	IFID common.IFIDType
}

type ForwardingArgs struct {
	// The next hop's address on the link layer. In IP/UDP based protocols these can be retrieved
	// via mechanisms such as ARP.
	NextHopLL *unix.RawSockaddrLinklayer
	// The protocol's specific forwarding arguments that are used when serializing the header.
	ProtocolArgs interface{}
}

type PrebakeArgs interface{}

type ProtocolType int

const (
	NONE ProtocolType = iota
	MPLS_IP_UDP
	MPLS_RAW
	DOT1Q //TODO(jvanbommel) Implement
	SCION //TODO(jvanbommel) Implement
)

// SendingFunc returns the HeaderLength and an error
type SendingFunc func(args *ForwardingArgs, hdrBuf []byte, payload []byte) (int, error)

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
