package protocols

import (
	"net"

	"github.com/scionproto/scion/private/underlay/raw"
)

type Ethernet struct {
	intf uint16
}

const (
	SCION_ETHERTYPE_BE = 0x7363 // SC in ascii
	SCION_ETHERTYPE_LE = 0x6373
)

func (m *Ethernet) RequiresUDPSourceValidation() bool {
	return false //TODO(jvanbommel) temp.
}

var _ raw.Protocol = &Ethernet{}

func (m *Ethernet) Name() string {
	return "Ethernet"
}

func (m *Ethernet) EtherType() (uint16, uint16) {
	return SCION_ETHERTYPE_BE, SCION_ETHERTYPE_LE
}

func (m *Ethernet) ParsePacket(packet []byte) (uint, *net.UDPAddr, uint16, error) {
	return 0, nil, m.intf, nil
}

func (m *Ethernet) AllocateSenderBufs(numBufs int) [][]byte {
	hdrs := make([][]byte, numBufs)
	for i := range hdrs {
		hdrs[i] = make([]byte, max(1, m.HeaderLength()))
	}
	return hdrs
}

func (m *Ethernet) HeaderLength() int {
	return 0
}

func (m *Ethernet) Serializer(sendOpts *raw.SendingOptions) raw.SerializeFn {
	pOk := sendOpts != nil
	return func(args *raw.ForwardingArgs, hdrBuf []byte, payload []byte) (int, error) {
		// Overwrite the next hop link layer address with the initial one, if defined:
		if pOk && sendOpts.NextHopMac != nil {
			args.NextHopLL = sendOpts.NextHopMac
		}
		return 0, nil
	}
}

func (m *Ethernet) Register(swIfId uint16, options *raw.RegisterOptions) error {
	//TODO(jvanbommel): Handle multiple senders to the same receiver (i.e.
	// pass the sockaddr through to the ParsePacket function, which will compare it with registered
	// ones and then return the corresponding intf.)
	m.intf = swIfId
	return nil
}
