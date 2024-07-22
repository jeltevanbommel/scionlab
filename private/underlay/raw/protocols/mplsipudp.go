package protocols

import (
	"encoding/binary"
	"net"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	errors "github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/underlay/raw"
)

const (
	IPV4_HDR_LENGTH = 20
	IPV6_HDR_LENGTH = 40
)

type MPLSIPv4UDPForwardingArguments struct {
	Label              uint32
	SourceAddress      *net.UDPAddr
	DestinationAddress *net.UDPAddr
}

type connection struct {
	srcIp   string
	srcPort int
	dstIp   string
	dstPort int
}

type listener struct {
	ip   string
	port int
}

type MPLSIPUDP struct {
	connections map[connection]uint16
	listeners   map[listener]uint16
}

func (m *MPLSIPUDP) RequiresUDPSourceValidation() bool {
	return false //TODO(jvanbommel) temp.
}

var _ raw.Protocol = &MPLSIPUDP{}

func (m *MPLSIPUDP) Name() string {
	return "MPLSIPUDP"
}

func (m *MPLSIPUDP) EtherType() (uint16, uint16) {
	return MPLS_ETHERTYPE_BE, MPLS_ETHERTYPE_LE
}

func (m *MPLSIPUDP) ParsePacket(packet []byte) (uint, *net.UDPAddr, error) {
	// If we have a prebaked connection, check that the incoming packet's top MPLS label matches the
	// one that is configured for this connection.
	//if m.prebakedRecvLabel != nil {
	//	label := binary.NativeEndian.Uint32(packet[0:4]) >> 12
	//	if label != *m.prebakedRecvLabel {
	//		return 0, nil, errors.New("dropping packet, invalid label", "received",
	//			label, "configured", m.prebakedRecvLabel)
	//	}
	//}
	offset := 0
	// There can be multiple MPLS labels, the bottom one is signalled with the "bottom of stack" bit
	for len(packet) > offset+2 && (packet[offset+2]&0x1 != 0x1) {
		offset += 4
	}
	if packet[offset+2]&0x1 != 0x1 {
		return 0, nil, errors.New("dropping packet, could not find bottom of MPLS stack", "p",
			packet)
	}
	offset += MPLS_HDR_LENGTH
	var protocol int
	var ipHdrLen int
	var ipSrc, ipDst net.IP
	// Check if this packet is IPv4
	version := packet[offset] & 0b1111000
	if version == 0x40 {
		// Parse IPv4 header
		ipHdrLen = int(packet[offset]&0x0f) << 2
		protocol = int(packet[offset+9])
		//ipSrc := packet[offset+12 : offset+15]
		//ipDst := packet[offset+16 : offset+19]
		//Store as a IPv6 address:
		ipSrc = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, packet[offset+12],
			packet[offset+13], packet[offset+14], packet[offset+15]}
		ipDst = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, packet[offset+16],
			packet[offset+17], packet[offset+18], packet[offset+19]}
		// Prevent allocations, otherwise:
		//ipHdr, err := ipv4.ParseHeader(packet[offset:])
		//if err != nil {
		//	return 0, nil, errors.WrapStr("dropping packet, could not parse ipv4 hdr: ", err)
		//}
	} else if version == 0x60 {
		ipHdr, err := ipv6.ParseHeader(packet[offset:])
		if err != nil {
			return 0, nil, errors.WrapStr("dropping packet, could not parse ipv6 hdr: ", err)
		}
		protocol = ipHdr.NextHeader
		ipSrc = ipHdr.Src
		ipDst = ipHdr.Dst
		ipHdrLen = IPV6_HDR_LENGTH
	} else {
		return 0, nil, errors.New("dropping packet, not ipv4 or ipv6")
	}

	offset += ipHdrLen
	// Check if the packet uses UDP
	if protocol != UDP_PROTOCOL {
		// TODO(jvanbommel): Support extensions or when nexthdr is SCION
		return 0, nil, errors.New("dropping packet, receiver is IPv4/UDP, no UDP header found",
			"nh", protocol)
	}
	//Parse the UDP header dst port
	srcPort := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	dstPort := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
	offset += UDP_HDR_LENGTH
	// Check if the packet was directed at the local ip for a prebaked connection

	var intf uint16
	var ok bool

	if m.connections != nil {
		intf, ok = m.connections[connection{string(ipSrc), srcPort, string(ipDst),
			dstPort}]
	}
	if !ok && m.listeners != nil {
		intf, ok = m.connections[connection{string(ipSrc), srcPort, string(ipDst),
			dstPort}]
	}
	if !ok {
		return 0, nil, errors.New("dropping packet, dst ip addr is not local ip: ",
			"received", ipDst, "received port", dstPort)
	}
	//TODO(jvanbommel): handover ingress
	_ = intf
	return uint(offset), &net.UDPAddr{IP: ipSrc, Port: srcPort}, nil
}

func (m *MPLSIPUDP) AllocateSenderBufs(numBufs int) [][]byte {
	hdrs := make([][]byte, numBufs)
	for i := range hdrs {
		hdrs[i] = make([]byte, m.HeaderLength())
	}
	return hdrs
}

func (m *MPLSIPUDP) HeaderLength() int {
	return MPLS_HDR_LENGTH + max(IPV4_HDR_LENGTH, IPV6_HDR_LENGTH) + UDP_HDR_LENGTH
}

type MPLSIPv4UDPPrebakeArgs struct {
	PrebakedSendLabel  *uint32
	PrebakedDstIPAddr  *net.UDPAddr
	PrebakedSrcIPAddr  *net.UDPAddr
	PrebakedDstMACAddr *unix.RawSockaddrLinklayer
}

func (m *MPLSIPUDP) Prebake(prebakeArgs interface{}) raw.SendingFunc {
	pArgs, pOk := prebakeArgs.(MPLSIPv4UDPPrebakeArgs)
	return func(args *raw.ForwardingArgs, hdrBuf []byte, payload []byte) (int, error) {
		var src *net.UDPAddr
		var dst *net.UDPAddr
		fwArgs, ok := args.ProtocolArgs.(MPLSIPv4UDPForwardingArguments)
		// Use the prebaked source IP address if defined
		if pOk && pArgs.PrebakedSrcIPAddr != nil {
			src = pArgs.PrebakedSrcIPAddr
		} else if ok && fwArgs.SourceAddress != nil { // No prebaked source, use the IP from the fw args
			src = fwArgs.SourceAddress
		} else {
			return 0, errors.New("missing or invalid arguments: source address is not defined")
		}

		if pOk && pArgs.PrebakedDstIPAddr != nil { // Similar for destination, use prebaked if defined
			dst = pArgs.PrebakedDstIPAddr
		} else if ok && fwArgs.DestinationAddress != nil { // Otherwise use IP from fw args
			dst = fwArgs.DestinationAddress
		} else {
			return 0, errors.New("missing or invalid arguments: destination address is not defined")
		}
		ipv6 := len(src.IP) == net.IPv6len || len(dst.IP) == net.IPv6len

		if ipv6 {
			// Write the UDP header
			WriteUDPHdr(hdrBuf[IPV6_HDR_LENGTH+MPLS_HDR_LENGTH:], payload, src, dst, true)
			// Write the IPv6 header
			WriteIPv6Hdr(hdrBuf[MPLS_HDR_LENGTH:], payload, &src.IP, &dst.IP, byte(UDP_PROTOCOL))
		} else {
			// Write the UDP header
			WriteUDPHdr(hdrBuf[IPV4_HDR_LENGTH+MPLS_HDR_LENGTH:], payload, src, dst, true)
			// Write the IPv4 header
			WriteIPv4Hdr(hdrBuf[MPLS_HDR_LENGTH:], payload, &src.IP, &dst.IP, byte(UDP_PROTOCOL))
		}

		var mplsLabel uint32
		// Prebaked connections do not need arguments, as the sending MPLS label is preconfigured.
		if pOk && pArgs.PrebakedSendLabel != nil {
			mplsLabel = *pArgs.PrebakedSendLabel
		} else if ok {
			mplsLabel = fwArgs.Label
		}
		// Construct the MPLS header
		encoded := mplsLabel << 12
		encoded |= uint32(MPLS_TRAFFIC_CLASS) << 9
		encoded |= uint32(MPLS_TTL)
		encoded |= 0x100 // Stack Bottom (we only support adding 1 MPLS label)
		binary.BigEndian.PutUint32(hdrBuf[0:], encoded)

		// Overwrite the next hop link layer address with the prebaked one, if defined:
		if pOk && pArgs.PrebakedDstMACAddr != nil {
			args.NextHopLL = pArgs.PrebakedDstMACAddr
		}
		if ipv6 {
			return MPLS_HDR_LENGTH + IPV6_HDR_LENGTH + UDP_HDR_LENGTH, nil
		}
		return MPLS_HDR_LENGTH + IPV4_HDR_LENGTH + UDP_HDR_LENGTH, nil

	}
}

// TODO(jvanbommel): or refactor to something WithDstIP(), WithSrcIP(), WithDstMAC() etc.
func (m *MPLSIPUDP) NewPrebakeArgs(args map[string]interface{}) raw.PrebakeArgs {
	pArgs := MPLSIPv4UDPPrebakeArgs{}
	//recvLabel, ok := args["recvLabel"].(uint32)
	//if ok {
	//	pArgs.PrebakedRecvLabel = &recvLabel
	//}

	sendLabel, ok := args["sendLabel"].(uint32)
	if ok {
		pArgs.PrebakedSendLabel = &sendLabel
	}

	srcIPAddr, ok := args["srcIPAddr"].(net.UDPAddr)
	if ok {
		pArgs.PrebakedSrcIPAddr = &srcIPAddr
	}

	dstIPAddr, ok := args["dstIPAddr"].(net.UDPAddr)
	if ok {
		pArgs.PrebakedDstIPAddr = &dstIPAddr
	}

	dstMACAddr, ok := args["dstMACAddr"].(unix.RawSockaddrLinklayer)
	if ok {
		pArgs.PrebakedDstMACAddr = &dstMACAddr
	}

	return pArgs
}

func (m *MPLSIPUDP) Register(swIfId uint16, info raw.LinkInfo) error {
	// Register as IPv6 by default to prevent issues in ipv6?
	if info.Local.Addr == nil {
		return errors.New("missing local address")
	}
	if info.Remote.Addr == nil {
		if m.listeners == nil {
			m.listeners = make(map[listener]uint16)
		}
		m.listeners[listener{
			ip:   string(info.Local.Addr.IP.To16()),
			port: info.Local.Addr.Port,
		}] = swIfId
	} else {
		if m.connections == nil {
			m.connections = make(map[connection]uint16)
		}
		m.connections[connection{
			srcIp:   string(info.Remote.Addr.IP.To16()),
			srcPort: info.Remote.Addr.Port,
			dstIp:   string(info.Local.Addr.IP.To16()),
			dstPort: info.Local.Addr.Port,
		}] = swIfId
	}
	return nil
}
