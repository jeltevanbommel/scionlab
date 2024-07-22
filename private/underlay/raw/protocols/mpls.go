package protocols

// import (
//
//	"encoding/binary"
//	"net"
//
//	errors "github.com/scionproto/scion/pkg/private/serrors"
//
// )
const (
	MPLS_HDR_LENGTH    = 4
	MPLS_ETHERTYPE_BE  = 0x8847
	MPLS_ETHERTYPE_LE  = 0x4788
	MPLS_TRAFFIC_CLASS = 0x7
	MPLS_TTL           = 254
)

//type MPLSForwardingArguments struct {
//	Label uint32
//}
//
//type MPLS struct {
//	prebakedRecvLabel *uint32
//	prebakedSendLabel *uint32
//}
//
//var _ Protocol = &MPLS{}
//
//func (m *MPLS) Name() string {
//	return "MPLS"
//}
//
//func (m *MPLS) EtherType() (uint16, uint16) {
//	return MPLS_ETHERTYPE_BE, MPLS_ETHERTYPE_LE
//}
//
//func (m *MPLS) ParsePacket(packet []byte) (uint, *net.UDPAddr, error) {
//	// If we have a prebaked connection, check that the incoming packet's top MPLS label matches the
//	// one that is configured for this connection.
//	if m.prebakedRecvLabel != nil {
//		label := binary.NativeEndian.Uint32(packet[0:4]) >> 12
//		if label != *m.prebakedRecvLabel {
//			return 0, nil, errors.New("dropping packet, invalid label", "received",
//				label, "configured", m.prebakedRecvLabel)
//		}
//	}
//	offset := 0
//	// There can be multiple MPLS labels, the bottom one is signalled with the "bottom of stack" bit
//	for len(packet) > offset+2 && (packet[offset+2]&0x1 != 0x1) {
//		offset += 4
//	}
//	if packet[offset+2]&0x1 != 0x1 {
//		return 0, nil, errors.New("dropping packet, could not find bottom of MPLS stack", "p",
//			packet)
//	}
//	offset += 4
//	return uint(offset), nil, nil
//}
//
//func (m *MPLS) AllocateSenderBufs(numBufs int) [][]byte {
//	hdrs := make([][]byte, numBufs)
//	for i := range hdrs {
//		hdrs[i] = make([]byte, m.HeaderLength())
//	}
//	return hdrs
//}
//
//func (m *MPLS) HeaderLength() int {
//	return MPLS_HDR_LENGTH
//}
//
//func (m *MPLS) SerializeHeader(args *ForwardingArgs, hdrBuf []byte, payload []byte) error {
//	var mplsLabel uint32
//	// Prebaked connections do not need arguments, as the sending MPLS label is preconfigured.
//	if m.prebakedSendLabel != nil {
//		mplsLabel = *m.prebakedSendLabel
//	} else {
//		// The connection is not prebaked with a sending MPLS label, fetch it from the arguments.
//		mplsArgs, ok := args.ProtocolArgs.(MPLSForwardingArguments)
//		if !ok {
//			return errors.New("missing or invalid arguments")
//		}
//		mplsLabel = mplsArgs.Label
//	}
//
//	// Construct the MPLS header
//	encoded := mplsLabel << 12
//	encoded |= uint32(MPLS_TRAFFIC_CLASS) << 9
//	encoded |= uint32(MPLS_TTL)
//	encoded |= 0x100 // Stack Bottom (we only support adding 1 MPLS label)
//	binary.BigEndian.PutUint32(hdrBuf, encoded)
//	return nil
//}
//
//func (m *MPLS) Prebake(args map[string]interface{}) error {
//	recvLabel, ok := args["recvLabel"].(uint32)
//	if ok {
//		m.prebakedRecvLabel = &recvLabel
//	}
//
//	sendLabel, ok := args["sendLabel"].(uint32)
//	if ok {
//		m.prebakedRecvLabel = &sendLabel
//	}
//
//	return nil
//}
