package protocols

import (
	"encoding/binary"
	"net"
)

const (
	IPV4_VERSION             = 4
	IPV4_TOS                 = 0
	IPV4_FRAGMENTATION_FLAGS = 0
	IPV4_TTL                 = 64
	UDP_PROTOCOL             = 0x11
	UDP_HDR_LENGTH           = 8

	IPV6_VERSION    = 6
	IPV6_CLASS      = 1
	IPV6_HOP_LIMIT  = 255
	IPV6_FLOW_LABEL = 0
)

func WriteUDPHdr(bytes []byte, payloadBytes []byte, srcAddr, dstAddr *net.UDPAddr, checksum bool) {
	binary.BigEndian.PutUint16(bytes, uint16(srcAddr.Port))
	binary.BigEndian.PutUint16(bytes[2:], uint16(dstAddr.Port))
	binary.BigEndian.PutUint16(bytes[4:], uint16(len(payloadBytes)+UDP_HDR_LENGTH))

	if checksum {
		// Checksum is optional in IPv4
		bytes[6] = 0
		bytes[7] = 0
		binary.BigEndian.PutUint16(bytes[6:], udpChecksum(bytes, payloadBytes, srcAddr.IP, dstAddr.IP))
	}
}

func WriteIPv6Hdr(bytes []byte, payloadBytes []byte, srcAddr, dstAddr *net.IP, protocol byte) {
	bytes[0] = (IPV6_VERSION << 4) | ((IPV6_CLASS >> 4) & 0x0f)     // Version, traffic class[0:4]
	bytes[1] = (IPV6_CLASS << 4) | ((IPV6_FLOW_LABEL >> 16) & 0x0f) // TOS and flow label
	bytes[2] = IPV6_FLOW_LABEL >> 8                                 // Flow label
	bytes[3] = IPV6_FLOW_LABEL                                      // Flow label
	// Payload Length
	binary.BigEndian.PutUint16(bytes[4:], UDP_HDR_LENGTH+uint16(len(payloadBytes)))
	bytes[6] = protocol       //Protocol
	bytes[7] = IPV6_HOP_LIMIT // TTL

	copy(bytes[8:24], srcAddr.To16())  // Source Address
	copy(bytes[24:40], dstAddr.To16()) // Destination Address
}
func WriteIPv4Hdr(bytes []byte, payloadBytes []byte, srcAddr, dstAddr *net.IP, protocol byte) {
	optionLength := 0
	ihl := uint8(5 + (optionLength / 4))
	length := IPV4_HDR_LENGTH + UDP_HDR_LENGTH + uint16(len(payloadBytes))
	bytes[0] = (IPV4_VERSION << 4) | ihl // version,
	// header length
	bytes[1] = IPV4_TOS                                                     // TOS
	binary.BigEndian.PutUint16(bytes[2:], length)                           // total length
	binary.BigEndian.PutUint16(bytes[4:], uint16(0))                        // Identification
	binary.BigEndian.PutUint16(bytes[6:], uint16(IPV4_FRAGMENTATION_FLAGS)) // Fragmentation flags
	bytes[8] = IPV4_TTL                                                     // TTL
	bytes[9] = protocol                                                     //Protocol

	copy(bytes[12:16], srcAddr.To4()) // Source Address
	copy(bytes[16:20], dstAddr.To4()) // Destination Address

	binary.BigEndian.PutUint16(bytes[10:], ip4Checksum(bytes[0:20])) // Checksum
}

func ip4PseudoheaderChecksum(srcAddr, dstAddr net.IP) (csum uint32) {
	csum += (uint32(srcAddr[0]) + uint32(srcAddr[2])) << 8
	csum += uint32(srcAddr[1]) + uint32(srcAddr[3])
	csum += (uint32(dstAddr[0]) + uint32(dstAddr[2])) << 8
	csum += uint32(dstAddr[1]) + uint32(dstAddr[3])
	return csum
}

// TODO(jvanbommel): is Local Checksum Offload of any use here?
func udpChecksum(bytes, payloadBytes []byte, srcAddr, dstAddr net.IP) uint16 {
	length := uint32(len(payloadBytes) + UDP_HDR_LENGTH)
	csum := ip4PseudoheaderChecksum(srcAddr, dstAddr)
	csum += uint32(UDP_PROTOCOL)
	csum += length & 0xffff
	csum += length >> 16

	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}
	for i := 0; i < len(payloadBytes)-1; i += 2 {
		csum += uint32(payloadBytes[i]) << 8
		csum += uint32(payloadBytes[i+1])
	}
	if len(payloadBytes)%2 == 1 {
		csum += uint32(payloadBytes[len(payloadBytes)-1]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

func ip4Checksum(bytes []byte) uint16 {
	bytes[10] = 0
	bytes[11] = 0

	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
