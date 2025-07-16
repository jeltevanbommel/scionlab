package protocols

import (
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/underlay/raw"
)

type ProtocolType int

const (
	NONE ProtocolType = iota
	DEFAULT_IP_UDP
	ETHERNET
	MPLS_IP_UDP
	MPLS_RAW
	DOT1Q //TODO(jvanbommel) Implement
)

func NewProtoFromType(protocolType ProtocolType) (raw.Protocol, error) {
	switch protocolType {
	case MPLS_IP_UDP:
		return &MPLSIPUDP{}, nil
	case ETHERNET:
		return &Ethernet{}, nil
	default:
		return nil, serrors.New("Unconfigured protocol type", "protocol", protocolType)
	}
}
