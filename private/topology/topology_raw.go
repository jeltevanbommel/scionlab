package topology

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/scionproto/scion/pkg/private/serrors"
	jsontopo "github.com/scionproto/scion/private/topology/json"
	"github.com/scionproto/scion/private/underlay/raw/protocols"
)

const (
	RAW_MPLS_IP_UDP_UNDERLAY = "raw_mplsipudp"
	RAW_ETHERNET_UNDERLAY    = "raw_eth"
	IP_UDP_UNDERLAY          = "ipudp"
)

type InternalUnderlayIdentifier struct {
	IntfIndex uint16 // sw interface
	Protocol  protocols.ProtocolType
	Label     uint32
}
type ExternalUnderlayInfo struct {
	Type            protocols.ProtocolType
	LocalIp         netip.AddrPort
	RemoteIp        netip.AddrPort
	NextHop         net.HardwareAddr
	HwInterfaceName string
	MplsLabel       uint32
}

func (i ExternalUnderlayInfo) String() string {
	return fmt.Sprintf("ExternalUnderlayInfo{Type: %d, LocalIp: %+v, RemoteIp: %+v, "+
		" NextHop: %s, HwInterfaceName: %s, MplsLabel: %d}",
		i.Type, i.LocalIp, i.RemoteIp, i.NextHop, i.HwInterfaceName, i.MplsLabel)
}

// tostring for internal underlay info
type InternalUnderlayInfo struct {
	// The type of the underlay, i.e. raw_mplsipudp, raw_dot1q, raw_ethernet
	Type            protocols.ProtocolType
	LocalIp         netip.AddrPort
	RemoteIp        netip.AddrPort
	NextHop         net.HardwareAddr
	HwInterfaceName string
	// Optional, used for MPLS, a map mapping the labels this connection supports to the next hop
	// MAC addresses for each of these labels.
	Labels map[uint32]net.HardwareAddr
}

// InternalUnderlaysFromJSON parses the alternative underlays from the JSON representation given in
// jsonUnderlays. The asInternal bool signals that the configuration is parsed for AS internal
// underlays (true), rather than border router to border router links (false).
func InternalUnderlaysFromJson(jsonUnderlays []jsontopo.InternalUnderlay) ([]InternalUnderlayInfo,
	error) {
	aus := make([]InternalUnderlayInfo, len(jsonUnderlays))
	// Parse each of the alternative underlays
	for i, jsonAu := range jsonUnderlays {
		var au InternalUnderlayInfo
		var err error
		// Based on the type parse the specific underlay
		switch jsonAu.Type {
		case RAW_MPLS_IP_UDP_UNDERLAY:
			au, err = mplsIpUdpIntUnderlayFromJson(jsonAu)
		case RAW_ETHERNET_UNDERLAY:
			au, err = ethernetIntUnderlayFromJson(jsonAu)
		case IP_UDP_UNDERLAY:
		default:
			return []InternalUnderlayInfo{},
				serrors.New("Unknown internal underlay type: " + jsonAu.Type)
		}
		if err != nil {
			return []InternalUnderlayInfo{}, serrors.WrapStr("parsing alt underlay", err)
		}
		aus[i] = au
	}
	return aus, nil
}

func ethernetIntUnderlayFromJson(underlay jsontopo.InternalUnderlay) (InternalUnderlayInfo,
	error) {
	au := InternalUnderlayInfo{}
	au.Type = protocols.ETHERNET
	if underlay.Interface == "" {
		return InternalUnderlayInfo{}, serrors.New("Hardware interface property not set",
			"interface", underlay.Interface)
	}
	if underlay.NextHop != "" {
		return InternalUnderlayInfo{},
			serrors.New("Next Hop value set for internal ETH underlay, this property is ignored.",
				"interface", underlay.Interface)
	}
	// TODO(jvanbommel): register the next hops per intf.
	au.HwInterfaceName = underlay.Interface
	return au, nil
}

func mplsIpUdpIntUnderlayFromJson(underlay jsontopo.InternalUnderlay) (InternalUnderlayInfo,
	error) {
	au := InternalUnderlayInfo{}
	var err error
	au.Type = protocols.MPLS_IP_UDP
	if underlay.Interface == "" {
		return InternalUnderlayInfo{}, serrors.New("Hardware interface property not set",
			"interface", underlay.Interface)
	}
	if au.LocalIp, err = resolveAddrPort(underlay.Local); err != nil {
		return InternalUnderlayInfo{}, serrors.WrapStr("unable to extract "+
			"internal underlay data-plane local ip address", err,
			"underlay", underlay.Type)
	}
	if au.RemoteIp, err = resolveAddrPort(underlay.Remote); err != nil {
		return InternalUnderlayInfo{}, serrors.WrapStr("unable to extract "+
			"internal underlay data-plane remote ip address", err,
			"underlay", underlay.Type)
	}
	if underlay.NextHop != "" {
		return InternalUnderlayInfo{},
			serrors.New("Next Hop value set for internal MPLS underlay, this property is ignored.",
				"interface", underlay.Interface)
	}
	au.HwInterfaceName = underlay.Interface
	au.Labels = make(map[uint32]net.HardwareAddr, len(underlay.MplsNextHops))
	for label, nh := range underlay.MplsNextHops {
		if au.Labels[label], err = net.ParseMAC(nh); err != nil {
			return InternalUnderlayInfo{}, serrors.WrapStr("unable to extract "+
				"internal underlay mpls next hop address", err,
				"address", underlay.Remote, "label", label)
		}
	}
	return au, nil
}

// InternalUnderlaysFromJSON parses the alternative underlays from the JSON representation given in
// jsonUnderlays. The asInternal bool signals that the configuration is parsed for AS internal
// underlays (true), rather than border router to border router links (false).
func ExternalUnderlayFromJson(jsonUnderlay jsontopo.ExternalUnderlay) (ExternalUnderlayInfo,
	error) {
	var eu ExternalUnderlayInfo
	var err error
	// Based on the type parse the specific underlay
	switch jsonUnderlay.Type {
	case RAW_MPLS_IP_UDP_UNDERLAY:
		eu, err = mplsIpUdpExtUnderlayFromJson(jsonUnderlay)
	case RAW_ETHERNET_UNDERLAY:
		eu, err = ethernetExtUnderlayFromJson(jsonUnderlay)
	case IP_UDP_UNDERLAY, "":
		eu, err = defaultIpUdpExtUnderlayFromJson(jsonUnderlay)
	default:
		return ExternalUnderlayInfo{},
			serrors.New("Unknown internal underlay type: " + jsonUnderlay.Type)
	}
	return eu, err
}
func ethernetExtUnderlayFromJson(underlay jsontopo.ExternalUnderlay) (ExternalUnderlayInfo,
	error) {
	au := ExternalUnderlayInfo{}
	var err error
	au.Type = protocols.ETHERNET
	if underlay.Interface == "" {
		return ExternalUnderlayInfo{}, serrors.New("Hardware interface property not set",
			"interface", underlay.Interface)
	}
	au.HwInterfaceName = underlay.Interface
	if au.NextHop, err = net.ParseMAC(underlay.NextHop); err != nil {
		return ExternalUnderlayInfo{}, serrors.WrapStr("unable to extract "+
			"internal underlay eth next hop address", err,
			"address", underlay.Remote, "label", underlay.MplsLabel)
	}
	return au, nil
}

func mplsIpUdpExtUnderlayFromJson(underlay jsontopo.ExternalUnderlay) (ExternalUnderlayInfo,
	error) {
	au := ExternalUnderlayInfo{}
	var err error
	au.Type = protocols.MPLS_IP_UDP
	if underlay.Interface == "" {
		return ExternalUnderlayInfo{}, serrors.New("Hardware interface property not set",
			"interface", underlay.Interface)
	}
	if au.LocalIp, err = resolveAddrPort(underlay.Local); err != nil {
		return ExternalUnderlayInfo{}, serrors.WrapStr("unable to extract "+
			"internal underlay data-plane local ip address", err,
			"underlay", underlay.Type)
	}
	if au.RemoteIp, err = resolveAddrPort(underlay.Remote); err != nil {
		return ExternalUnderlayInfo{}, serrors.WrapStr("unable to extract "+
			"internal underlay data-plane remote ip address", err,
			"underlay", underlay.Type)
	}
	au.HwInterfaceName = underlay.Interface
	au.MplsLabel = underlay.MplsLabel
	if au.NextHop, err = net.ParseMAC(underlay.NextHop); err != nil {
		return ExternalUnderlayInfo{}, serrors.WrapStr("unable to extract "+
			"internal underlay mpls next hop address", err,
			"address", underlay.Remote, "label", underlay.MplsLabel)
	}
	return au, nil
}

func defaultIpUdpExtUnderlayFromJson(underlay jsontopo.ExternalUnderlay) (ExternalUnderlayInfo,
	error) {
	au := ExternalUnderlayInfo{}
	var err error
	au.Type = protocols.DEFAULT_IP_UDP

	if au.LocalIp, err = rawBRIntfLocalAddr(&underlay); err != nil {
		return ExternalUnderlayInfo{}, serrors.WrapStr("unable to extract "+
			"underlay external data-plane local address", err)
	}
	if au.RemoteIp, err = resolveAddrPort(underlay.Remote); err != nil {
		return ExternalUnderlayInfo{}, serrors.WrapStr("unable to extract "+
			"underlay external data-plane remote address", err)
	}
	return au, nil
}
