package control

import (
	"net"

	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/underlay/raw"
	"github.com/scionproto/scion/private/underlay/raw/protocols"
)

func confInternalAltUnderlays(dp Dataplane, cfg *Config) error {
	// for each alternative underlay:
	for _, underlay := range cfg.BR.AltUnderlays {
		infoMap := cfg.Topo.IFInfoMap()
		for ifid := range infoMap {
			_, owned := cfg.BR.IFs[ifid]
			if !owned {
				// This is an external interface on another border router that is internal to our AS.
				// Since we can reach this border router (likely) via the alternate internal interfaces
				// we initiate a connection for each alternate interface.
				if err := confAltIntUnderlay(ifid, infoMap, dp, underlay); err != nil {
					return err
				}
			}
		}
		// Configure the underlay for interface 0, which is for all traffic to end hosts in this AS.
		if err := confAltIntUnderlay(0, infoMap, dp, underlay); err != nil {
			return err
		}
	}
	return nil
}
func confAltIntUnderlay(ifid common.IFIDType, iface topology.IfInfoMap, dp Dataplane, underlay topology.InternalUnderlayInfo) error {
	var err error
	switch underlay.Type {
	case protocols.MPLS_IP_UDP:
		err = confMplsIpUdpIntUnderlay(ifid, iface, dp, underlay)
	case protocols.ETHERNET:
		return serrors.New("Unsupported ethernet internal underlay")
	default:
		return serrors.New("Unknown iface underlay type ", "iface", iface)
	}
	if err != nil {
		return err
	}
	return nil
}
func confAltExtUnderlay(iface topology.IFInfo, dp Dataplane) error {
	var err error
	switch iface.Underlay.Type {
	case protocols.MPLS_IP_UDP:
		err = confMplsIpUdpExtUnderlay(iface, dp)
	case protocols.ETHERNET:
		err = confEthernetExtUnderlay(iface, dp)
	default:
		return serrors.New("Unknown iface underlay type ", "iface", iface)
	}
	if err != nil {
		return err
	}
	return nil
}

func confEthernetExtUnderlay(iface topology.IFInfo, dp Dataplane) error {
	var intf *net.Interface
	var err error
	underlay := iface.Underlay

	log.Debug("Configuring alternative external underlay:", "iface", iface.ID, "type", underlay.Type,
		"hwIf", underlay.HwInterfaceName)
	// Look up the hardware interface used for this underlay
	// Lookup the interface by string name.
	intf, err = net.InterfaceByName(underlay.HwInterfaceName)
	if err != nil {
		return serrors.WrapStr("raw interface not found", err)
	}

	// Initiate a new raw socket for this interface, or if one already exists for this protocol,
	// get that raw socket.
	receiver, err := dp.GetRawReceiver(intf.Index, underlay.Type)
	if err != nil {
		return err
	}

	// Register the specific SCION interface ID withthe receiver, such that it knows
	// packets received on the interface should map to a specific interface ID.
	// Currently the Ethernet underlay only supports one interface.
	if err = receiver.Register(uint16(iface.ID), raw.NewRegisterOptions()); err != nil {
		return err
	}

	// Register the sending closures for sending on the raw interface, such that the dataplane can
	// use the raw socket.
	nextHopAddr := &unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Protocol: uint16(protocols.SCION_ETHERTYPE_LE), // MPLS ethertype
		Ifindex:  int32(intf.Index),
	}
	copy(nextHopAddr.Addr[:], underlay.NextHop)
	so := raw.NewSendingOptions().WithNextHopMac(nextHopAddr)
	if err = dp.AddRawSender(intf.Index, iface.ID, underlay.Type, receiver.Serializer(so),
		true, nil, iface); err != nil {
		return err
	}
	return nil
}

func confMplsIpUdpExtUnderlay(iface topology.IFInfo, dp Dataplane) error {
	var intf *net.Interface
	var err error
	underlay := iface.Underlay

	log.Debug("Configuring alternative external underlay:", "iface", iface.ID, "type", underlay.Type,
		"hwIf", underlay.HwInterfaceName)
	// Look up the hardware interface used for this underlay
	if underlay.HwInterfaceName == "auto" {
		// The automatic detection uses the local IP address defined to make an informed guess of
		// the hardware interface by looking up the IP addresses for each hardware interface.
		intf, err = raw.GetInterfaceByIP(net.UDPAddrFromAddrPort(underlay.LocalIp).IP)
		if err != nil {
			return serrors.WrapStr("getting interface for IP address", err)
		}
		log.Debug("Protocol is using", "interface", iface.ID, "protocol",
			underlay.Type, "err", err, "ip", underlay.LocalIp)
	} else {
		// Lookup the interface by string name.
		intf, err = net.InterfaceByName(underlay.HwInterfaceName)
		if err != nil {
			return serrors.WrapStr("raw interface not found", err)
		}
	}
	// Initiate a new raw socket for this interface, or if one already exists for this protocol,
	// get that raw socket.
	receiver, err := dp.GetRawReceiver(intf.Index, underlay.Type)
	if err != nil {
		return err
	}

	// Register the specific source and destination IP addresses with the underlay, such that
	// the underlay knows packets that arrived with a specific src and destination pair are destined
	// for SCION interface number swIfId
	if err = receiver.Register(uint16(iface.ID), raw.NewRegisterOptions().
		WithLocalIp(net.UDPAddrFromAddrPort(underlay.LocalIp)).
		WithRemoteIp(net.UDPAddrFromAddrPort(underlay.RemoteIp))); err != nil {
		return err
	}
	// Register the sending closures for sending on the raw interface, such that the dataplane can
	// use the raw socket.

	nextHopAddr := &unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Protocol: uint16(protocols.MPLS_ETHERTYPE_LE), // MPLS ethertype
		Ifindex:  int32(intf.Index),
	}
	copy(nextHopAddr.Addr[:], underlay.NextHop)
	so := raw.NewSendingOptions().WithSrcIpAddr(net.UDPAddrFromAddrPort(underlay.LocalIp)).
		WithDstIpAddr(net.UDPAddrFromAddrPort(underlay.RemoteIp)).WithNextHopMac(nextHopAddr)
	if err = dp.AddRawSender(intf.Index, iface.ID, underlay.Type, receiver.Serializer(so),
		true, nil, iface); err != nil {
		return err
	}
	return nil
}

func confMplsIpUdpIntUnderlay(ifid common.IFIDType, infomap topology.IfInfoMap, dp Dataplane,
	underlay topology.InternalUnderlayInfo) error {
	var intf *net.Interface
	var err error
	log.Debug("Configuring alternative internal underlay:", "iface", ifid, "type", underlay.Type,
		"hwIf", underlay.HwInterfaceName)
	// Look up the hardware interface used for this underlay
	if underlay.HwInterfaceName == "auto" {
		// The automatic detection uses the local IP address defined to make an informed guess of
		// the hardware interface by looking up the IP addresses for each hardware interface.
		intf, err = raw.GetInterfaceByIP(net.UDPAddrFromAddrPort(underlay.LocalIp).IP)
		if err != nil {
			return serrors.WrapStr("getting interface for IP address", err)
		}
		log.Debug("Protocol is using", "interface", ifid, "protocol",
			underlay.Type, "err", err, "ip", underlay.LocalIp)
	} else {
		// Lookup the interface by string name.
		intf, err = net.InterfaceByName(underlay.HwInterfaceName)
		if err != nil {
			return serrors.WrapStr("raw interface not found", err)
		}
	}
	// Initiate a new raw socket for this interface, or if one already exists for this protocol,
	// get that raw socket.
	receiver, err := dp.GetRawReceiver(intf.Index, underlay.Type)
	if err != nil {
		return err
	}

	// Register the local IP address with the underlay, such that the underlay knows packets that
	// arrived with the IP as a destination, are mapped to the queue for the corresponding
	// specific SCION interface
	so := raw.NewSendingOptions()
	if ifid == 0 {
		if err = receiver.Register(uint16(ifid), raw.NewRegisterOptions().
			WithLocalIp(net.UDPAddrFromAddrPort(underlay.LocalIp))); err != nil {
			return err
		}
		so = so.WithSrcIpAddr(net.UDPAddrFromAddrPort(underlay.LocalIp))
	} else {
		// If this is an underlay to reach another border router in the internal network, we know
		// the destination and source IP addresses, so we prebake the connection as such.
		if err = receiver.Register(0, raw.NewRegisterOptions().
			WithLocalIp(net.UDPAddrFromAddrPort(underlay.LocalIp)).
			WithRemoteIp(net.UDPAddrFromAddrPort(infomap[ifid].InternalAddr))); err != nil {
			return err
		}
		so = so.WithSrcIpAddr(net.UDPAddrFromAddrPort(underlay.LocalIp)).
			WithDstIpAddr(net.UDPAddrFromAddrPort(infomap[ifid].InternalAddr))
	}
	// Obtain all the next hops addresses
	nhs := make(map[uint32]*unix.RawSockaddrLinklayer)
	identifiers := make([]topology.InternalUnderlayIdentifier, 0, len(underlay.Labels))
	for label, nh := range underlay.Labels {
		nhs[label] = &unix.RawSockaddrLinklayer{
			Family:   unix.AF_PACKET,
			Protocol: uint16(protocols.MPLS_ETHERTYPE_LE), // MPLS ethertype
			Ifindex:  int32(intf.Index),
		}
		copy(nhs[label].Addr[:], nh)
		identifiers = append(identifiers, topology.InternalUnderlayIdentifier{
			IntfIndex: uint16(ifid),
			Protocol:  underlay.Type,
			Label:     label,
		})
	}
	so = so.WithMplsNextHops(nhs)

	// Register the sending closures for sending on the raw interface, such that the dataplane can
	// use the raw socket.
	if err = dp.AddRawSender(intf.Index, ifid, underlay.Type, receiver.Serializer(so), false,
		identifiers,
		topology.IFInfo{}); err != nil {
		return err
	}

	return nil
}
