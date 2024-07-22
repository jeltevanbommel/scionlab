package router

import (
	"net"

	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/underlay/raw"
	"github.com/scionproto/scion/private/underlay/raw/protocols"
	"github.com/scionproto/scion/router/control"
)

func (c *Connector) GetRawReceiver(hwIfId int, protocol protocols.ProtocolType) (raw.Protocol, error) {
	return c.DataPlane.GetRawReceiver(hwIfId, protocol)
}

func (c *Connector) AddRawSender(hwIfId int, swIfId common.IFIDType,
	protocol protocols.ProtocolType, serializeFn raw.SerializeFn, external bool,
	internalIdentifiers []topology.InternalUnderlayIdentifier, iface topology.IFInfo) error {

	if external {
		if err := c.DataPlane.AddLinkType(uint16(swIfId), iface.LinkType); err != nil {
			return serrors.WrapStr("adding link type", err, "if_id", swIfId)
		}
		if err := c.DataPlane.AddNeighborIA(uint16(swIfId), iface.IA); err != nil {
			return serrors.WrapStr("adding neighboring IA", err, "if_id", swIfId)
		}

		bfd := c.applyBFDDefaults(control.BFD(iface.BFD))
		// iface.underlay.localIp may be null.
		err := c.DataPlane.addExternalRawInterfaceBFD(uint16(swIfId),
			c.DataPlane.rawReceivers[HwReceiver{hwIntfIndex: hwIfId,
				protocol: protocol}], serializeFn, c.DataPlane.localIA, iface.IA,
			net.UDPAddrFromAddrPort(iface.
				Underlay.LocalIp),
			net.UDPAddrFromAddrPort(iface.Underlay.RemoteIp),
			bfd)
		if err != nil {
			return err
		}

	}
	err := c.DataPlane.AddRawSender(hwIfId, swIfId, protocol, serializeFn, external,
		internalIdentifiers, iface)
	if err != nil {
		return err
	}
	return nil
}
