package router

import (
	"crypto/rand"
	"fmt"
	"hash"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/underlay/raw"
	"github.com/scionproto/scion/private/underlay/raw/protocols"
	"github.com/scionproto/scion/router/bfd"
	"github.com/scionproto/scion/router/control"
)

type SenderConn struct {
	Conn       raw.Conn
	Serializer raw.SerializeFn
}
type SwSender struct {
	swIntfIndex uint16
	protocol    protocols.ProtocolType
	hwIfId      int
	external    bool
}
type HwReceiver struct {
	hwIntfIndex int
	protocol    protocols.ProtocolType
}

// MplsRib stores a single entry to the routing information base.
type MplsRibEntry struct {
	NextHopLL   *unix.RawSockaddrLinklayer
	HwIntfIndex int32
	HwIntfName  string
}

func (d *DataPlane) GetRawReceiver(hwIfId int, protocol protocols.ProtocolType) (raw.Protocol, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return nil, modifyExisting
	}

	//
	if d.rawReceivers == nil {
		d.rawReceivers = make(map[HwReceiver]raw.Conn)
	}
	// Add a listener on the raw socket for the specified protocol if one does not yet exist.
	receiver := HwReceiver{hwIntfIndex: hwIfId, protocol: protocol}
	if _, exists := d.rawReceivers[receiver]; !exists {
		proto, err := protocols.NewProtoFromType(protocol)
		if err != nil {
			return nil, serrors.WrapStr("Raw interface failed to init", err, "hwIfID", hwIfId)
		}
		conn, err := raw.New(hwIfId, proto, false)
		if err != nil {
			return nil, serrors.WrapStr("Raw interface failed to start", err, "hwIfID", hwIfId)
		}
		d.rawReceivers[receiver] = conn
	}
	return d.rawReceivers[receiver].Protocol(), nil
}

func (d *DataPlane) AddRawSender(hwIfId int, swIfId common.IFIDType, protocol protocols.ProtocolType,
	serializer raw.SerializeFn, external bool,
	internalIdentifiers []topology.InternalUnderlayIdentifier, iface topology.IFInfo) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	// Store the prebaked sending function so that it can be used in the forwarder.
	if d.rawForwarders == nil {
		d.rawForwarders = make(map[SwSender]SenderConn)
	}
	sender := SwSender{swIntfIndex: uint16(swIfId), protocol: protocol, hwIfId: hwIfId, external: external}
	if _, exists := d.rawForwarders[sender]; exists {
		return serrors.New("Sending function already exists", "swIf", swIfId, "protocol",
			protocol)
	}
	proto, err := protocols.NewProtoFromType(protocol)
	if err != nil {
		return serrors.WrapStr("Raw interface failed to init", err, "hwIfID", hwIfId)
	}
	conn, err := raw.New(hwIfId, proto, true)
	d.rawForwarders[sender] = SenderConn{
		conn,
		serializer}
	if external {
		// External interfaces use the forwarding queues for regular external interfaces and it
		// is thus not required to register any extra attributes such that the specific raw sender
		// can be found during processing.
		if d.external == nil {
			d.external = make(map[uint16]bool)
		}
		d.external[uint16(swIfId)] = true
	} else {
		// On some protocols, such as MPLS with IP and UDP, a single queue and sending function
		// for a specific interface id serves multiple MPLS labels. Two distinct mpls labels for the
		// same interface id can still map to different hardware interfaces, and would thus map to
		// different sending functions. Here we create a mapping for an interface, protocol,
		// label to the corresponding interface, protocol and hardware interface, such that it can
		// be used for forwarding. This mapping is not exclusive to MPLS and could be used for other
		// underlays.
		if d.internalUnderlays == nil {
			d.internalUnderlays = make(map[topology.InternalUnderlayIdentifier]SwSender)
		}
		for _, id := range internalIdentifiers {
			d.internalUnderlays[id] = sender
		}
	}
	log.Debug("Added raw sender", "swifId", swIfId, "protocol", protocol, "external", external)
	return nil
}

func (d *DataPlane) runRawReceiver(hwIfID int32, conn raw.Conn, cfg *RunConfig,
	procQs []chan packet) {
	log.Debug("Run raw receiver for", "interface", hwIfID, "protocol", conn.Protocol().Name())
	randomValue := make([]byte, 16)
	if _, err := rand.Read(randomValue); err != nil {
		panic("Error while generating random value")
	}

	oobn := 100
	_, hs := raw.MakeReadMessages(cfg.BatchSize, oobn)

	numReusable := 0 // unused buffers from previous loop

	// Each receiver (therefore each input interface) has a unique random seed for the procID hash
	// function.
	hashSeed := fnv1aOffset32
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		panic("Error while generating random value")
	}
	for _, c := range randomBytes {
		hashSeed = hashFNV1a(hashSeed, c)
	}
	for d.running {
		for i := 0; i < cfg.BatchSize-numReusable; i++ {
			p := <-d.packetPool
			hs[i].Hdr.Iov.Base = &p[0]
			hs[i].Hdr.Iov.SetLen(len(p))
		}

		numPkts, err := conn.ReadBatch(hs)
		numReusable = cfg.BatchSize - numPkts
		if err != nil {
			log.Debug("Error while reading batch", "hwInterfaceID", hwIfID, "err", err)
			continue
		}

		for i := range hs[:numPkts] {
			// We need to make the unsafe slice for the entire rawPkt buffer, otherwise the capacity
			// will not be set adequately, which means we leak memory when we return the packet to
			// the pool.
			rawPkt := unsafe.Slice(hs[i].Hdr.Iov.Base, hs[i].Hdr.Iov.Len)[:hs[i].Len]
			offset, srcAddr, intf, err := conn.Protocol().ParsePacket(rawPkt)
			if err != nil {
				log.Debug("Error while parsing packet", "HW Interface ID", hwIfID, "err",
					err)
				continue
			}
			//TODO(jvanbommel): remove this copy, it should not be necessary if we properly pass the
			// offset to the right functions.
			pktCopy := <-d.packetPool
			copy(pktCopy, rawPkt[offset:])
			d.returnPacketToPool(rawPkt)
			pktCopy = pktCopy[:uint(len(rawPkt))-offset]
			outPkt := packet{
				rawPacket:       pktCopy,
				ingress:         intf,
				validatedSource: !conn.Protocol().RequiresUDPSourceValidation(),
				offset:          offset,
				srcAddr:         srcAddr,
			}
			// Enqueue the packet for processing
			procID, err := computeProcID(outPkt.rawPacket, cfg.NumProcessors, hashSeed)
			if err != nil {
				log.Debug("Error while computing procID", "err", err)
				d.returnPacketToPool(rawPkt)
				return
			}

			select {
			case procQs[procID] <- outPkt:
			default:
				d.returnPacketToPool(pktCopy)
			}
			// Reset the control length and name length (optional) as they have been modified
			// by the call to read batch.
			hs[i].Hdr.Namelen = unix.SizeofSockaddrLinklayer
			hs[i].Hdr.SetControllen(oobn)
		}
	}
}

// AddExternalInterfaceBFD adds the inter AS connection BFD session.
func (d *DataPlane) addExternalRawInterfaceBFD(ifID uint16, conn raw.Conn,
	sendingFn raw.SerializeFn,
	srcIA, dstIA addr.IA, srcAddr,
	dstAddr *net.UDPAddr, cfg control.BFD) error {

	if *cfg.Disable {
		return nil
	}
	var m bfd.Metrics
	if d.Metrics != nil {
		labels := prometheus.Labels{
			"interface":       fmt.Sprint(ifID),
			"isd_as":          d.localIA.String(),
			"neighbor_isd_as": dstIA.String(),
		}
		m = bfd.Metrics{
			Up:              d.Metrics.InterfaceUp.With(labels),
			StateChanges:    d.Metrics.BFDInterfaceStateChanges.With(labels),
			PacketsSent:     d.Metrics.BFDPacketsSent.With(labels),
			PacketsReceived: d.Metrics.BFDPacketsReceived.With(labels),
		}
	}
	s, err := newRawBFDSend(conn, sendingFn, srcIA, dstIA, srcAddr, dstAddr, ifID,
		d.macFactory())
	if err != nil {
		return err
	}
	return d.addBFDController(ifID, s, cfg, m)
}

type rawBfdSend struct {
	conn             raw.Conn
	srcAddr, dstAddr *net.UDPAddr
	scn              *slayers.SCION
	ohp              *onehop.Path
	mac              hash.Hash
	macBuffer        []byte
	buffer           gopacket.SerializeBuffer
	sendingFn        raw.SerializeFn
}

// newBFDSend creates and initializes a BFD Sender
func newRawBFDSend(conn raw.Conn, sendingFn raw.SerializeFn, srcIA, dstIA addr.IA, srcAddr,
	dstAddr *net.UDPAddr,
	ifID uint16, mac hash.Hash) (*rawBfdSend, error) {

	scn := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4BFD,
		SrcIA:        srcIA,
		DstIA:        dstIA,
	}

	srcAddrIP, ok := netip.AddrFromSlice(srcAddr.IP)
	if !ok {
		srcAddrIP = netip.MustParseAddr("127.0.0.1")
	}
	dstAddrIP, ok := netip.AddrFromSlice(dstAddr.IP)
	if !ok {
		dstAddrIP = netip.MustParseAddr("127.0.0.1")
	}
	if err := scn.SetSrcAddr(addr.HostIP(srcAddrIP)); err != nil {
		panic(err) // Must work
	}
	if err := scn.SetDstAddr(addr.HostIP(dstAddrIP)); err != nil {
		panic(err) // Must work
	}

	var ohp *onehop.Path
	if ifID == 0 {
		scn.PathType = empty.PathType
		scn.Path = &empty.Path{}
	} else {
		ohp = &onehop.Path{
			Info: path.InfoField{
				ConsDir: true,
				// Timestamp set in Send
			},
			FirstHop: path.HopField{
				ConsEgress: ifID,
				ExpTime:    hopFieldDefaultExpTime,
			},
		}
		scn.PathType = onehop.PathType
		scn.Path = ohp
	}

	return &rawBfdSend{
		conn:      conn,
		srcAddr:   srcAddr,
		dstAddr:   dstAddr,
		scn:       scn,
		ohp:       ohp,
		mac:       mac,
		macBuffer: make([]byte, path.MACBufferSize),
		buffer:    gopacket.NewSerializeBuffer(),
		sendingFn: sendingFn,
	}, nil
}

func (b *rawBfdSend) String() string {
	return b.srcAddr.String()
}

// Send sends out a BFD message.
// Due to the internal state of the MAC computation, this is not goroutine
// safe.
func (b *rawBfdSend) Send(bfd *layers.BFD) error {
	if b.ohp != nil {
		// Subtract 10 seconds to deal with possible clock drift.
		ohp := b.ohp
		ohp.Info.Timestamp = uint32(time.Now().Unix() - 10)
		ohp.FirstHop.Mac = path.MAC(b.mac, ohp.Info, ohp.FirstHop, b.macBuffer)
	}

	err := gopacket.SerializeLayers(b.buffer, gopacket.SerializeOptions{FixLengths: true},
		b.scn, bfd)
	if err != nil {
		return err
	}
	fwArgs := raw.ForwardingArgs{}
	hdrs := b.conn.Protocol().AllocateSenderBufs(1)
	pld := b.buffer.Bytes()
	pktHdrLen, err := b.sendingFn(&fwArgs, hdrs[0], pld)
	if err != nil {
		return err
	}
	msgs, iovecs := raw.MakeSendMessages(1)
	iovecs[0].Base = &hdrs[0][0]
	iovecs[0].SetLen(pktHdrLen)
	iovecs[1].Base = &pld[0]
	iovecs[1].SetLen(len(pld))
	msgs[0].Hdr.Name = (*byte)(unsafe.Pointer(fwArgs.NextHopLL))
	_, err = b.conn.WriteBatch(msgs, 0)
	if err != nil {
		return err
	}
	return err
}

func (d *DataPlane) runRawForwarder(ifID uint16, conn raw.Conn, fn raw.SerializeFn, cfg *RunConfig, c <-chan packet) {
	log.Debug("Initialize Raw forwarder for", "swIf", ifID, "protocol", conn.Protocol().Name(),
		"batch", cfg.BatchSize)

	// We use this somewhat like a ring buffer.
	pkts := make([]packet, cfg.BatchSize)

	// We use this as a temporary buffer, but allocate it just once
	// to save on garbage handling.
	msgs, iovecs := raw.MakeSendMessages(cfg.BatchSize)
	hdrs := conn.Protocol().AllocateSenderBufs(cfg.BatchSize)
	toWrite := 0

	for d.running {
		toWrite += readUpTo(c, cfg.BatchSize-toWrite, toWrite == 0, pkts[toWrite:])

		// Turn the packets into underlay messages that WriteBatch can send.
		for i, p := range pkts[:toWrite] {
			hdrLen, err := fn(&p.rawForwardingArgs, hdrs[i], p.rawPacket)
			if err != nil {
				log.Error("Failed to serialize header", "err", err, "protocol",
					conn.Protocol().Name(),
					"swIfId", ifID)
				d.returnPacketToPool(p.rawPacket)
				continue
			}
			// Set up the iovecs for sending the packet: the first entry in the iovec is the
			// packet header, the second is the SCION packet
			iovecs[i*2].Base = &hdrs[i][0]
			iovecs[i*2].SetLen(hdrLen)
			iovecs[i*2+1].Base = &p.rawPacket[0]
			iovecs[i*2+1].SetLen(len(p.rawPacket))
			msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(p.rawForwardingArgs.NextHopLL))
		}

		written, _ := conn.WriteBatch(msgs[:toWrite], 0)
		if written < 0 {
			// WriteBatch returns -1 on error, we just consider this as
			// 0 packets written
			written = 0
		}

		//updateOutputMetrics(metrics, pkts[:written])

		for _, p := range pkts[:written] {
			d.returnPacketToPool(p.rawPacket)
		}

		if written != toWrite {
			// Only one is dropped at this time. We'll retry the rest.
			//sc := classOfSize(len(pkts[written].rawPacket))
			//metrics[sc].DroppedPacketsInvalid.Inc()
			d.returnPacketToPool(pkts[written].rawPacket)
			toWrite -= written + 1
			// Shift the leftovers to the head of the buffers.
			for i := 0; i < toWrite; i++ {
				pkts[i] = pkts[i+written+1]
			}

		} else {
			toWrite = 0
		}
	}
}
