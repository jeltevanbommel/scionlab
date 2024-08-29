// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
// Copyright 2023 SCION Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is a general purpose client/server code for end2end tests. The client
// sends pings to the server until it receives at least one pong from the
// server or a given deadline is reached. The server responds to all pings and
// the client wait for a response before doing anything else.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	libfabrid "github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/experimental/fabrid/crypto"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/metrics"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/tracing"
	libint "github.com/scionproto/scion/tools/integration"
	integration "github.com/scionproto/scion/tools/integration/integrationlib"
)

const (
	ping = "ping"
	pong = "pong"
)

type Ping struct {
	Server  addr.IA `json:"server"`
	Message string  `json:"message"`
	Trace   []byte  `json:"trace"`
}

type Pong struct {
	Client  addr.IA `json:"client"`
	Server  addr.IA `json:"server"`
	Message string  `json:"message"`
	Trace   []byte  `json:"trace"`
}

var (
	remote                 snet.UDPAddr
	timeout                = &util.DurWrap{Duration: 10 * time.Second}
	scionPacketConnMetrics = metrics.NewSCIONPacketConnMetrics()
	scmpErrorsCounter      = scionPacketConnMetrics.SCMPErrors
	epic                   bool
	fabrid                 bool
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.HandlePanic()
	defer log.Flush()
	addFlags()
	err := integration.Setup()
	if err != nil {
		log.Error("Parsing common flags failed", "err", err)
		return 1
	}
	validateFlags()

	closeTracer, err := integration.InitTracer("end2end-" + integration.Mode)
	if err != nil {
		log.Error("Tracer initialization failed", "err", err)
		return 1
	}
	defer closeTracer()

	if integration.Mode == integration.ModeServer {
		server{}.run()
		return 0
	}
	c := client{}
	return c.run()
}

func addFlags() {
	flag.Var(&remote, "remote", "(Mandatory for clients) address to connect to")
	flag.Var(timeout, "timeout", "The timeout for each attempt")
	flag.BoolVar(&epic, "epic", false, "Enable EPIC")
	flag.BoolVar(&fabrid, "fabrid", false, "Enable FABRID")
}

func validateFlags() {
	if integration.Mode == integration.ModeClient {
		if remote.Host == nil {
			integration.LogFatal("Missing remote address")
		}
		if remote.Host.Port == 0 {
			integration.LogFatal("Invalid remote port", "remote port", remote.Host.Port)
		}
		if timeout.Duration == 0 {
			integration.LogFatal("Invalid timeout provided", "timeout", timeout)
		}
	}
	if epic && fabrid {
		integration.LogFatal("FABRID is incompatible with EPIC")
	}
	log.Info("Flags", "timeout", timeout, "epic", epic, "fabrid", fabrid, "remote", remote)
}

type server struct{}

func (s server) run() {
	log.Info("Starting server", "isd_as", integration.Local.IA)
	defer log.Info("Finished server", "isd_as", integration.Local.IA)

	sdConn := integration.SDConn()
	defer sdConn.Close()
	sn := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		PacketConnMetrics: scionPacketConnMetrics,
		Topology:          sdConn,
	}
	if fabrid {
		conn, err := sn.OpenRaw(context.Background(), integration.Local.Host)
		if err != nil {
			integration.LogFatal("Error listening", "err", err)
		}
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
			// Needed for integration test ready signal.
			fmt.Printf("Port=%d\n", localAddr.Port)
			fmt.Printf("%s%s\n\n", libint.ReadySignal, integration.Local.IA)
		}
		log.Info("Listening", "local",
			fmt.Sprintf("%v:%d", integration.Local.Host.IP, localAddr.Port))
		// Receive ping message
		for {
			if err := s.handlePingFabrid(conn); err != nil {
				log.Error("Error handling ping", "err", err)
			}
		}
	} else {
		conn, err := sn.Listen(context.Background(), "udp", integration.Local.Host)
		if err != nil {
			integration.LogFatal("Error listening", "err", err)
		}
		defer conn.Close()
		localAddr := conn.LocalAddr().(*snet.UDPAddr)
		if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
			// Needed for integration test ready signal.
			fmt.Printf("Port=%d\n", localAddr.Host.Port)
			fmt.Printf("%s%s\n\n", libint.ReadySignal, integration.Local.IA)
		}
		log.Info("Listening", "local", fmt.Sprintf("%v:%d", localAddr.Host.IP, localAddr.Host.Port))
		// Receive ping message
		for {
			if err := s.handlePing(conn); err != nil {
				log.Error("Error handling ping", "err", err)
			}
		}
	}
}

func (s server) handlePing(conn *snet.Conn) error {
	rawPld := make([]byte, common.MaxMTU)
	n, clientAddr, err := readFrom(conn, rawPld)
	if err != nil {
		return serrors.WrapStr("reading packet", err)
	}

	var pld Ping
	if err := json.Unmarshal(rawPld[:n], &pld); err != nil {
		return serrors.New("invalid payload contents",
			"data", string(rawPld),
		)
	}

	spanCtx, err := opentracing.GlobalTracer().Extract(
		opentracing.Binary,
		bytes.NewReader(pld.Trace),
	)
	if err != nil {
		return serrors.WrapStr("extracting trace information", err)
	}
	span, _ := opentracing.StartSpanFromContext(
		context.Background(),
		"handle_ping",
		ext.RPCServerOption(spanCtx),
	)
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}
	clientUDPAddr := clientAddr.(*snet.UDPAddr)
	if pld.Message != ping || !pld.Server.Equal(integration.Local.IA) {
		return withTag(serrors.New("unexpected data in payload",
			"remote", clientUDPAddr,
			"data", pld,
		))
	}
	log.Info(fmt.Sprintf("Ping received from %v, sending pong.", clientUDPAddr))
	raw, err := json.Marshal(Pong{
		Client:  clientUDPAddr.IA,
		Server:  integration.Local.IA,
		Message: pong,
		Trace:   pld.Trace,
	})
	if err != nil {
		return withTag(serrors.WrapStr("packing pong", err))
	}
	// Send pong
	if _, err := conn.WriteTo(raw, clientUDPAddr); err != nil {
		return withTag(serrors.WrapStr("sending reply", err))
	}
	log.Info("Sent pong to", "client", clientUDPAddr)
	return nil
}

func (s server) handlePingFabrid(conn snet.PacketConn) error {
	var p snet.Packet
	var ov net.UDPAddr
	err := readFromFabrid(conn, &p, &ov)
	if err != nil {
		return serrors.WrapStr("reading packet", err)
	}

	// If the packet is from remote IA, validate the FABRID path
	if p.Source.IA != integration.Local.IA {
		if p.HbhExtension == nil {
			return serrors.New("Missing HBH extension")
		}

		// Check extensions for relevant options
		var identifierOption *extension.IdentifierOption
		var fabridOption *extension.FabridOption
		var err error

		for _, opt := range p.HbhExtension.Options {
			switch opt.OptType {
			case slayers.OptTypeIdentifier:
				decoded := scion.Decoded{}
				err = decoded.DecodeFromBytes(p.Path.(snet.RawPath).Raw)
				if err != nil {
					return err
				}
				baseTimestamp := decoded.InfoFields[0].Timestamp
				identifierOption, err = extension.ParseIdentifierOption(opt, baseTimestamp)
				if err != nil {
					return err
				}
			case slayers.OptTypeFabrid:
				fabridOption, err = extension.ParseFabridOptionFullExtension(opt,
					(opt.OptDataLen-4)/4)
				if err != nil {
					return err
				}
			}
		}

		if identifierOption == nil {
			return serrors.New("Missing identifier option")
		}

		if fabridOption == nil {
			return serrors.New("Missing FABRID option")
		}

		meta := drkey.HostHostMeta{
			Validity: identifierOption.Timestamp,
			SrcIA:    integration.Local.IA,
			SrcHost:  integration.Local.Host.IP.String(),
			DstIA:    p.Source.IA,
			DstHost:  p.Source.Host.IP().String(),
			ProtoId:  drkey.FABRID,
		}
		hostHostKey, err := integration.SDConn().DRKeyGetHostHostKey(context.Background(), meta)
		if err != nil {
			return serrors.WrapStr("getting host key", err)
		}

		tmpBuffer := make([]byte, (len(fabridOption.HopfieldMetadata)*3+15)&^15+16)
		_, _, _, err = crypto.VerifyPathValidator(fabridOption, tmpBuffer, hostHostKey.Key[:])
		if err != nil {
			return err
		}
	}

	udp, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return serrors.New("unexpected payload received",
			"source", p.Source,
			"destination", p.Destination,
			"type", common.TypeOf(p.Payload),
		)
	}
	var pld Ping
	if err := json.Unmarshal(udp.Payload, &pld); err != nil {
		return serrors.New("invalid payload contents",
			"source", p.Source,
			"destination", p.Destination,
			"data", string(udp.Payload),
		)
	}

	spanCtx, err := opentracing.GlobalTracer().Extract(
		opentracing.Binary,
		bytes.NewReader(pld.Trace),
	)
	if err != nil {
		return serrors.WrapStr("extracting trace information", err)
	}
	span, _ := opentracing.StartSpanFromContext(
		context.Background(),
		"handle_ping",
		ext.RPCServerOption(spanCtx),
	)
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	if pld.Message != ping || !pld.Server.Equal(integration.Local.IA) {
		return withTag(serrors.New("unexpected data in payload",
			"source", p.Source,
			"destination", p.Destination,
			"data", pld,
		))
	}
	log.Info(fmt.Sprintf("Ping received from %s, sending pong.", p.Source))
	raw, err := json.Marshal(Pong{
		Client:  p.Source.IA,
		Server:  integration.Local.IA,
		Message: pong,
		Trace:   pld.Trace,
	})
	if err != nil {
		return withTag(serrors.WrapStr("packing pong", err))
	}

	p.Destination, p.Source = p.Source, p.Destination
	p.Payload = snet.UDPPayload{
		DstPort: udp.SrcPort,
		SrcPort: udp.DstPort,
		Payload: raw,
	}

	// Remove header extension for reverse path
	p.HbhExtension = nil
	p.E2eExtension = nil

	// reverse path
	rpath, ok := p.Path.(snet.RawPath)
	if !ok {
		return serrors.New("unexpected path", "type", common.TypeOf(p.Path))
	}
	replypather := snet.DefaultReplyPather{}
	replyPath, err := replypather.ReplyPath(rpath)
	if err != nil {
		return serrors.WrapStr("creating reply path", err)
	}
	p.Path = replyPath
	// Send pong
	if err := conn.WriteTo(&p, &ov); err != nil {
		return withTag(serrors.WrapStr("sending reply", err))
	}
	log.Info("Sent pong to", "client", p.Destination)
	return nil
}

type client struct {
	network *snet.SCIONNetwork
	conn    *snet.Conn
	sdConn  daemon.Connector

	errorPaths map[snet.PathFingerprint]struct{}
}

func (c *client) run() int {
	pair := fmt.Sprintf("%s -> %s", integration.Local.IA, remote.IA)
	log.Info("Starting", "pair", pair)
	defer log.Info("Finished", "pair", pair)
	defer integration.Done(integration.Local.IA, remote.IA)
	c.sdConn = integration.SDConn()
	defer c.sdConn.Close()
	c.network = &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: c.sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		PacketConnMetrics: scionPacketConnMetrics,
		Topology:          c.sdConn,
	}
	log.Info("Send", "local",
		fmt.Sprintf("%v,[%v] -> %v,[%v]",
			integration.Local.IA, integration.Local.Host,
			remote.IA, remote.Host))
	c.errorPaths = make(map[snet.PathFingerprint]struct{})
	return integration.AttemptRepeatedly("End2End", c.attemptRequest)
}

// attemptRequest sends one ping packet and expect a pong.
// Returns true (which means "stop") *if both worked*.
func (c *client) attemptRequest(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	span, ctx := tracing.CtxWith(timeoutCtx, "attempt")
	span.SetTag("attempt", n)
	span.SetTag("src", integration.Local.IA)
	span.SetTag("dst", remote.IA)
	defer span.Finish()
	logger := log.FromCtx(ctx)

	path, err := c.getRemote(ctx, n)
	if err != nil {
		logger.Error("Could not get remote", "err", err)
		return false
	}
	span, ctx = tracing.StartSpanFromCtx(ctx, "attempt.ping")
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	// Send ping
	close, err := c.ping(ctx, n, path)
	if err != nil {
		logger.Error("Could not send packet", "err", withTag(err))
		return false
	}
	defer close()
	// Receive pong
	if err := c.pong(ctx); err != nil {
		logger.Error("Error receiving pong", "err", withTag(err))
		if path != nil {
			c.errorPaths[snet.Fingerprint(path)] = struct{}{}
		}
		return false
	}
	return true
}

func (c *client) ping(ctx context.Context, n int, path snet.Path) (func(), error) {
	rawPing, err := json.Marshal(Ping{
		Server:  remote.IA,
		Message: ping,
		Trace:   tracing.IDFromCtx(ctx),
	})
	if err != nil {
		return nil, serrors.WrapStr("packing ping", err)
	}
	log.FromCtx(ctx).Info("Dialing", "remote", remote)
	c.conn, err = c.network.Dial(ctx, "udp", integration.Local.Host, &remote)
	if err != nil {
		return nil, serrors.WrapStr("dialing conn", err)
	}
	if err := c.conn.SetWriteDeadline(getDeadline(ctx)); err != nil {
		return nil, serrors.WrapStr("setting write deadline", err)
	}
	log.Info("sending ping", "attempt", n, "remote", c.conn.RemoteAddr())
	if _, err := c.conn.Write(rawPing); err != nil {
		return nil, err
	}
	closer := func() {
		if err := c.conn.Close(); err != nil {
			log.Error("Unable to close connection", "err", err)
		}
	}
	return closer, nil
}

func (c *client) getRemote(ctx context.Context, n int) (snet.Path, error) {
	if remote.IA.Equal(integration.Local.IA) {
		remote.Path = snetpath.Empty{}
		return nil, nil
	}
	span, ctx := tracing.StartSpanFromCtx(ctx, "attempt.get_remote")
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA,
		daemon.PathReqFlags{Refresh: n != 0})
	if err != nil {
		return nil, withTag(serrors.WrapStr("requesting paths", err))
	}
	// If all paths had an error, let's try them again.
	if len(paths) <= len(c.errorPaths) {
		c.errorPaths = make(map[snet.PathFingerprint]struct{})
	}
	// Select first path that didn't error before.
	var path snet.Path
	for _, p := range paths {
		if _, ok := c.errorPaths[snet.Fingerprint(p)]; ok {
			continue
		}
		path = p
		break
	}
	if path == nil {
		return nil, withTag(serrors.New("no path found",
			"candidates", len(paths),
			"errors", len(c.errorPaths),
		))
	}
	// Extract forwarding path from the SCION Daemon response.
	// If the epic flag is set, try to use the EPIC path type header.
	if epic {
		scionPath, ok := path.Dataplane().(snetpath.SCION)
		if !ok {
			return nil, serrors.New("provided path must be of type scion")
		}
		epicPath, err := snetpath.NewEPICDataplanePath(scionPath, path.Metadata().EpicAuths)
		if err != nil {
			return nil, err
		}
		remote.Path = epicPath
	} else if fabrid {
		// If the fabrid flag is set, try to create FABRID dataplane path.
		if len(path.Metadata().FabridInfo) > 0 {
			// Check if fabrid info is available, otherwise the source
			// AS does not support fabrid

			scionPath, ok := path.Dataplane().(snetpath.SCION)
			if !ok {
				return nil, serrors.New("provided path must be of type scion")
			}
			fabridConfig := &snetpath.FabridConfig{
				LocalIA:         integration.Local.IA,
				LocalAddr:       integration.Local.Host.IP.String(),
				DestinationIA:   remote.IA,
				DestinationAddr: remote.Host.IP.String(),
			}
			hops := path.Metadata().Hops()
			log.Info("Fabrid path", "path", path, "hops", hops)
			// Use ZERO policy for all hops with fabrid, to just do path validation
			policies := make([]*libfabrid.PolicyID, len(hops))
			zeroPol := libfabrid.PolicyID(0)
			for i, hop := range hops {
				if hop.FabridEnabled {
					policies[i] = &zeroPol
				}
			}
			fabridPath, err := snetpath.NewFABRIDDataplanePath(scionPath, hops,
				policies, fabridConfig)
			if err != nil {
				return nil, serrors.New("Error creating FABRID path", "err", err)
			}
			remote.Path = fabridPath
			fabridPath.RegisterDRKeyFetcher(c.sdConn.FabridKeys)
		} else {
			log.Info("FABRID flag was set for client in non-FABRID AS. Proceeding without FABRID.")
			remote.Path = path.Dataplane()
		}
	} else {
		remote.Path = path.Dataplane()
	}
	remote.NextHop = path.UnderlayNextHop()
	return path, nil
}

func (c *client) pong(ctx context.Context) error {
	if err := c.conn.SetReadDeadline(getDeadline(ctx)); err != nil {
		return serrors.WrapStr("setting read deadline", err)
	}
	rawPld := make([]byte, common.MaxMTU)
	n, serverAddr, err := readFrom(c.conn, rawPld)
	if err != nil {
		return serrors.WrapStr("reading packet", err)
	}

	var pld Pong
	if err := json.Unmarshal(rawPld[:n], &pld); err != nil {
		return serrors.WrapStr("unpacking pong", err, "data", string(rawPld))
	}

	expected := Pong{
		Client:  integration.Local.IA,
		Server:  remote.IA,
		Message: pong,
	}
	if pld.Client != expected.Client || pld.Server != expected.Server || pld.Message != pong {
		return serrors.New("unexpected contents received", "data", pld, "expected", expected)
	}
	log.Info("Received pong", "server", serverAddr)
	return nil
}

func getDeadline(ctx context.Context) time.Time {
	dl, ok := ctx.Deadline()
	if !ok {
		integration.LogFatal("No deadline in context")
	}
	return dl
}

func readFrom(conn *snet.Conn, pld []byte) (int, net.Addr, error) {
	n, remoteAddr, err := conn.ReadFrom(pld)
	// Attach more context to error
	var opErr *snet.OpError
	if !(errors.As(err, &opErr) && opErr.RevInfo() != nil) {
		return n, remoteAddr, err
	}
	return n, remoteAddr, serrors.WithCtx(err,
		"isd_as", opErr.RevInfo().IA(),
		"interface", opErr.RevInfo().IfID,
	)
}

func readFromFabrid(conn snet.PacketConn, pkt *snet.Packet, ov *net.UDPAddr) error {
	err := conn.ReadFrom(pkt, ov)
	// Attach more context to error
	var opErr *snet.OpError
	if !(errors.As(err, &opErr) && opErr.RevInfo() != nil) {
		return err
	}
	return serrors.WithCtx(err,
		"isd_as", opErr.RevInfo().IA(),
		"interface", opErr.RevInfo().IfID,
	)
}
