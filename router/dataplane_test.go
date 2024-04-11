// Copyright 2020 Anapaya Systems
// Copyright 2023 ETH Zurich
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

package router_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	libepic "github.com/scionproto/scion/pkg/experimental/epic"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/private/topology"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/control"
	"github.com/scionproto/scion/router/mock_router"
)

var metrics = router.GetMetrics()

func TestDataPlaneAddInternalInterface(t *testing.T) {
	internalIP := net.ParseIP("198.51.100.1")
	t.Run("fails after serve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddInternalInterface(mock_router.NewMockBatchConn(ctrl), internalIP))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.Error(t, d.AddInternalInterface(nil, nil))
	})
	t.Run("single set works", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddInternalInterface(mock_router.NewMockBatchConn(ctrl), internalIP))
	})
	t.Run("double set fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddInternalInterface(mock_router.NewMockBatchConn(ctrl), internalIP))
		assert.Error(t, d.AddInternalInterface(mock_router.NewMockBatchConn(ctrl), internalIP))
	})
}

func TestDataPlaneSetKey(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.SetKey([]byte("dummy")))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.SetKey(nil))
	})
	t.Run("single set works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.SetKey([]byte("dummy key xxxxxx")))
	})
	t.Run("double set fails", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.SetKey([]byte("dummy key xxxxxx")))
		assert.Error(t, d.SetKey([]byte("dummy key xxxxxx")))
	})
}

func TestDataPlaneAddExternalInterface(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl)))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.Error(t, d.AddExternalInterface(42, nil))
	})
	t.Run("normal add works", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl)))
		assert.NoError(t, d.AddExternalInterface(45, mock_router.NewMockBatchConn(ctrl)))
	})
	t.Run("overwrite fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := &router.DataPlane{}
		assert.NoError(t, d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl)))
		assert.Error(t, d.AddExternalInterface(42, mock_router.NewMockBatchConn(ctrl)))
	})
}

func TestDataPlaneAddSVC(t *testing.T) {
	t.Run("succeeds after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.UDPAddr{}))
	})
	t.Run("adding nil value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.Error(t, d.AddSvc(addr.SvcCS, nil))
	})
	t.Run("normal set works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.UDPAddr{}))
		assert.NoError(t, d.AddSvc(addr.SvcDS, &net.UDPAddr{}))
	})
	t.Run("set multiple times works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.UDPAddr{}))
		assert.NoError(t, d.AddSvc(addr.SvcCS, &net.UDPAddr{}))
	})
}

func TestDataPlaneAddNextHop(t *testing.T) {
	t.Run("fails after serve", func(t *testing.T) {
		d := &router.DataPlane{}
		d.FakeStart()
		assert.Error(t, d.AddNextHop(45, &net.UDPAddr{}))
	})
	t.Run("setting nil value is not allowed", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.Error(t, d.AddNextHop(45, nil))
	})
	t.Run("normal add works", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddNextHop(45, &net.UDPAddr{}))
		assert.NoError(t, d.AddNextHop(43, &net.UDPAddr{}))
	})
	t.Run("overwrite fails", func(t *testing.T) {
		d := &router.DataPlane{}
		assert.NoError(t, d.AddNextHop(45, &net.UDPAddr{}))
		assert.Error(t, d.AddNextHop(45, &net.UDPAddr{}))
	})
}

func TestDataPlaneRun(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := map[string]struct {
		prepareDP func(*gomock.Controller, chan<- struct{}) *router.DataPlane
	}{
		"fabrid basic": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}
				key := []byte("testkey_xxxxxxxx")
				dstIA := xtest.MustParseIA("4-ff00:0:411")
				dstAddr := addr.MustParseHost("2.2.2.2")
				srcIA := xtest.MustParseIA("2-ff00:0:222")
				srcAddr := addr.MustParseHost("1.1.1.1")

				asDRKey := [16]byte{
					0x00, 0x11, 0x22, 0x33,
					0x44, 0x55, 0x66, 0x77,
					0x88, 0x99, 0xaa, 0xbb,
					0xcc, 0xdd, 0xee, 0xff,
				}
				_ = ret.AddDRKeySecret(int32(drkey.FABRID),
					control.SecretValue{
						Key:        asDRKey,
						EpochBegin: time.Now().Add(-time.Second),
						EpochEnd:   time.Now().AddDate(1, 0, 0),
					})
				local := xtest.MustParseIA("1-ff00:0:110")
				now := time.Now().Truncate(time.Millisecond)
				identifier := extension.IdentifierOption{
					Timestamp:     now,
					PacketID:      0xabcd,
					BaseTimestamp: uint32(now.Unix()),
				}

				policyID := fabrid.FabridPolicyID{
					ID: 0x0f,
				}
				_, ipPrefix, _ := net.ParseCIDR("0.0.0.0/0")
				ret.UpdateFabridPolicies(map[uint32][]*control.PolicyIPRange{
					// ingress 3 with policy index 0x0f
					(3<<8 + 0x0f): {
						{
							MPLSLabel: 1,
							IPPrefix:  ipPrefix,
						},
					},
				}, nil)

				asToHostKey, err := ret.DeriveASToHostKey(int32(drkey.FABRID), now,
					srcIA, srcAddr.String())
				assert.NoError(t, err)
				encPolicyID, err := fabrid.EncryptPolicyID(&policyID, &identifier, asToHostKey[:])
				assert.NoError(t, err)

				mExternal := mock_router.NewMockBatchConn(ctrl)
				infoField := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)}

				mExternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						buf := gopacket.NewSerializeBuffer()
						path := &scion.Decoded{
							Base: scion.Base{
								PathMeta: scion.MetaHdr{
									CurrHF: 1,
									SegLen: [3]uint8{3, 0, 0},
								},
								NumINF:  1,
								NumHops: 3,
							},
							InfoFields: []path.InfoField{
								infoField,
							},
							HopFields: []path.HopField{
								{ConsIngress: 1, ConsEgress: 2},
								{ConsIngress: 3, ConsEgress: 4},
								{ConsIngress: 5, ConsEgress: 6},
							},
						}
						path.HopFields[1].Mac = computeMAC(t, key, path.InfoFields[0], path.HopFields[1])
						rawDstAddr := dstAddr.IP().As4()
						rawSrcAddr := srcAddr.IP().As4()
						s := slayers.SCION{
							NextHdr:     slayers.HopByHopClass,
							PathType:    scion.PathType,
							DstIA:       dstIA,
							SrcIA:       srcIA,
							SrcAddrType: slayers.T4Ip,
							DstAddrType: slayers.T4Ip,
							RawSrcAddr:  rawSrcAddr[:],
							RawDstAddr:  rawDstAddr[:],
							Path:        path,
						}

						identifierData := make([]byte, 8)
						identifier.Serialize(identifierData)

						meta := &extension.FabridHopfieldMetadata{
							EncryptedPolicyID: encPolicyID,
							FabridEnabled:     true,
						}
						tmp := make([]byte, 100)
						err = fabrid.ComputeBaseHVF(meta, &identifier, &s, tmp, asToHostKey[:], 3, 4)
						assert.NoError(t, err)

						fabrid := extension.FabridOption{
							HopfieldMetadata: []*extension.FabridHopfieldMetadata{
								{},
								meta,
								{},
							},
						}
						fabridData := make([]byte, 16)
						fabrid.SerializeTo(fabridData)
						hbh := slayers.HopByHopExtn{
							Options: []*slayers.HopByHopOption{
								{
									OptType:    slayers.OptTypeIdentifier,
									OptData:    identifierData,
									OptDataLen: uint8(len(identifierData)),
								},
								{
									OptType:    slayers.OptTypeFabrid,
									OptData:    fabridData,
									OptDataLen: uint8(len(fabridData)),
								},
							},
						}
						err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &s, &hbh)
						assert.NoError(t, err)
						raw := buf.Bytes()
						copy(m[0].Buffers[0], raw)
						m[0].N = len(raw)
						m[0].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}

						return 1, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				mExternal2 := mock_router.NewMockBatchConn(ctrl)
				mExternal2.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mExternal2.EXPECT().WriteBatch(gomock.Any(), 0).DoAndReturn(
					func(ms underlayconn.Messages, flags int) (int, error) {
						if len(ms) != 1 {
							assert.Fail(t, "len(ms)!=1", len(ms))
							return 0, nil
						}
						s := slayers.SCION{}
						hbh := slayers.HopByHopExtn{}
						_, err := router.DecodeLayers(ms[0].Buffers[0], &s, &hbh)
						assert.NoError(t, err)

						containsFabrid := false
						containsIdentifier := false
						var foundIdentifier *extension.IdentifierOption
						var foundFabrid *extension.FabridOption

						baseTs := infoField.Timestamp
						for _, hbhOption := range hbh.Options {
							switch hbhOption.OptType {
							case slayers.OptTypeIdentifier:
								containsIdentifier = true
								foundIdentifier, err = extension.ParseIdentifierOption(hbhOption, baseTs)
								assert.NoError(t, err)
								assert.Equal(t, identifier.Timestamp, foundIdentifier.Timestamp)
								assert.Equal(t, identifier.PacketID, foundIdentifier.PacketID)
							case slayers.OptTypeFabrid:
								containsFabrid = true
								if containsIdentifier {
									foundFabrid, err = extension.ParseFabridOptionFullExtension(hbhOption, 3)
									assert.NoError(t, err)
									meta := foundFabrid.HopfieldMetadata[1]
									tmp := make([]byte, 100)
									recomputedVerifiedHVF := &extension.FabridHopfieldMetadata{
										EncryptedPolicyID: encPolicyID,
										FabridEnabled:     true,
									}
									err = fabrid.ComputeVerifiedHVF(recomputedVerifiedHVF, foundIdentifier, &s, tmp, asToHostKey[:], 3, 4)
									assert.NoError(t, err)
									assert.Equal(t, encPolicyID, meta.EncryptedPolicyID)
									assert.Equal(t, recomputedVerifiedHVF.HopValidationField, meta.HopValidationField)
								} else {
									assert.Fail(t, "identifier not present before fabrid")
								}
							}
						}
						assert.True(t, containsIdentifier)
						assert.True(t, containsFabrid)

						done <- struct{}{}
						return 1, nil
					}).Times(1)
				mExternal2.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				_ = ret.AddExternalInterface(3, mExternal)
				_ = ret.AddLinkType(3, topology.Core)
				_ = ret.AddExternalInterface(4, mExternal2)
				_ = ret.AddLinkType(4, topology.Core)

				_ = ret.SetIA(local)
				_ = ret.SetKey(key)
				return ret
			},
		},
		"fabrid mpls ingress egress different router": {
			prepareDP: func(c1 *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}
				key := []byte("testkey_xxxxxxxx")
				dstIA := xtest.MustParseIA("4-ff00:0:411")
				dstAddr := addr.MustParseHost("2.2.2.2")
				srcIA := xtest.MustParseIA("2-ff00:0:222")
				srcAddr := addr.MustParseHost("1.1.1.1")

				asDRKey := [16]byte{
					0x00, 0x11, 0x22, 0x33,
					0x44, 0x55, 0x66, 0x77,
					0x88, 0x99, 0xaa, 0xbb,
					0xcc, 0xdd, 0xee, 0xff,
				}
				_ = ret.AddDRKeySecret(int32(drkey.FABRID),
					control.SecretValue{
						Key:        asDRKey,
						EpochBegin: time.Now().Add(-time.Second),
						EpochEnd:   time.Now().AddDate(1, 0, 0),
					})
				local := xtest.MustParseIA("1-ff00:0:110")
				now := time.Now().Truncate(time.Millisecond)
				identifier := extension.IdentifierOption{
					Timestamp:     now,
					PacketID:      0xabcd,
					BaseTimestamp: uint32(now.Unix()),
				}

				policyID := fabrid.FabridPolicyID{
					ID: 0x0f,
				}
				ret.UpdateFabridPolicies(nil,
					map[uint64]uint32{
						3<<24 + 2<<8 + 0x0f: 7,
					})

				asToHostKey, err := ret.DeriveASToHostKey(int32(drkey.FABRID), now,
					srcIA, srcAddr.String())
				assert.NoError(t, err)
				encPolicyID, err := fabrid.EncryptPolicyID(&policyID, &identifier, asToHostKey[:])
				assert.NoError(t, err)

				mExternal := mock_router.NewMockBatchConn(ctrl)
				infoField := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)}

				mExternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						buf := gopacket.NewSerializeBuffer()
						path := &scion.Decoded{
							Base: scion.Base{
								PathMeta: scion.MetaHdr{
									CurrHF: 1,
									SegLen: [3]uint8{3, 0, 0},
								},
								NumINF:  1,
								NumHops: 3,
							},
							InfoFields: []path.InfoField{
								infoField,
							},
							HopFields: []path.HopField{
								{ConsIngress: 1, ConsEgress: 2},
								{ConsIngress: 3, ConsEgress: 2},
								{ConsIngress: 5, ConsEgress: 6},
							},
						}
						path.HopFields[1].Mac = computeMAC(t, key, path.InfoFields[0], path.HopFields[1])
						rawDstAddr := dstAddr.IP().As4()
						rawSrcAddr := srcAddr.IP().As4()
						s := slayers.SCION{
							NextHdr:     slayers.HopByHopClass,
							PathType:    scion.PathType,
							DstIA:       dstIA,
							SrcIA:       srcIA,
							SrcAddrType: slayers.T4Ip,
							DstAddrType: slayers.T4Ip,
							RawSrcAddr:  rawSrcAddr[:],
							RawDstAddr:  rawDstAddr[:],
							Path:        path,
						}

						identifierData := make([]byte, 8)
						identifier.Serialize(identifierData)

						meta := &extension.FabridHopfieldMetadata{
							EncryptedPolicyID: encPolicyID,
							FabridEnabled:     true,
						}
						tmp := make([]byte, 100)
						err = fabrid.ComputeBaseHVF(meta, &identifier, &s, tmp, asToHostKey[:], 3, 2)
						assert.NoError(t, err)

						fabrid := extension.FabridOption{
							HopfieldMetadata: []*extension.FabridHopfieldMetadata{
								{},
								meta,
								{},
							},
						}
						fabridData := make([]byte, 16)
						fabrid.SerializeTo(fabridData)
						hbh := slayers.HopByHopExtn{
							Options: []*slayers.HopByHopOption{
								{
									OptType:    slayers.OptTypeIdentifier,
									OptData:    identifierData,
									OptDataLen: uint8(len(identifierData)),
								},
								{
									OptType:    slayers.OptTypeFabrid,
									OptData:    fabridData,
									OptDataLen: uint8(len(fabridData)),
								},
							},
						}
						err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &s, &hbh)
						assert.NoError(t, err)
						raw := buf.Bytes()
						copy(m[0].Buffers[0], raw)
						m[0].N = len(raw)
						m[0].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}

						return 1, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mInternal.EXPECT().SetToS(uint8(7)).Times(1)
				mInternal.EXPECT().WriteBatch(gomock.Any(), 0).DoAndReturn(
					func(ms underlayconn.Messages, flags int) (int, error) {
						if len(ms) != 1 {
							assert.Fail(t, "len(ms)!=1", len(ms))
							return 0, nil
						}
						s := slayers.SCION{}
						hbh := slayers.HopByHopExtn{}
						_, err := router.DecodeLayers(ms[0].Buffers[0], &s, &hbh)
						assert.NoError(t, err)

						containsFabrid := false
						containsIdentifier := false
						var foundIdentifier *extension.IdentifierOption
						var foundFabrid *extension.FabridOption

						baseTs := infoField.Timestamp
						for _, hbhOption := range hbh.Options {
							switch hbhOption.OptType {
							case slayers.OptTypeIdentifier:
								containsIdentifier = true
								foundIdentifier, err = extension.ParseIdentifierOption(hbhOption, baseTs)
								assert.NoError(t, err)
								assert.Equal(t, identifier.Timestamp, foundIdentifier.Timestamp)
								assert.Equal(t, identifier.PacketID, foundIdentifier.PacketID)
							case slayers.OptTypeFabrid:
								containsFabrid = true
								if containsIdentifier {
									foundFabrid, err = extension.ParseFabridOptionFullExtension(hbhOption, 3)
									assert.NoError(t, err)
									meta := foundFabrid.HopfieldMetadata[1]
									tmp := make([]byte, 100)
									recomputedVerifiedHVF := &extension.FabridHopfieldMetadata{
										EncryptedPolicyID: encPolicyID,
										FabridEnabled:     true,
									}
									err = fabrid.ComputeVerifiedHVF(recomputedVerifiedHVF, foundIdentifier, &s, tmp, asToHostKey[:], 3, 2)
									assert.NoError(t, err)
									assert.Equal(t, encPolicyID, meta.EncryptedPolicyID)
									assert.Equal(t, recomputedVerifiedHVF.HopValidationField, meta.HopValidationField)
								} else {
									assert.Fail(t, "identifier not present before fabrid")
								}
							}
						}
						assert.True(t, containsIdentifier)
						assert.True(t, containsFabrid)

						done <- struct{}{}
						return 1, nil
					}).Times(1)
				_ = ret.AddInternalInterface(mInternal, net.IP{})

				_ = ret.AddExternalInterface(3, mExternal)
				_ = ret.AddLinkType(3, topology.Core)

				_ = ret.SetIA(local)
				_ = ret.SetKey(key)

				err = ret.AddNextHop(2, xtest.MustParseUDPAddr(t, "127.0.0.2:8888"))
				assert.NoError(t, err)
				err = ret.AddLinkType(2, topology.Core)
				assert.NoError(t, err)
				return ret
			},
		},
		"fabrid mpls internal traffic": {
			prepareDP: func(c1 *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}
				key := []byte("testkey_xxxxxxxx")
				dstIA := xtest.MustParseIA("4-ff00:0:411")
				dstAddr := addr.MustParseHost("2.2.2.2")
				srcIA := xtest.MustParseIA("2-ff00:0:222")
				srcAddr := addr.MustParseHost("1.1.1.1")

				asDRKey := [16]byte{
					0x00, 0x11, 0x22, 0x33,
					0x44, 0x55, 0x66, 0x77,
					0x88, 0x99, 0xaa, 0xbb,
					0xcc, 0xdd, 0xee, 0xff,
				}
				_ = ret.AddDRKeySecret(int32(drkey.FABRID),
					control.SecretValue{
						Key:        asDRKey,
						EpochBegin: time.Now().Add(-time.Second),
						EpochEnd:   time.Now().AddDate(1, 0, 0),
					})
				local := dstIA
				now := time.Now().Truncate(time.Millisecond)
				identifier := extension.IdentifierOption{
					Timestamp:     now,
					PacketID:      0xabcd,
					BaseTimestamp: uint32(now.Unix()),
				}

				policyID := fabrid.FabridPolicyID{
					ID: 0x0f,
				}
				_, ipPrefix, _ := net.ParseCIDR("2.2.2.0/24")
				ret.UpdateFabridPolicies(map[uint32][]*control.PolicyIPRange{
					// ingress 3 with policy index 0x0f
					(3<<8 + 0x0f): {
						{
							MPLSLabel: 7,
							IPPrefix:  ipPrefix,
						},
					},
				}, nil)

				asToHostKey, err := ret.DeriveASToHostKey(int32(drkey.FABRID), now,
					srcIA, srcAddr.String())
				assert.NoError(t, err)
				encPolicyID, err := fabrid.EncryptPolicyID(&policyID, &identifier, asToHostKey[:])
				assert.NoError(t, err)

				mExternal := mock_router.NewMockBatchConn(ctrl)
				infoField := path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)}

				mExternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						buf := gopacket.NewSerializeBuffer()
						path := &scion.Decoded{
							Base: scion.Base{
								PathMeta: scion.MetaHdr{
									CurrHF: 2,
									SegLen: [3]uint8{3, 0, 0},
								},
								NumINF:  1,
								NumHops: 3,
							},
							InfoFields: []path.InfoField{
								infoField,
							},
							HopFields: []path.HopField{
								{ConsIngress: 1, ConsEgress: 2},
								{ConsIngress: 3, ConsEgress: 4},
								{ConsIngress: 3, ConsEgress: 0},
							},
						}
						path.HopFields[2].Mac = computeMAC(t, key, path.InfoFields[0], path.HopFields[2])
						rawDstAddr := dstAddr.IP().As4()
						rawSrcAddr := srcAddr.IP().As4()
						s := slayers.SCION{
							NextHdr:     slayers.HopByHopClass,
							PathType:    scion.PathType,
							DstIA:       dstIA,
							SrcIA:       srcIA,
							SrcAddrType: slayers.T4Ip,
							DstAddrType: slayers.T4Ip,
							RawSrcAddr:  rawSrcAddr[:],
							RawDstAddr:  rawDstAddr[:],
							Path:        path,
						}

						identifierData := make([]byte, 8)
						identifier.Serialize(identifierData)

						meta := &extension.FabridHopfieldMetadata{
							EncryptedPolicyID: encPolicyID,
							FabridEnabled:     true,
						}
						tmp := make([]byte, 100)
						err = fabrid.ComputeBaseHVF(meta, &identifier, &s, tmp, asToHostKey[:], 3, 0)
						assert.NoError(t, err)

						fabrid := extension.FabridOption{
							HopfieldMetadata: []*extension.FabridHopfieldMetadata{
								{},
								{},
								meta,
							},
						}
						fabridData := make([]byte, 16)
						fabrid.SerializeTo(fabridData)
						hbh := slayers.HopByHopExtn{
							Options: []*slayers.HopByHopOption{
								{
									OptType:    slayers.OptTypeIdentifier,
									OptData:    identifierData,
									OptDataLen: uint8(len(identifierData)),
								},
								{
									OptType:    slayers.OptTypeFabrid,
									OptData:    fabridData,
									OptDataLen: uint8(len(fabridData)),
								},
							},
						}
						err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &s, &hbh)
						assert.NoError(t, err)
						raw := buf.Bytes()
						copy(m[0].Buffers[0], raw)
						m[0].N = len(raw)
						m[0].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}

						return 1, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mInternal.EXPECT().SetToS(uint8(7)).Times(1)
				mInternal.EXPECT().WriteBatch(gomock.Any(), 0).DoAndReturn(
					func(ms underlayconn.Messages, flags int) (int, error) {
						if len(ms) != 1 {
							assert.Fail(t, "len(ms)!=1", len(ms))
							return 0, nil
						}
						s := slayers.SCION{}
						hbh := slayers.HopByHopExtn{}
						_, err := router.DecodeLayers(ms[0].Buffers[0], &s, &hbh)
						assert.NoError(t, err)

						containsFabrid := false
						containsIdentifier := false
						var foundIdentifier *extension.IdentifierOption
						var foundFabrid *extension.FabridOption

						baseTs := infoField.Timestamp
						for _, hbhOption := range hbh.Options {
							switch hbhOption.OptType {
							case slayers.OptTypeIdentifier:
								containsIdentifier = true
								foundIdentifier, err = extension.ParseIdentifierOption(hbhOption, baseTs)
								assert.NoError(t, err)
								assert.Equal(t, identifier.Timestamp, foundIdentifier.Timestamp)
								assert.Equal(t, identifier.PacketID, foundIdentifier.PacketID)
							case slayers.OptTypeFabrid:
								containsFabrid = true
								if containsIdentifier {
									foundFabrid, err = extension.ParseFabridOptionFullExtension(hbhOption, 3)
									assert.NoError(t, err)
									meta := foundFabrid.HopfieldMetadata[2]
									tmp := make([]byte, 100)
									recomputedVerifiedHVF := &extension.FabridHopfieldMetadata{
										EncryptedPolicyID: encPolicyID,
										FabridEnabled:     true,
									}
									err = fabrid.ComputeVerifiedHVF(recomputedVerifiedHVF, foundIdentifier, &s, tmp, asToHostKey[:], 3, 0)
									assert.NoError(t, err)
									assert.Equal(t, encPolicyID, meta.EncryptedPolicyID)
									assert.Equal(t, recomputedVerifiedHVF.HopValidationField, meta.HopValidationField)
								} else {
									assert.Fail(t, "identifier not present before fabrid")
								}
							}
						}
						assert.True(t, containsIdentifier)
						assert.True(t, containsFabrid)

						done <- struct{}{}
						return 1, nil
					}).Times(1)
				_ = ret.AddInternalInterface(mInternal, net.IP{})

				_ = ret.AddExternalInterface(3, mExternal)
				_ = ret.AddLinkType(3, topology.Core)

				_ = ret.SetIA(local)
				_ = ret.SetKey(key)

				err = ret.AddNextHop(2, xtest.MustParseUDPAddr(t, "127.0.0.2:8888"))
				assert.NoError(t, err)
				err = ret.AddLinkType(2, topology.Core)
				assert.NoError(t, err)
				return ret
			},
		},
		"route 10 msg from external to internal": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}
				key := []byte("testkey_xxxxxxxx")
				local := xtest.MustParseIA("1-ff00:0:110")

				totalCount := 10
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mInternal.EXPECT().WriteBatch(gomock.Any(), 0).DoAndReturn(
					func(ms underlayconn.Messages, flags int) (int, error) {
						if totalCount == 0 {
							t.Fail()
							return 0, nil
						}
						for _, msg := range ms {
							want := bytes.Repeat([]byte("actualpayloadbytes"), 10-totalCount)
							if len(msg.Buffers[0]) != len(want)+84 {
								return 1, nil
							}
							totalCount--
							if totalCount == 0 {
								done <- struct{}{}
							}
						}
						return len(ms), nil
					}).AnyTimes()
				_ = ret.AddInternalInterface(mInternal, net.IP{})

				mExternal := mock_router.NewMockBatchConn(ctrl)
				mExternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						// 10 scion messages to external
						for i := 0; i < totalCount; i++ {
							spkt, dpath := prepBaseMsg(time.Now())
							spkt.DstIA = local
							dpath.HopFields = []path.HopField{
								{ConsIngress: 41, ConsEgress: 40},
								{ConsIngress: 31, ConsEgress: 30},
								{ConsIngress: 1, ConsEgress: 0},
							}
							dpath.Base.PathMeta.CurrHF = 2
							dpath.HopFields[2].Mac = computeMAC(t, key,
								dpath.InfoFields[0], dpath.HopFields[2])
							spkt.Path = dpath
							payload := bytes.Repeat([]byte("actualpayloadbytes"), i)
							buffer := gopacket.NewSerializeBuffer()
							err := gopacket.SerializeLayers(buffer,
								gopacket.SerializeOptions{FixLengths: true},
								spkt, gopacket.Payload(payload))
							require.NoError(t, err)
							raw := buffer.Bytes()
							copy(m[i].Buffers[0], raw)
							m[i].N = len(raw)
							m[i].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
						}
						return 10, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				_ = ret.AddExternalInterface(1, mExternal)

				_ = ret.SetIA(local)
				_ = ret.SetKey(key)
				return ret
			},
		},
		"bfd bootstrap internal session": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}

				postInternalBFD := func(id layers.BFDDiscriminator, src *net.UDPAddr) []byte {
					scn := &slayers.SCION{
						NextHdr:  slayers.L4BFD,
						PathType: empty.PathType,
						Path:     &empty.Path{},
					}
					bfdL := &layers.BFD{
						Version:           1,
						DetectMultiplier:  layers.BFDDetectMultiplier(2),
						MyDiscriminator:   id,
						YourDiscriminator: 0,
					}

					srcIP, _ := netip.AddrFromSlice(src.IP)
					_ = scn.SetSrcAddr(addr.HostIP(srcIP))
					buffer := gopacket.NewSerializeBuffer()
					_ = gopacket.SerializeLayers(buffer,
						gopacket.SerializeOptions{FixLengths: true}, scn, bfdL)
					return buffer.Bytes()
				}

				mtx := sync.Mutex{}
				expectRemoteDiscriminators := map[layers.BFDDiscriminator]struct{}{}
				routers := map[net.Addr][]uint16{
					&net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4()}: {2, 3},
					&net.UDPAddr{IP: net.ParseIP("10.0.200.201").To4()}: {4},
				}

				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						i := 0
						for k := range routers { // post a BFD from each neighbor router
							disc := layers.BFDDiscriminator(i)
							raw := postInternalBFD(disc, k.(*net.UDPAddr))
							copy(m[i].Buffers[0], raw)
							m[i].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
							m[i].Buffers[0] = m[i].Buffers[0][:len(raw)]
							m[i].N = len(raw)
							expectRemoteDiscriminators[disc] = struct{}{}
							i++
						}
						return len(routers), nil
					},
				).Times(1)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mInternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(
					func(data []byte, _ net.Addr) (int, error) {
						pkt := gopacket.NewPacket(data,
							slayers.LayerTypeSCION, gopacket.Default)
						if b := pkt.Layer(layers.LayerTypeBFD); b != nil {
							v := b.(*layers.BFD).YourDiscriminator
							mtx.Lock()
							defer mtx.Unlock()
							delete(expectRemoteDiscriminators, v)
							if len(expectRemoteDiscriminators) == 0 {
								done <- struct{}{}
							}
							return 1, nil
						}

						return 0, fmt.Errorf("no valid BFD message")
					}).MinTimes(1)
				mInternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				local := &net.UDPAddr{IP: net.ParseIP("10.0.200.100").To4()}
				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, net.IP{})
				for remote, ifIDs := range routers {
					for _, ifID := range ifIDs {
						_ = ret.AddNextHop(ifID, remote.(*net.UDPAddr))
						_ = ret.AddNextHopBFD(ifID, local, remote.(*net.UDPAddr), bfd(), "")
					}
				}
				return ret
			},
		},
		"bfd sender internal": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}
				localAddr := &net.UDPAddr{IP: net.ParseIP("10.0.200.100").To4()}
				remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4()}
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(
					func(data []byte, _ net.Addr) (int, error) {
						pkt := gopacket.NewPacket(data,
							slayers.LayerTypeSCION, gopacket.Default)

						if b := pkt.Layer(layers.LayerTypeBFD); b == nil {
							return 1, nil
						}

						if scnL := pkt.Layer(slayers.LayerTypeSCION); scnL != nil {
							s := scnL.(*slayers.SCION)
							a, err := s.SrcAddr()
							if err != nil {
								return 1, nil
							}
							if !bytes.Equal(a.IP().AsSlice(), localAddr.IP) {
								return 1, nil
							}

							b, err := s.DstAddr()
							if err != nil {
								return 1, nil
							}
							if !bytes.Equal(b.IP().AsSlice(), remoteAddr.IP) {
								return 1, nil
							}

							if s.PathType != empty.PathType {
								return 1, nil
							}
							if _, ok := s.Path.(empty.Path); !ok {
								return 1, nil
							}
						}
						done <- struct{}{}
						return 1, nil
					}).MinTimes(1)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, net.IP{})
				_ = ret.AddNextHop(3, localAddr)
				_ = ret.AddNextHopBFD(3, localAddr, remoteAddr, bfd(), "")

				return ret
			},
		},
		"bfd sender external": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}
				ifID := uint16(1)
				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mExternal := mock_router.NewMockBatchConn(ctrl)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()
				mExternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(
					func(data []byte, _ net.Addr) (int, error) {
						pkt := gopacket.NewPacket(data,
							slayers.LayerTypeSCION, gopacket.Default)

						if b := pkt.Layer(layers.LayerTypeBFD); b == nil {
							return 1, nil
						}

						if scnL := pkt.Layer(slayers.LayerTypeSCION); scnL != nil {
							s := scnL.(*slayers.SCION)
							if s.PathType != onehop.PathType {
								return 1, nil
							}

							v, ok := s.Path.(*onehop.Path)
							if !ok {
								return 1, nil
							}
							if v.FirstHop.ConsEgress != ifID {
								return 1, nil
							}
						}

						done <- struct{}{}
						return 1, nil
					}).MinTimes(1)
				mExternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				local := control.LinkEnd{
					IA:   xtest.MustParseIA("1-ff00:0:1"),
					Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.100")},
				}
				remote := control.LinkEnd{
					IA:   xtest.MustParseIA("1-ff00:0:3"),
					Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.200")},
				}
				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, net.IP{})
				_ = ret.AddExternalInterface(ifID, mExternal)
				_ = ret.AddExternalInterfaceBFD(ifID, mExternal, local, remote, bfd())

				return ret
			},
		},
		"bfd bootstrap external session": {
			prepareDP: func(ctrl *gomock.Controller, done chan<- struct{}) *router.DataPlane {
				ret := &router.DataPlane{Metrics: metrics}

				postExternalBFD := func(id layers.BFDDiscriminator, fromIfID uint16) []byte {
					scn := &slayers.SCION{
						NextHdr:  slayers.L4BFD,
						PathType: onehop.PathType,
						Path: &onehop.Path{
							FirstHop: path.HopField{ConsEgress: fromIfID},
						},
					}
					bfdL := &layers.BFD{
						Version:           1,
						DetectMultiplier:  layers.BFDDetectMultiplier(2),
						MyDiscriminator:   id,
						YourDiscriminator: 0,
					}

					buffer := gopacket.NewSerializeBuffer()
					_ = gopacket.SerializeLayers(buffer,
						gopacket.SerializeOptions{FixLengths: true}, scn, bfdL)
					return buffer.Bytes()
				}

				mInternal := mock_router.NewMockBatchConn(ctrl)
				mInternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mtx := sync.Mutex{}
				expectRemoteDiscriminators := map[int]struct{}{}

				mExternal := mock_router.NewMockBatchConn(ctrl)
				mExternal.EXPECT().ReadBatch(gomock.Any()).DoAndReturn(
					func(m underlayconn.Messages) (int, error) {
						raw := postExternalBFD(2, 1)
						expectRemoteDiscriminators[2] = struct{}{}
						copy(m[0].Buffers[0], raw)
						m[0].Buffers[0] = m[0].Buffers[0][:len(raw)]
						m[0].N = len(raw)
						m[0].Addr = &net.UDPAddr{IP: net.IP{10, 0, 200, 200}}
						return 1, nil
					},
				).Times(1)
				mExternal.EXPECT().ReadBatch(gomock.Any()).Return(0, nil).AnyTimes()

				mExternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(
					func(data []byte, _ net.Addr) (int, error) {
						pkt := gopacket.NewPacket(data,
							slayers.LayerTypeSCION, gopacket.Default)

						if b := pkt.Layer(layers.LayerTypeBFD); b != nil {
							v := int(b.(*layers.BFD).YourDiscriminator)
							mtx.Lock()
							defer mtx.Unlock()
							delete(expectRemoteDiscriminators, v)
							if len(expectRemoteDiscriminators) == 0 {
								done <- struct{}{}
							}
							return 1, nil
						}
						return 0, fmt.Errorf("no valid BFD message")
					}).MinTimes(1)
				mExternal.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()

				local := control.LinkEnd{
					IA:   xtest.MustParseIA("1-ff00:0:1"),
					Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.100")},
				}
				remote := control.LinkEnd{
					IA:   xtest.MustParseIA("1-ff00:0:3"),
					Addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.200")},
				}
				_ = ret.SetKey([]byte("randomkeyformacs"))
				_ = ret.AddInternalInterface(mInternal, net.IP{})
				_ = ret.AddExternalInterface(1, mExternal)
				_ = ret.AddExternalInterfaceBFD(1, mExternal, local, remote, bfd())

				return ret
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runConfig := &router.RunConfig{
				NumProcessors:         8,
				BatchSize:             256,
				NumSlowPathProcessors: 1,
			}
			ch := make(chan struct{})
			dp := tc.prepareDP(ctrl, ch)
			errors := make(chan error)
			ctx, cancelF := context.WithCancel(context.Background())
			defer cancelF()
			go func() {
				errors <- dp.Run(ctx, runConfig)
			}()

			for done := false; !done; {
				select {
				case <-ch:
					done = true
				case err := <-errors:
					require.NoError(t, err)
				case <-time.After(3 * time.Second):
					t.Fatalf("time out")
				}
			}
		})
	}
}

func TestProcessPkt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	key := []byte("testkey_xxxxxxxx")
	otherKey := []byte("testkey_yyyyyyyy")
	now := time.Now()
	epicTS, err := libepic.CreateTimestamp(now, now)
	require.NoError(t, err)

	// ProcessPacket assumes some pre-conditions:
	// * The ingress interface has to exist. This fake map is good for most test cases.
	//   Others need a custom one.
	// * InternalNextHops may not be nil. Empty is ok (sufficient unless testing AS transit).
	fakeExternalInterfaces := map[uint16]router.BatchConn{1: nil, 2: nil, 3: nil}
	fakeInternalNextHops := map[uint16]*net.UDPAddr{}

	testCases := map[string]struct {
		mockMsg         func(bool) *ipv4.Message
		prepareDP       func(*gomock.Controller) *router.DataPlane
		srcInterface    uint16
		egressInterface uint16
		assertFunc      assert.ErrorAssertionFunc
	}{
		"inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				dst := addr.MustParseHost("10.0.100.100")
				_ = spkt.SetDstAddr(dst)
				dpath.HopFields = []path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 0},
				}
				dpath.Base.PathMeta.CurrHF = 2
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: topology.EndhostPort}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []path.HopField{
					{ConsIngress: 0, ConsEgress: 1},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 41, ConsEgress: 40},
				}
				dpath.Base.PathMeta.CurrHF = 0
				dpath.HopFields[0].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[0])
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath()
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[0].Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    0,
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
		"brtransit": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Parent,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
				dpath.HopFields = []path.HopField{
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 2},
					{ConsIngress: 40, ConsEgress: 41},
				}
				dpath.Base.PathMeta.CurrHF = 1
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath()
				dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"brtransit non consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						2: topology.Parent,
						1: topology.Child,
					}, nil,
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
				dpath.HopFields = []path.HopField{
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 2, ConsEgress: 1},
					{ConsIngress: 40, ConsEgress: 41},
				}
				dpath.Base.PathMeta.CurrHF = 1
				dpath.InfoFields[0].ConsDir = false
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].Mac)
					return toMsg(t, spkt, dpath)
				}
				require.NoError(t, dpath.IncPath())
				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"brtransit peering consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet just left segment 0 which ends at
				// (peering) hop 0 and is landing on segment 1 which
				// begins at (peering) hop 1. We do not care what hop 0
				// looks like. The forwarding code is looking at hop 1 and
				// should leave the message in shape to be processed at hop 2.
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF:  1,
							CurrINF: 1,
							SegLen:  [3]uint8{1, 2, 0},
						},
						NumINF:  2,
						NumHops: 3,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []path.HopField{
						{ConsIngress: 31, ConsEgress: 30},
						{ConsIngress: 1, ConsEgress: 2},
						{ConsIngress: 40, ConsEgress: 41},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the second one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].Mac = computeMAC(
					t, key, dpath.InfoFields[1], dpath.HopFields[1])
				dpath.HopFields[2].Mac = computeMAC(
					t, otherKey, dpath.InfoFields[1], dpath.HopFields[2])
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath()

				// ... The SegID accumulator wasn't updated from HF[1],
				// it is still the same. That is the key behavior.

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1, // from peering link
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"brtransit peering non consdir": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet lands on the last (peering) hop of
				// segment 0. After processing, the packet is ready to
				// be processed by the first (peering) hop of segment 1.
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF:  1,
							CurrINF: 0,
							SegLen:  [3]uint8{2, 1, 0},
						},
						NumINF:  2,
						NumHops: 3,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []path.HopField{
						{ConsIngress: 31, ConsEgress: 30},
						{ConsIngress: 1, ConsEgress: 2},
						{ConsIngress: 40, ConsEgress: 41},
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (0 and 1) derive from the same SegID
				// accumulator value. However, the forwarding code isn't
				// supposed to even look at the first one. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[0].Mac = computeMAC(
					t, otherKey, dpath.InfoFields[0], dpath.HopFields[0])
				dpath.HopFields[1].Mac = computeMAC(
					t, key, dpath.InfoFields[0], dpath.HopFields[1])

				// We're going against construction order, so the accumulator
				// value is that of the previous hop in traversal order. The
				// story starts with the packet arriving at hop 1, so the
				// accumulator value must match hop field 0. In this case,
				// it is identical to that for hop field 1, which we made
				// identical to the original SegID. So, we're all set.
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}

				_ = dpath.IncPath()

				// The SegID should not get updated on arrival. If it is, then MAC validation
				// of HF1 will fail. Otherwise, this isn't visible because we changed segment.

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    2, // from child link
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
		"peering consdir downstream": {
			// Similar to previous test case but looking at what
			// happens on the next hop.
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet just left hop 1 (the first hop
				// of peering down segment 1) and is processed at hop 2
				// which is not a peering hop.
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF:  2,
							CurrINF: 1,
							SegLen:  [3]uint8{1, 3, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
						// core seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []path.HopField{
						{ConsIngress: 31, ConsEgress: 30},
						{ConsIngress: 40, ConsEgress: 41},
						{ConsIngress: 1, ConsEgress: 2},
						{ConsIngress: 50, ConsEgress: 51},
						// There has to be a 4th hop to make
						// the 3rd router agree that the packet
						// is not at destination yet.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The router shouldn't need to
				// know this or do anything special. The SegID
				// accumulator value can be anything (it comes from the
				// parent hop of HF[1] in the original beaconned segment,
				// which is not in the path). So, we use one from an
				// info field because computeMAC makes that easy.
				dpath.HopFields[1].Mac = computeMAC(
					t, otherKey, dpath.InfoFields[1], dpath.HopFields[1])
				dpath.HopFields[2].Mac = computeMAC(
					t, key, dpath.InfoFields[1], dpath.HopFields[2])
				if !afterProcessing {
					// The SegID we provide is that of HF[2] which happens to be SEG[1]'s SegID,
					// so, already set.
					return toMsg(t, spkt, dpath)
				}
				_ = dpath.IncPath()

				// ... The SegID accumulator should have been updated.
				dpath.InfoFields[1].UpdateSegID(dpath.HopFields[2].Mac)

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"peering non consdir upstream": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						1: topology.Peer,
						2: topology.Child,
					},
					nil,
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				// Story: the packet lands on the second (non-peering) hop of
				// segment 0 (a peering segment). After processing, the packet
				// is ready to be processed by the third (peering) hop of segment 0.
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF:  1,
							CurrINF: 0,
							SegLen:  [3]uint8{3, 1, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now), Peer: true},
						// down seg
						{SegID: 0x222, ConsDir: true, Timestamp: util.TimeToSecs(now), Peer: true},
					},
					HopFields: []path.HopField{
						{ConsIngress: 31, ConsEgress: 30},
						{ConsIngress: 1, ConsEgress: 2},
						{ConsIngress: 40, ConsEgress: 41},
						{ConsIngress: 50, ConsEgress: 51},
						// The second segment (4th hop) has to be
						// there but the packet isn't processed
						// at that hop for this test.
					},
				}

				// Make obvious the unusual aspect of the path: two
				// hopfield MACs (1 and 2) derive from the same SegID
				// accumulator value. The SegID accumulator value can
				// be anything (it comes from the parent hop of HF[1]
				// in the original beaconned segment, which is not in
				// the path). So, we use one from an info field because
				// computeMAC makes that easy.
				dpath.HopFields[1].Mac = computeMAC(
					t, key, dpath.InfoFields[0], dpath.HopFields[1])
				dpath.HopFields[2].Mac = computeMAC(
					t, otherKey, dpath.InfoFields[0], dpath.HopFields[2])

				if !afterProcessing {
					// We're going against construction order, so the
					// before-processing accumulator value is that of
					// the previous hop in traversal order. The story
					// starts with the packet arriving at hop 1, so the
					// accumulator value must match hop field 0, which
					// derives from hop field[1]. HopField[0]'s MAC is
					// not checked during this test.
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[1].Mac)

					return toMsg(t, spkt, dpath)
				}

				_ = dpath.IncPath()

				// After-processing, the SegID should have been updated
				// (on ingress) to be that of HF[1], which happens to be
				// the Segment's SegID. That is what we already have as
				// we only change it in the before-processing version
				// of the packet.

				ret := toMsg(t, spkt, dpath)
				ret.Addr = nil
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    2, // from child link
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
		"astransit direct": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
						// Interface 3 isn't in the external interfaces of this router
						// another router has it.
					},
					map[uint16]topology.LinkType{
						1: topology.Core,
						3: topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(3): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
				dpath.HopFields = []path.HopField{
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 3},
					{ConsIngress: 50, ConsEgress: 51},
				}
				dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface:    1,
			egressInterface: 0, // Internal forward to the egress router
			assertFunc:      assert.NoError,
		},
		"astransit xover": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(51): mock_router.NewMockBatchConn(ctrl),
					},
					map[uint16]topology.LinkType{
						51: topology.Child,
						3:  topology.Core,
					},
					mock_router.NewMockBatchConn(ctrl),
					map[uint16]*net.UDPAddr{
						uint16(3): {IP: net.ParseIP("10.0.200.200").To4(), Port: 30043},
					}, nil, xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg(now)
				dpath := &scion.Decoded{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrHF: 2,
							SegLen: [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					InfoFields: []path.InfoField{
						// up seg
						{SegID: 0x111, ConsDir: false, Timestamp: util.TimeToSecs(now)},
						// core seg
						{SegID: 0x222, ConsDir: false, Timestamp: util.TimeToSecs(now)},
					},
					HopFields: []path.HopField{
						{ConsIngress: 0, ConsEgress: 1},  // IA 110
						{ConsIngress: 31, ConsEgress: 0}, // Src
						{ConsIngress: 0, ConsEgress: 51}, // Dst
						{ConsIngress: 3, ConsEgress: 0},  // IA 110
					},
				}
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				dpath.HopFields[3].Mac = computeMAC(t, key, dpath.InfoFields[1], dpath.HopFields[3])

				if !afterProcessing {
					dpath.InfoFields[0].UpdateSegID(dpath.HopFields[2].Mac)
					return toMsg(t, spkt, dpath)
				}
				require.NoError(t, dpath.IncPath())
				ret := toMsg(t, spkt, dpath)
				ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(), Port: 30043}
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    51, // == consEgress, bc non-consdir
			egressInterface: 0,  // Cross-over. The egress happens in the next segment.
			assertFunc:      assert.NoError,
		},
		"svc": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					map[addr.SVC][]*net.UDPAddr{
						addr.SvcCS: {
							&net.UDPAddr{
								IP:   net.ParseIP("10.0.200.200").To4(),
								Port: topology.EndhostPort,
							},
						},
					},
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, dpath := prepBaseMsg(now)
				_ = spkt.SetDstAddr(addr.MustParseHost("CS"))
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				dpath.HopFields = []path.HopField{
					{ConsIngress: 41, ConsEgress: 40},
					{ConsIngress: 31, ConsEgress: 30},
					{ConsIngress: 1, ConsEgress: 0},
				}
				dpath.Base.PathMeta.CurrHF = 2
				dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
				ret := toMsg(t, spkt, dpath)
				if afterProcessing {
					ret.Addr = &net.UDPAddr{IP: net.ParseIP("10.0.200.200").To4(),
						Port: topology.EndhostPort}
					ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				}
				return ret
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"onehop inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					fakeExternalInterfaces,
					nil,
					mock_router.NewMockBatchConn(ctrl), nil,
					map[addr.SVC][]*net.UDPAddr{
						addr.SvcCS: {&net.UDPAddr{
							IP:   net.ParseIP("172.0.2.10"),
							Port: topology.EndhostPort,
						}},
					},
					xtest.MustParseIA("1-ff00:0:110"),
					map[uint16]addr.IA{
						uint16(1): xtest.MustParseIA("1-ff00:0:111"),
					}, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = onehop.PathType
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:111")
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
				err := spkt.SetDstAddr(addr.HostSVC(addr.SvcCS.Multicast()))
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: 0x100,
					},
					FirstHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 0,
						ConsEgress:  21,
						Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
				}
				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				dpath.SecondHop = path.HopField{
					ExpTime:     63,
					ConsIngress: 1,
				}
				dpath.SecondHop.Mac = computeMAC(t, key, dpath.Info, dpath.SecondHop)

				sp, err := dpath.ToSCIONDecoded()
				require.NoError(t, err)
				_, err = sp.Reverse()
				require.NoError(t, err)

				ret := toMsg(t, spkt, dpath)
				ret.Addr = &net.UDPAddr{
					IP:   net.ParseIP("172.0.2.10"),
					Port: topology.EndhostPort,
				}
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"onehop inbound invalid src": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					fakeExternalInterfaces,
					nil, nil,
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"),
					map[uint16]addr.IA{
						uint16(1): xtest.MustParseIA("1-ff00:0:111"),
					}, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = onehop.PathType
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:110") // sneaky
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:111")
				err := spkt.SetDstAddr(addr.HostSVC(addr.SvcCS.Multicast()))
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: 0x100,
					},
					FirstHop: path.HopField{
						IngressRouterAlert: true,
						EgressRouterAlert:  true,
						ExpTime:            63,
						ConsIngress:        0,
						ConsEgress:         21,
						Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
				}
				return toMsg(t, spkt, dpath)
			},
			srcInterface:    2,
			egressInterface: 21,
			assertFunc:      assert.Error,
		},
		"reversed onehop outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(1): mock_router.NewMockBatchConn(ctrl),
					},
					nil,
					mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops,
					map[addr.SVC][]*net.UDPAddr{
						addr.SvcCS: {&net.UDPAddr{
							IP:   net.ParseIP("172.0.2.10"),
							Port: topology.EndhostPort,
						}},
					},
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = scion.PathType
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:110")
				err := spkt.SetDstAddr(addr.HostSVC(addr.SvcCS.Multicast()))
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: util.TimeToSecs(time.Now()),
					},
					FirstHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 0,
						ConsEgress:  21,
						Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
					SecondHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 1,
					},
				}
				dpath.SecondHop.Mac = computeMAC(t, key, dpath.Info, dpath.SecondHop)
				sp, err := dpath.ToSCIONDecoded()
				require.NoError(t, err)
				require.NoError(t, sp.IncPath())
				p, err := sp.Reverse()
				require.NoError(t, err)
				sp = p.(*scion.Decoded)

				if !afterProcessing {
					return toMsg(t, spkt, sp)
				}

				require.NoError(t, sp.IncPath())
				ret := toMsg(t, spkt, sp)
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    0,
			egressInterface: 1,
			assertFunc:      assert.NoError,
		},
		"onehop outbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(
					map[uint16]router.BatchConn{
						uint16(2): mock_router.NewMockBatchConn(ctrl),
					},
					nil,
					mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"),
					map[uint16]addr.IA{
						uint16(2): xtest.MustParseIA("1-ff00:0:111"),
					}, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, _ := prepBaseMsg(now)
				spkt.PathType = onehop.PathType
				spkt.SrcIA = xtest.MustParseIA("1-ff00:0:110")
				spkt.DstIA = xtest.MustParseIA("1-ff00:0:111")
				err := spkt.SetDstAddr(addr.HostSVC(addr.SvcCS.Multicast()))
				require.NoError(t, err)
				dpath := &onehop.Path{
					Info: path.InfoField{
						ConsDir:   true,
						SegID:     0x222,
						Timestamp: 0x100,
					},
					FirstHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 0,
						ConsEgress:  2,
					},
				}
				dpath.FirstHop.Mac = computeMAC(t, key, dpath.Info, dpath.FirstHop)

				if !afterProcessing {
					return toMsg(t, spkt, dpath)
				}
				dpath.Info.UpdateSegID(dpath.FirstHop.Mac)
				ret := toMsg(t, spkt, dpath)
				ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
				return ret
			},
			srcInterface:    0,
			egressInterface: 2,
			assertFunc:      assert.NoError,
		},
		"epic inbound": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)

				prepareEpicCrypto(t, spkt, epicpath, dpath, key)
				return toIP(t, spkt, epicpath, afterProcessing)
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.NoError,
		},
		"epic malformed path": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)
				prepareEpicCrypto(t, spkt, epicpath, dpath, key)

				// Wrong path type
				return toIP(t, spkt, &scion.Decoded{}, afterProcessing)
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.Error,
		},
		"epic invalid timestamp": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)

				// Invalid timestamp
				epicpath.PktID.Timestamp = epicpath.PktID.Timestamp + 250000

				prepareEpicCrypto(t, spkt, epicpath, dpath, key)
				return toIP(t, spkt, epicpath, afterProcessing)
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.Error,
		},
		"epic invalid LHVF": {
			prepareDP: func(ctrl *gomock.Controller) *router.DataPlane {
				return router.NewDP(fakeExternalInterfaces,
					nil, mock_router.NewMockBatchConn(ctrl),
					fakeInternalNextHops, nil,
					xtest.MustParseIA("1-ff00:0:110"), nil, key)
			},
			mockMsg: func(afterProcessing bool) *ipv4.Message {
				spkt, epicpath, dpath := prepEpicMsg(t,
					afterProcessing, key, epicTS, now)
				prepareEpicCrypto(t, spkt, epicpath, dpath, key)

				// Invalid LHVF
				epicpath.LHVF = []byte{0, 0, 0, 0}

				return toIP(t, spkt, epicpath, afterProcessing)
			},
			srcInterface:    1,
			egressInterface: 0,
			assertFunc:      assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dp := tc.prepareDP(ctrl)
			input, want := tc.mockMsg(false), tc.mockMsg(true)
			result, err := dp.ProcessPkt(tc.srcInterface, input)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			outPkt := &ipv4.Message{
				Buffers: [][]byte{result.OutPkt},
				Addr:    result.OutAddr,
			}
			if result.OutAddr == nil {
				outPkt.Addr = nil
			}
			assert.Equal(t, want, outPkt)
			assert.Equal(t, tc.egressInterface, result.EgressID)
		})
	}
}

func toMsg(t *testing.T, spkt *slayers.SCION, dpath path.Path) *ipv4.Message {
	t.Helper()
	ret := &ipv4.Message{}
	spkt.Path = dpath
	buffer := gopacket.NewSerializeBuffer()
	payload := []byte("actualpayloadbytes")
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		spkt, gopacket.Payload(payload))
	require.NoError(t, err)
	raw := buffer.Bytes()
	ret.Buffers = make([][]byte, 1)
	ret.Buffers[0] = make([]byte, 1500)
	copy(ret.Buffers[0], raw)
	ret.N = len(raw)
	ret.Buffers[0] = ret.Buffers[0][:ret.N]
	return ret
}

func prepBaseMsg(now time.Time) (*slayers.SCION, *scion.Decoded) {
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4UDP,
		PathType:     scion.PathType,
		DstIA:        xtest.MustParseIA("4-ff00:0:411"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
		PayloadLen:   18,
	}

	dpath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(now)},
		},

		HopFields: []path.HopField{},
	}
	return spkt, dpath
}

func prepEpicMsg(t *testing.T, afterProcessing bool, key []byte,
	epicTS uint32, now time.Time) (*slayers.SCION, *epic.Path, *scion.Decoded) {

	spkt, dpath := prepBaseMsg(now)
	spkt.PathType = epic.PathType

	spkt.DstIA = xtest.MustParseIA("1-ff00:0:110")
	dpath.HopFields = []path.HopField{
		{ConsIngress: 41, ConsEgress: 40},
		{ConsIngress: 31, ConsEgress: 30},
		{ConsIngress: 01, ConsEgress: 0},
	}
	dpath.Base.PathMeta.CurrHF = 2
	dpath.Base.PathMeta.CurrINF = 0

	pktID := epic.PktID{
		Timestamp: epicTS,
		Counter:   libepic.PktCounterFromCore(1, 2),
	}

	epicpath := &epic.Path{
		PktID: pktID,
		PHVF:  make([]byte, 4),
		LHVF:  make([]byte, 4),
	}
	require.NoError(t, spkt.SetSrcAddr(addr.MustParseHost("10.0.200.200")))

	spkt.Path = epicpath

	return spkt, epicpath, dpath
}

func prepareEpicCrypto(t *testing.T, spkt *slayers.SCION,
	epicpath *epic.Path, dpath *scion.Decoded, key []byte) {

	// Calculate SCION MAC
	dpath.HopFields[2].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])
	scionPath, err := dpath.ToRaw()
	require.NoError(t, err)
	epicpath.ScionPath = scionPath

	// Generate EPIC authenticator
	authLast := computeFullMAC(t, key, dpath.InfoFields[0], dpath.HopFields[2])

	// Calculate PHVF and LHVF
	macLast, err := libepic.CalcMac(authLast, epicpath.PktID,
		spkt, dpath.InfoFields[0].Timestamp, nil)
	require.NoError(t, err)
	copy(epicpath.LHVF, macLast)
}

func toIP(t *testing.T, spkt *slayers.SCION, path path.Path, afterProcessing bool) *ipv4.Message {
	// Encapsulate in IPv4
	dst := addr.MustParseHost("10.0.100.100")
	require.NoError(t, spkt.SetDstAddr(dst))
	ret := toMsg(t, spkt, path)
	if afterProcessing {
		ret.Addr = &net.UDPAddr{IP: dst.IP().AsSlice(), Port: topology.EndhostPort}
		ret.Flags, ret.NN, ret.N, ret.OOB = 0, 0, 0, nil
	}
	return ret
}

func computeMAC(t *testing.T, key []byte, info path.InfoField, hf path.HopField) [path.MacLen]byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.MAC(mac, info, hf, nil)
}

func computeFullMAC(t *testing.T, key []byte, info path.InfoField, hf path.HopField) []byte {
	mac, err := scrypto.InitMac(key)
	require.NoError(t, err)
	return path.FullMAC(mac, info, hf, nil)
}

func bfd() control.BFD {
	return control.BFD{
		DetectMult:            3,
		DesiredMinTxInterval:  1 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
	}
}
