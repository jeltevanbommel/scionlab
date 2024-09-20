// Copyright 2024 ETH Zurich
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

package router

import (
	"net"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid/crypto"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/router/control"
)

type transitType int

func (d *DataPlane) UpdateFabridPolicies(ipRangePolicies map[uint32][]*control.PolicyIPRange,
	interfacePolicies map[uint64]uint32) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	// TODO(rohrerj): check for concurrency issues
	// when an update happens during reading
	d.fabridPolicyIPRangeMap = ipRangePolicies
	d.fabridPolicyInterfaceMap = interfacePolicies
	return nil
}

func (p *scionPacketProcessor) processFabrid(egressIF uint16) error {
	meta := p.fabrid.HopfieldMetadata[0]
	src, err := p.scionLayer.SrcAddr()
	if err != nil {
		return err
	}
	var key [16]byte
	if p.fabrid.HopfieldMetadata[0].ASLevelKey {
		key, err = p.d.DRKeyProvider.DeriveASASKey(int32(drkey.FABRID), p.identifier.Timestamp,
			p.scionLayer.SrcIA)
	} else {
		key, err = p.d.DRKeyProvider.DeriveASHostKey(int32(drkey.FABRID), p.identifier.Timestamp,
			p.scionLayer.SrcIA, src.String())
	}
	if err != nil {
		return err
	}
	policyID, err := crypto.ComputePolicyID(meta, p.identifier, key[:])
	if err != nil {
		return err
	}
	err = crypto.VerifyAndUpdate(meta, p.identifier, &p.scionLayer, p.fabridInputBuffer, key[:],
		p.ingressID, egressIF)
	if err != nil {
		return err
	}
	// Check / set MPLS label only if policy ID != 0
	// and only if the packet will be sent within the AS or to another router of the local AS
	if policyID != 0 {
		var mplsLabel uint32
		switch p.transitType {
		case ingressEgressDifferentRouter:
			mplsLabel, err = p.d.getFabridMplsLabelForInterface(uint32(p.ingressID),
				uint32(policyID), uint32(egressIF))
		case internalTraffic:
			mplsLabel, err = p.d.getFabridMplsLabel(uint32(p.ingressID), uint32(policyID),
				p.nextHop.IP)
			if err != nil {
				mplsLabel, err = p.d.getFabridMplsLabelForInterface(uint32(p.ingressID),
					uint32(policyID), 0)
			}
		case ingressEgressSameRouter:
			return nil
		}
		if err != nil {
			return err
		}
		p.mplsLabel = mplsLabel
	}
	return nil
}

func (d *DataPlane) getFabridMplsLabelForInterface(ingressID uint32, policyIndex uint32,
	egressID uint32) (uint32, error) {

	policyMapKey := uint64(ingressID)<<24 + uint64(egressID)<<8 + uint64(policyIndex)
	mplsLabel, found := d.fabridPolicyInterfaceMap[policyMapKey]
	if !found {
		//lookup default (instead of using the ingressID as part of the key, use a 1 bit as MSB):
		policyMapKey = 1<<63 + uint64(egressID)<<8 + uint64(policyIndex)
		mplsLabel, found = d.fabridPolicyInterfaceMap[policyMapKey]
		if !found {
			return 0, serrors.New("Provided policyID is invalid",
				"ingress", ingressID, "index", policyIndex, "egress", egressID)
		}
	}
	return mplsLabel, nil
}

func (d *DataPlane) getFabridMplsLabel(ingressID uint32, policyIndex uint32,
	nextHopIP net.IP) (uint32, error) {

	policyMapKey := ingressID<<8 + policyIndex
	ipRanges, found := d.fabridPolicyIPRangeMap[policyMapKey]
	if !found {
		//lookup default (instead of using the ingressID as part of the key, use a 1 bit as MSB):
		policyMapKey = 1<<31 + policyIndex
		ipRanges, found = d.fabridPolicyIPRangeMap[policyMapKey]
		if !found {
			return 0, serrors.New("Provided policyID is invalid",
				"ingress", ingressID, "index", policyIndex)
		}
	}
	var bestRange *control.PolicyIPRange
	for _, r := range ipRanges {
		if r.IPPrefix.Contains(nextHopIP) {
			if bestRange == nil {
				bestRange = r
			} else {
				bestPrefixLength, _ := bestRange.IPPrefix.Mask.Size()
				currentPrefixLength, _ := r.IPPrefix.Mask.Size()
				if currentPrefixLength > bestPrefixLength {
					bestRange = r
				}
			}
		}
	}
	if bestRange == nil {
		return 0, serrors.New("Provided policy index is not valid for nexthop.",
			"index", policyIndex, "next hop IP", nextHopIP)
	}
	return bestRange.MPLSLabel, nil
}
