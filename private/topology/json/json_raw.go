package json

// An important distinguishing factor between internal underlays and external underlays is that
// a single internal underlay, e.g. the MPLS IP underlay,
// can have multiple different labels associated with the underlay.
// That means that there can be different next hop addresses as well. These choices are exposed
// via FABRID for intra-AS paths. Inter-AS paths can simply leverage the interfaces mechanism
// already present, and will thus have a single label associated.
// In a similar vein, an ethernet underlay internally can also have multiple next hop addresses
// associated with different border routers. For an inter-AS connection there will only be two
// border routers on the connection, and thus only one next hop address.
// TLDR; InternalUnderlays can also be used for one to many connections, ExternalUnderlays
// are one to one connections.

// InternalUnderlay is a data structure describing an alternative AS-internal underlay,
// i.e. a raw underlay that can be used instead of the regular IP UDP underlay.
type InternalUnderlay struct {
	// The type of the underlay, i.e. raw_mplsipudp, raw_dot1q, raw_ethernet
	Type string `json:"type,omitempty"`
	// The local address of the underlay, in the case of an IP-based protocol this will be an IP
	// address. For other protocols, e.g. those without IP, the local address can be omitted.
	Local string `json:"local,omitempty"`
	// The remote address of the underlay, in the case of an IP-based protocol this will be an IP
	// address. For other protocols, e.g. those without IP, the remote address can be omitted.
	Remote string `json:"remote,omitempty"`
	// The next hop address of the underlay, this will be the MAC address. For some protocols,
	// such as MPLS, more fine-grained configuration is required as there can be a different
	// next hop address for different MPLS labels, in this case the attribute can be omitted.
	NextHop string `json:"nexthop,omitempty"`
	// The name of the hardware interface the source should use to reach the destination.
	Interface string `json:"interface,omitempty"`
	// Optional, used for MPLS, a map mapping the labels this connection supports to the next hop
	// MAC addresses for each of these labels. This allows a different MPLS label to be sent to a
	// different router. If a different hardware interface is required, create a new alt underlay
	// for that interface and label.
	MplsNextHops map[uint32]string `json:"mpls_nexthops,omitempty"`
}

// ExternalUnderlay is a data structure describing an alternative border-router to border router
// underlay, i.e. a raw underlay that can be used instead of the regular IP UDP underlay.
type ExternalUnderlay struct {
	// The type of the underlay, i.e. raw_mplsipudp, raw_dot1q, raw_ethernet, default
	Type string `json:"type,omitempty"`
	// The local address of the underlay, in the case of an IP-based protocol this will be an IP
	// address. For other protocols, e.g. those without IP, the local address can be omitted.
	Local            string `json:"local,omitempty"`
	DeprecatedBind   string `json:"bind,omitempty"`   // superseded by "local", for backwards compat
	DeprecatedPublic string `json:"public,omitempty"` // superseded by "local", for backwards compat
	// The remote address of the underlay, in the case of an IP-based protocol this will be an IP
	// address. For other protocols, e.g. those without IP, the remote address can be omitted.
	Remote string `json:"remote,omitempty"`
	// The next hop address of the underlay, this will be the MAC address.
	NextHop string `json:"nexthop,omitempty"`
	// The name of the hardware interface the source should use to reach the destination.
	Interface string `json:"interface,omitempty"`
	// Optional, used for MPLS, the label to send with:
	MplsLabel uint32 `json:"mpls_label,omitempty"`
}
