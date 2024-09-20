// Copyright 2020 Anapaya Systems
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

package config

const idSample = "cs-1"

const psSample = `
# The time after which segments for a destination are refetched. (default 5m)
query_interval = "5m"
# The path to the hidden paths configuration file. If the path is empty, hidden
# paths functionality is not enabled. If the path starts with http:// or
# https:// the configuration is fetched from the given URL. (default: "")
hidden_paths_cfg = ""
`

const caSample = `
# The maximum validity time of a renewed AS certificate the control server
# creates in a CA AS. The remaining validity of the locally available CA
# certificate must be larger than the here configured value at every given point
# in time. (i.e., ca.not_after - current_time >= max_as_validity) If that is not
# the case, certificate renewal is not possible until a new CA certificate is
# loaded that satisfies the condition. (default 3d)
max_as_validity = "3d"

# The mode the CA handler of this control service operates in.
#
# - disabled:   In this mode, control AS is not a CA.
# - in-process: In this mode, the certificates are renewed in the control
#               service process. This means it needs access to the CA private
#               key and a currently active CA certificate.
#
# - delegating: In this mode, the certificate renewal is delegated to the CA
#               service via an API call. This means the service needs to be
#               configured with the CA service address and the secrets to
#               authenticate itself. Note that legacy requests will always
#               be handled in-process, even if delegating mode is selected.
#
# (default disabled)
mode = "in-process"
`

const serviceSample = `
# The path to the PEM-encoded shared secret that is used to create JWT tokens.
shared_secret = ""
# The address of the CA Service that handles the delegated certificate renewal requests.
addr = ""
# The validity period of self-generated JWT authorization tokens. The format
# is a Go duration. If not set, the application default in this sample is used instead.
lifetime = "10m"
# The client identification string that should be used in self-generated JWT
# authorization tokens. If not set, the SCION ID is used instead.
client_id = ""
`

const drkeySample = `
# Number of distinct Level1Keys to be prefetched.
prefetch_entries = 10000
`
const drkeySecretValueHostListSample = `
# The list of hosts authorized to get a SV per protocol.
scmp = [ "127.0.0.1", "127.0.0.2"]
`

const fabridLocalPolicySample = `
# Bool indicating whether the policy is a global or local policy.
local: true
# The identifier that the policy has locally in the AS
local_identifier: 55
# A description which other ASes can fetch, describing the policy
local_description: Fabrid Example Policy
# A list of connections to which this policy applies
connections:
  # Every connection has an ingress and an egress point:
  - ingress:
      # The type of the connection point, can be "ipv4", "ipv6" or "interface"
      type: interface
      # If the type is set to "interface", specify the specific interface
      interface: 1
    egress:
      # The type of the connection point, can be "ipv4", "ipv6" or "interface"
      type: ipv6
      # If the type is set to "ipv4" or "ipv6", specify the IP range using a IP and prefix
      ip: 2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b
      # The prefix of the IP mask, has to be smaller than 32 for IPv4, smaller than 128 for
      # IPv6
      prefix: 100
      # If the type is set to "interface", specify the specific interface, e.g.
      # interface: 1
    # Every connnection can have a different mpls label they use to enable the policy:
    mpls_label: 1
`

const fabridConfigSample = `
# Whether Fabrid is enabled on this AS
enabled = true
# Folder in which the fabrid policies are stored
path = "gen/ASff00_0_110/fabrid/"
`
