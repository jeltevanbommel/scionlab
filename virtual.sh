
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

sudo ip link add veth-as110 type dummy
sudo ip link add veth-as112 type dummy
sudo ip link add veth-br111_112 type dummy
sudo ip link add link veth-as110 name vnic0 address 00:11:22:33:44:55 type macvlan mode bridge
sudo ip link add link veth-as110 name vnic1 address 00:11:22:33:44:66 type macvlan mode bridge
sudo ip link add link veth-br111_112 name vnic2 address 00:11:22:33:44:77 type macvlan mode bridge
sudo ip link add link veth-br111_112 name vnic3 address 00:11:22:33:44:88 type macvlan mode bridge
sudo ip link add link veth-as112 name vnic4 address 00:11:22:33:44:99 type macvlan mode bridge
sudo ip link set vnic0 up
sudo ip link set vnic1 up
sudo ip link set vnic2 up
sudo ip link set vnic3 up
sudo ip link set vnic4 up
sudo ip link set veth-as110 up
sudo ip link set veth-as112 up
sudo ip link set veth-br111_112 up

# On VNIC0 we will see traffic from or to BR110-2 to the MPLS Underlay (internal)
# On VNIC1 we will see traffic from or to BR110-1 to the MPLS Underlay (internal)
# On VNIC2 we will see traffic from BR of AS111 to BR112 over MPLS (external)
# On VNIC3 we will see traffic from BR of AS112 to AS 111 over MPLS (external)
# On VNIC4 we will see traffic from or to BR112 to the MPLS Underlay (internal)
