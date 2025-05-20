#!/usr/sbin/nft -f

flush ruleset

define CLIENT=192.168.1.0/24
define WWW=172.31.0.0/16
define VPN=10.0.0.0/16
define DNS=9.9.9.0/24
define VPN_RED=3.3.3.0/24
define IP_FW_CLIENT=192.168.1.2
define IP_FW_WWW=172.31.0.2
define IP_FW_DNS=9.9.9.2
define IP_FW_VPN=10.0.0.2
define IP_CLIENT_1=192.168.1.3
define IP_WWW_SERVER=172.31.0.3
define IP_VPN_SERVER=10.0.0.3
define IP_DNS_SERVER=9.9.9.3

define IFACE_DNS="eth1"
define IFACE_WWW="eth3"
define IFACE_VPN="eth2"
define IFACE_CLIENT="eth0"

add table ip filtrat
add table ip nat

add chain ip filtrat input { type filter hook input priority 0 ; policy drop;}
add chain ip filtrat output { type filter hook output priority 0 ; policy drop;}
add chain ip filtrat forward { type filter hook forward priority 0 ; policy drop;}

add chain ip nat prerouting { type nat hook prerouting priority 0 ; }

add rule ip filtrat forward ct state established,related counter accept
add rule ip filtrat forward  iif $IFACE_CLIENT ip saddr $IP_CLIENT_1 icmp type {echo-request,echo-reply} counter accept
add rule ip filtrat forward iif $IFACE_CLIENT ip saddr $CLIENT ip daddr $IP_WWW_SERVER tcp dport http counter accept


