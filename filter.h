#pragma once
#define arp_filter "ether proto \\arp"
#define ip_filter "ether proto \\ip"
#define tcp_filter "ip proto \\tcp"
#define udp_filter "ip proto \\udp"
#define icmp_filter "ip proto \\icmp"
#define igmp_filter "ip proto 2"
#define bootp_filter "udp port 67 or 68"
#define dhcp_filter "udp port 67 or 68"
//#define snmp_filter "udp port 161 or 162"