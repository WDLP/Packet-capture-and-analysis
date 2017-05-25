#pragma once

#include <pcap.h>
#include "proce.h"
#include "protocol.h"
#include "filter.h"

int proc_arp(pcap_t * adhandle);
int proc_ip(pcap_t * adhandle);
int proc_tcp(pcap_t * adhandle);
int proc_udp(pcap_t * adhandle);
int proc_bootp(pcap_t * adhandle);
int proc_icmp(pcap_t * adhandle);
int proc_igmp(pcap_t * adhandle);
int proc_dhcp(pcap_t * adhandle);