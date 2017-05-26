#pragma once

//各种协议包头结构

//typedef signed char BOOL;
typedef unsigned char UINT1;
typedef unsigned short UINT2;
typedef unsigned long UINT4;
//typedef unsigned long long int UINT8;


 struct EtherHeader
{
	UINT1 dest[6];
	UINT1 src[6];
	UINT1 proto[2];
	UINT1 data[1];

} ;

struct ArpHeader
{
	u_char hdtyp[2];   //硬件类型
	u_char  protyp[2];   //协议类型
	unsigned char hdsize;   //硬件地址长度
	unsigned char prosize;   //协议地址长度
	unsigned short op;   //操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	u_char smac[6];   //源MAC地址
	u_char sip[4];   //源IP地址
	u_char dmac[6];   //目的MAC地址
	u_char dip[4];   //目的IP地址
	UINT1 data[1];
};

 struct IpHeader
{
	UINT1 hlen;
	UINT1 tos;
	UINT2 len;
	UINT2 ipid;
	UINT2 flagoff;
	UINT1 ttl;
	UINT1 proto;
	UINT2 cksum;
	u_char sip[4];
	u_char dip[4];
	UINT1 data[1];
} ;

 struct TcpHeader
{
	UINT2 sport;
	UINT2 dport;
	UINT4 seq;
	UINT4 ack;
	UINT1 hlen;
	UINT1 code;
	UINT2 window;
	UINT2 chsum;
	UINT2 urg;
	char data[1];
} ;

 struct UdpHeader
{
	UINT2 sport;
	UINT2 dport;
	UINT2 len;
	UINT2 cksum;
	char data[1];
} ;

 struct IcmpHeader
 {
	 UINT1 type;
	 UINT1 code;
	 UINT2 cksum;
	 UINT2 id;
	 UINT2 seq;
	 char data[1];
 };

 struct Igmp_query_Header
 {
	 UINT1 type;
	 UINT1 mrtime;  //最大响应时间 v2版本 v1未用
	 UINT2 cksum;
	 UINT1 gip[1];     //32位组地址
 };

 struct Igmp_report_Header
 {
	 UINT1 type;
	 UINT1 reserved;  
	 UINT2 cksum;
	 UINT1 reserved1;
	 UINT1 num_group_record;
	 UINT1 group_record[][4];     
 };









