#include <pcap.h>
#include "protocol.h"
#include "filter.h"



int proc_arp(pcap_t * adhandle)
{	
	struct pcap_pkthdr *header;   //接收到的数据包的头部
	const u_char *pkt_data;    //接收到的数据包的内容

	struct tm *ltime;   //和时间处理有关的变量 
	char timestr[16];   //和时间处理有关的变量
	time_t local_tv_sec;    //和时间处理有关的变量

	int res;
	int i;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* 超时时间到 */
			continue;

		EtherHeader * tet = (EtherHeader *)(pkt_data);

		printf("以太网帧头dmac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("以太网帧头smac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("以太网帧头类型：");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[5]);
		printf("\n");

		//解析ARP包

		ArpHeader* arph = (ArpHeader *)(tet->data);

		//类型 
		printf("arp协议头\n");


		printf("帧类型：");
		for (i = 0; i < 1; i++)
		{
			printf("%02x", arph->hdtyp[i]);
		}
		printf("%02x\n", arph->hdtyp[1]);
		


		printf("协议类型：");
		for (i = 0; i < 1; i++)
		{
			printf("%02x", arph->protyp[i]);
		}
		printf("%02x\n", arph->protyp[1]);

		printf("硬件地址长度：");
		printf("%d\n", arph->hdsize);


		printf("报文类型：");
		if (arph->op == 256)
			printf("请求报文\t");
		else
			printf("应答报文\t");

		//长度
		printf("长度(B)：%d\t", header->len);

		//时间
		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("时间：%s\n", timestr);


		//输出源IP
		printf("源IP：");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", arph->sip[i]);
		}
		printf("%d\t", arph->sip[3]);

		//输出目的IP
		printf("目的IP：");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", arph->dip[i]);
		}
		printf("%d\n", arph->dip[3]);

		//输出源MAC，MAC 6个字节，使用%02x 进行格式格式控制
		printf("源MAC：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", arph->smac[i]);
		}
		printf("%02x\t", arph->smac[5]);

		//输出目的MAC
		printf("目的MAC：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", *(pkt_data + i));
		}
		printf("%02x\n", *(pkt_data + 5));

		printf("----------------------------我是一只分隔线-----------------------------\n");

	}

	if (res == -1) {   //接收ARP包出错
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
}


int proc_ip(pcap_t * adhandle)
{
	struct pcap_pkthdr *header;   //接收到的数据包的头部
	const u_char *pkt_data;    //接收到的数据包的内容

	struct tm *ltime;   //和时间处理有关的变量 
	char timestr[16];   //和时间处理有关的变量
	time_t local_tv_sec;    //和时间处理有关的变量

	int res;
	int i;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* 超时时间到 */
			continue;

		EtherHeader * tet = (EtherHeader *)(pkt_data);

		printf("以太网帧头dmac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("以太网帧头smac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("以太网帧头类型：");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[5]);
		printf("\n");

		//解析ARP包

		IpHeader* Iph = (IpHeader *)(tet->data);

		//类型 
		printf("ip协议头\n");

		printf("ip包类型：");
		u_char ver = Iph->hlen >> 4;
		printf("%d\n", ver);


		printf("ip包头长度");
		u_char a = 15;
		u_char len = (Iph->hlen)&a;
		printf("%d\n", len);

		printf("服务类型");
		printf("%d\n", (Iph->tos));


		printf("Total Length");
		printf("%d\n", ntohs((Iph->len)));


		printf("TTL：");
		printf("%d\n", Iph->ttl);

		printf("Protocol：");
		printf("%d\n", Iph->proto);

		//输出源IP
		printf("Source address");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", Iph->sip[i]);
		}
		printf("%d\t", Iph->sip[3]);



		//长度
		printf("长度(B)：%d\t", header->len);

		//时间
		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("时间：%s\n", timestr);


		printf("----------------------------我是一只分隔线-----------------------------\n");

	}

	if (res == -1) {   //接收ARP包出错
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}


	return 0;
}

int proc_tcp(pcap_t * adhandle)
{

	struct pcap_pkthdr *header;   //接收到的数据包的头部
	const u_char *pkt_data;    //接收到的数据包的内容

	struct tm *ltime;   //和时间处理有关的变量 
	char timestr[16];   //和时间处理有关的变量
	time_t local_tv_sec;    //和时间处理有关的变量

	int res;
	int i;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* 超时时间到 */
			continue;

		EtherHeader * tet = (EtherHeader *)(pkt_data);

		printf("以太网帧头dmac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("以太网帧头smac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("以太网帧头类型：");
		for (i = 0; i < 1; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[2]);
		printf("\n");

		//解析ARP包

		IpHeader* Iph = (IpHeader *)(tet->data);

		//类型 
		printf("ip协议头\n");

		printf("ip包类型：");
		u_char ver = Iph->hlen >> 4;
		printf("%d\n", ver);


		printf("ip包头长度");
		u_char a = 15;
		u_char len = (Iph->hlen)&a;
		
		printf("%d\n", len*4);

		printf("服务类型");
		printf("%d\n", (Iph->tos));


		printf("Total Length");
		printf("%d\n", ntohs((Iph->len)));


		printf("TTL：");
		printf("%d\n", Iph->ttl);

		printf("Protocol：");
		printf("%d\n", Iph->proto);

		//输出源IP
		printf("Source address");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", Iph->sip[i]);
		}
		printf("%d\t", Iph->sip[3]);

		TcpHeader* Tcph = (TcpHeader *)(Iph->data);

		//类型 
		printf("tcp协议头\n");

		printf("源端口：");
		printf("%d\n", ntohs(Tcph->sport));

		printf("目的端口：");
		printf("%d\n", ntohs(Tcph->dport));


		printf("序列号seq：");
		printf("%d\n", ntohl(Tcph->seq));

		printf("确认号ack：");
		printf("%d\n", ntohl(Tcph->ack));

		printf("头部长度：");
		u_char hlen = Tcph->hlen >> 4;
		printf("%d\n", hlen);


		//长度
		printf("长度(B)：%d\t", header->len);

		//时间
		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("时间：%s\n", timestr);


		printf("----------------------------我是一只分隔线-----------------------------\n");

	}

	if (res == -1) {   //接收ARP包出错
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}




	return 0;
}
int proc_udp(pcap_t * adhandle)
{
	return 0;
}
int proc_bootp(pcap_t * adhandle)
{
	return 0;
}
int proc_icmp(pcap_t * adhandle)
{
	struct pcap_pkthdr *header;   //接收到的数据包的头部
	const u_char *pkt_data;    //接收到的数据包的内容

	struct tm *ltime;   //和时间处理有关的变量 
	char timestr[16];   //和时间处理有关的变量
	time_t local_tv_sec;    //和时间处理有关的变量

	int res;
	int i;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* 超时时间到 */
			continue;

		EtherHeader * tet = (EtherHeader *)(pkt_data);

		printf("以太网帧头dmac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("以太网帧头smac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("以太网帧头类型：");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[5]);
		printf("\n");

		//解析ARP包

		IpHeader* Iph = (IpHeader *)(tet->data);

		//类型 
		printf("ip协议头\n");

		printf("ip包类型：");
		u_char ver = Iph->hlen >> 4;
		printf("%d\n", ver);


		printf("ip包头长度");
		u_char a = 15;
		u_char len = (Iph->hlen)&a;
		printf("%d\n", len);

		printf("服务类型");
		printf("%d\n", (Iph->tos));


		printf("Total Length");
		printf("%d\n", ntohs((Iph->len)));


		printf("TTL：");
		printf("%d\n", Iph->ttl);

		printf("Protocol：");
		printf("%d\n", Iph->proto);

		//输出源IP
		printf("Source address");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", Iph->sip[i]);
		}
		printf("%d\t", Iph->sip[3]);


		//icmp协议头
		IcmpHeader * icmph = (IcmpHeader *)(Iph->data);
		printf("type:");
		printf("%d\n", icmph->type);

		printf("code:");
		printf("%d\n", icmph->code);

		printf("cksum:");
		printf("%d\n", ntohs(icmph->cksum));

		printf("id:");
		printf("%d\n", ntohs(icmph->id));

		printf("seq:");
		printf("%d\n", ntohs(icmph->seq));


		//长度
		printf("长度(B)：%d\t", header->len);

		//时间
		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("时间：%s\n", timestr);


		printf("----------------------------我是一只分隔线-----------------------------\n");

	}


	if (res == -1) {   //接收ARP包出错
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 0;
}

int proc_igmp(pcap_t * adhandle)
{
	struct pcap_pkthdr *header;   //接收到的数据包的头部
	const u_char *pkt_data;    //接收到的数据包的内容

	struct tm *ltime;   //和时间处理有关的变量 
	char timestr[16];   //和时间处理有关的变量
	time_t local_tv_sec;    //和时间处理有关的变量

	int res;
	int i;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* 超时时间到 */
			continue;

		EtherHeader * tet = (EtherHeader *)(pkt_data);

		printf("以太网帧头dmac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("以太网帧头smac：");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("以太网帧头类型：");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[5]);
		printf("\n");

		//解析ARP包

		IpHeader* Iph = (IpHeader *)(tet->data);

		//类型 
		printf("ip协议头\n");

		printf("ip包类型：");
		u_char ver = Iph->hlen >> 4;
		printf("%d\n", ver);


		printf("ip包头长度");
		u_char a = 15;
		u_char len = (Iph->hlen)&a;
		printf("%d\n", len);

		printf("服务类型");
		printf("%d\n", (Iph->tos));


		printf("Total Length");
		printf("%d\n", ntohs((Iph->len)));


		printf("TTL：");
		printf("%d\n", Iph->ttl);

		printf("Protocol：");
		printf("%d\n", Iph->proto);

		//输出源IP
		printf("Source address");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", Iph->sip[i]);
		}
		printf("%d\t", Iph->sip[3]);


		//igmp_query协议头
		

		Igmp_query_Header * igmph = (Igmp_query_Header *)(Iph->data);

		if (igmph->mrtime == 0)
		{
			printf("type:");
			printf("%d\n", igmph->type);

			printf("max response time:");
			printf("%d\n", igmph->mrtime);

			printf("cksum:");
			printf("%d\n", ntohs(igmph->cksum));

			printf("group address:");
			for (i = 0; i < 3; i++)
			{
				printf("%d.", igmph->gip[i]);
			}
			printf("%d\n", igmph->gip[3]);
		}
		else
		{
			Igmp_report_Header * igmph = (Igmp_report_Header *)(Iph->data);
			printf("type:");
			printf("%d\n", igmph->type);

			printf("reserved:");
			printf("%d\n", igmph->reserved);

			printf("cksum:");
			printf("%d\n", ntohs(igmph->cksum));

			printf("reserved1:");
			printf("%d\n", igmph->reserved1);

			printf("num_group_record:");
			printf("%d\n", igmph->num_group_record);


			printf("group_record:");
			for (i = 0; i < igmph->num_group_record; i++)
			{
				for (int j = 0; j < 3; j++)
				{
					{
						printf("%d.", igmph->group_record[i][j]);
					}
				}
				printf("%d", igmph->group_record[i][3]);
			}
		}

		//长度
		printf("长度(B)：%d\t", header->len);

		//时间
		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("时间：%s\n", timestr);


		printf("----------------------------我是一只分隔线-----------------------------\n");

	}


	if (res == -1) {   //接收ARP包出错
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	return 0;
}

