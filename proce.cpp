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
		for (i = 0; i < 6; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("\n");

		printf("以太网帧头类型：");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("\n");

		//解析ARP包

		ArpHeader* arph = (ArpHeader *)(tet->data);

		//类型 
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
	return 0;
}
int proc_tcp(pcap_t * adhandle)
{
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
	return 0;
}
int proc_igmp(pcap_t * adhandle)
{
	return 0;
}