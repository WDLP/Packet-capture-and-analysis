#include <pcap.h>
#include "protocol.h"
#include "filter.h"

int proc_arp(pcap_t * adhandle)
{	
	struct pcap_pkthdr *header;   //���յ������ݰ���ͷ��
	const u_char *pkt_data;    //���յ������ݰ�������

	struct tm *ltime;   //��ʱ�䴦���йصı��� 
	char timestr[16];   //��ʱ�䴦���йصı���
	time_t local_tv_sec;    //��ʱ�䴦���йصı���

	int res;
	int i;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* ��ʱʱ�䵽 */
			continue;

		EtherHeader * tet = (EtherHeader *)(pkt_data);

		printf("��̫��֡ͷdmac��");
		for (i = 0; i < 6; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("\n");

		printf("��̫��֡ͷ���ͣ�");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("\n");

		//����ARP��

		ArpHeader* arph = (ArpHeader *)(tet->data);

		//���� 
		printf("�������ͣ�");
		if (arph->op == 256)
			printf("������\t");
		else
			printf("Ӧ����\t");

		//����
		printf("����(B)��%d\t", header->len);

		//ʱ��
		/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("ʱ�䣺%s\n", timestr);


		//���ԴIP
		printf("ԴIP��");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", arph->sip[i]);
		}
		printf("%d\t", arph->sip[3]);

		//���Ŀ��IP
		printf("Ŀ��IP��");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", arph->dip[i]);

		}
		printf("%d\n", arph->dip[3]);

		//���ԴMAC��MAC 6���ֽڣ�ʹ��%02x ���и�ʽ��ʽ����
		printf("ԴMAC��");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", arph->smac[i]);
		}
		printf("%02x\t", arph->smac[5]);

		//���Ŀ��MAC
		printf("Ŀ��MAC��");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", *(pkt_data + i));
		}
		printf("%02x\n", *(pkt_data + 5));

		printf("----------------------------����һֻ�ָ���-----------------------------\n");

	}

	if (res == -1) {   //����ARP������
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