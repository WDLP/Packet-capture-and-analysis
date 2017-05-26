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
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("��̫��֡ͷsmac��");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("��̫��֡ͷ���ͣ�");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[5]);
		printf("\n");

		//����ARP��

		ArpHeader* arph = (ArpHeader *)(tet->data);

		//���� 
		printf("arpЭ��ͷ\n");


		printf("֡���ͣ�");
		for (i = 0; i < 1; i++)
		{
			printf("%02x", arph->hdtyp[i]);
		}
		printf("%02x\n", arph->hdtyp[1]);
		


		printf("Э�����ͣ�");
		for (i = 0; i < 1; i++)
		{
			printf("%02x", arph->protyp[i]);
		}
		printf("%02x\n", arph->protyp[1]);

		printf("Ӳ����ַ���ȣ�");
		printf("%d\n", arph->hdsize);


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
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("��̫��֡ͷsmac��");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("��̫��֡ͷ���ͣ�");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[5]);
		printf("\n");

		//����ARP��

		IpHeader* Iph = (IpHeader *)(tet->data);

		//���� 
		printf("ipЭ��ͷ\n");

		printf("ip�����ͣ�");
		u_char ver = Iph->hlen >> 4;
		printf("%d\n", ver);


		printf("ip��ͷ����");
		u_char a = 15;
		u_char len = (Iph->hlen)&a;
		printf("%d\n", len);

		printf("��������");
		printf("%d\n", (Iph->tos));


		printf("Total Length");
		printf("%d\n", ntohs((Iph->len)));


		printf("TTL��");
		printf("%d\n", Iph->ttl);

		printf("Protocol��");
		printf("%d\n", Iph->proto);

		//���ԴIP
		printf("Source address");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", Iph->sip[i]);
		}
		printf("%d\t", Iph->sip[3]);



		//����
		printf("����(B)��%d\t", header->len);

		//ʱ��
		/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("ʱ�䣺%s\n", timestr);


		printf("----------------------------����һֻ�ָ���-----------------------------\n");

	}

	if (res == -1) {   //����ARP������
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}


	return 0;
}

int proc_tcp(pcap_t * adhandle)
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
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("��̫��֡ͷsmac��");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("��̫��֡ͷ���ͣ�");
		for (i = 0; i < 1; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[2]);
		printf("\n");

		//����ARP��

		IpHeader* Iph = (IpHeader *)(tet->data);

		//���� 
		printf("ipЭ��ͷ\n");

		printf("ip�����ͣ�");
		u_char ver = Iph->hlen >> 4;
		printf("%d\n", ver);


		printf("ip��ͷ����");
		u_char a = 15;
		u_char len = (Iph->hlen)&a;
		
		printf("%d\n", len*4);

		printf("��������");
		printf("%d\n", (Iph->tos));


		printf("Total Length");
		printf("%d\n", ntohs((Iph->len)));


		printf("TTL��");
		printf("%d\n", Iph->ttl);

		printf("Protocol��");
		printf("%d\n", Iph->proto);

		//���ԴIP
		printf("Source address");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", Iph->sip[i]);
		}
		printf("%d\t", Iph->sip[3]);

		TcpHeader* Tcph = (TcpHeader *)(Iph->data);

		//���� 
		printf("tcpЭ��ͷ\n");

		printf("Դ�˿ڣ�");
		printf("%d\n", ntohs(Tcph->sport));

		printf("Ŀ�Ķ˿ڣ�");
		printf("%d\n", ntohs(Tcph->dport));


		printf("���к�seq��");
		printf("%d\n", ntohl(Tcph->seq));

		printf("ȷ�Ϻ�ack��");
		printf("%d\n", ntohl(Tcph->ack));

		printf("ͷ�����ȣ�");
		u_char hlen = Tcph->hlen >> 4;
		printf("%d\n", hlen);


		//����
		printf("����(B)��%d\t", header->len);

		//ʱ��
		/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("ʱ�䣺%s\n", timestr);


		printf("----------------------------����һֻ�ָ���-----------------------------\n");

	}

	if (res == -1) {   //����ARP������
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
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("��̫��֡ͷsmac��");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("��̫��֡ͷ���ͣ�");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[5]);
		printf("\n");

		//����ARP��

		IpHeader* Iph = (IpHeader *)(tet->data);

		//���� 
		printf("ipЭ��ͷ\n");

		printf("ip�����ͣ�");
		u_char ver = Iph->hlen >> 4;
		printf("%d\n", ver);


		printf("ip��ͷ����");
		u_char a = 15;
		u_char len = (Iph->hlen)&a;
		printf("%d\n", len);

		printf("��������");
		printf("%d\n", (Iph->tos));


		printf("Total Length");
		printf("%d\n", ntohs((Iph->len)));


		printf("TTL��");
		printf("%d\n", Iph->ttl);

		printf("Protocol��");
		printf("%d\n", Iph->proto);

		//���ԴIP
		printf("Source address");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", Iph->sip[i]);
		}
		printf("%d\t", Iph->sip[3]);


		//icmpЭ��ͷ
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


		//����
		printf("����(B)��%d\t", header->len);

		//ʱ��
		/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("ʱ�䣺%s\n", timestr);


		printf("----------------------------����һֻ�ָ���-----------------------------\n");

	}


	if (res == -1) {   //����ARP������
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 0;
}

int proc_igmp(pcap_t * adhandle)
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
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->dest[i]);
		}
		printf("%02x", tet->dest[5]);
		printf("\n");

		printf("��̫��֡ͷsmac��");
		for (i = 0; i < 5; i++)
		{
			printf("%02x-", tet->src[i]);
		}
		printf("%02x", tet->src[5]);
		printf("\n");

		printf("��̫��֡ͷ���ͣ�");
		for (i = 0; i < 2; i++)
		{
			printf("%02x-", tet->proto[i]);
		}
		printf("%02x", tet->proto[5]);
		printf("\n");

		//����ARP��

		IpHeader* Iph = (IpHeader *)(tet->data);

		//���� 
		printf("ipЭ��ͷ\n");

		printf("ip�����ͣ�");
		u_char ver = Iph->hlen >> 4;
		printf("%d\n", ver);


		printf("ip��ͷ����");
		u_char a = 15;
		u_char len = (Iph->hlen)&a;
		printf("%d\n", len);

		printf("��������");
		printf("%d\n", (Iph->tos));


		printf("Total Length");
		printf("%d\n", ntohs((Iph->len)));


		printf("TTL��");
		printf("%d\n", Iph->ttl);

		printf("Protocol��");
		printf("%d\n", Iph->proto);

		//���ԴIP
		printf("Source address");
		for (i = 0; i < 3; i++)
		{
			printf("%d.", Iph->sip[i]);
		}
		printf("%d\t", Iph->sip[3]);


		//igmp_queryЭ��ͷ
		

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

		//����
		printf("����(B)��%d\t", header->len);

		//ʱ��
		/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("ʱ�䣺%s\n", timestr);


		printf("----------------------------����һֻ�ָ���-----------------------------\n");

	}


	if (res == -1) {   //����ARP������
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	return 0;
}

