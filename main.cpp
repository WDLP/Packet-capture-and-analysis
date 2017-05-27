
#include <pcap.h>
#include "proce.h"
#include "protocol.h"
#include "filter.h"
#include <stdlib.h>


	int main(int argc, char **argv)
{
	pcap_if_t *alldevs;   //��������������
	pcap_if_t *d;   //ѡ�е�����������
	int inum;   //ѡ������������
	int i = 0;   //forѭ������
	pcap_t *adhandle;   //����������������׽ʵ��,��pcap_open���صĶ���
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256
	int res;   //ץ������pcap_next_ex����ֵ��1-�ɹ���0����ȡ���ĳ�ʱ��-1����������-2: ��ȡ�����߼�¼�ļ������һ������
	u_int netmask;    //��������
					  //ether proto protocol��������ݰ�����ĳЩ��̫Э�飨protocol������, ����˶�Ӧ���������ʽΪ�棬Э���ֶο�����ARP
	char *packet_filter;    //Ҫץȡ�İ������ͣ�������ץȡARP����
	packet_filter = 0;

	struct bpf_program fcode;   //pcap_compile�����õĽṹ��
								//struct tm *ltime;   //��ʱ�䴦���йصı���
								//char timestr[16];   //��ʱ�䴦���йصı���
								//time_t local_tv_sec;    //��ʱ�䴦���йصı���




								/* ��ȡ�����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}


	/* ��ת����ѡ�е������� */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* ���豸 */
	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // Ҫ��׽�����ݰ��Ĳ���
						  // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* �ͷ����б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;


	// ���ݲ��� ѡ��filter
	printf("set filter\n");
	//printf("%s,%d", argv[0], argc);
	for (i = 1; i < argc; i += 1)
	{

		switch (argv[i][0])
		{
		case 'i':
		{
			switch (argv[i][1])
			{
			case 'p':
			{
				packet_filter = ip_filter;
			}
			break;
			case 'c':
			{
				packet_filter = icmp_filter;
			}
			break;
			case 'g':
			{
				packet_filter = igmp_filter;
			}
			break;
			}
			//packet_filter = arp_filter;
		};
		break;
		case 'a':
		{
			packet_filter = arp_filter;
		};
		break;
		case 'b':
		{
			packet_filter = bootp_filter;
		};
		break;
		case 'd':
		{
			packet_filter = dhcp_filter;
		}
		break;

		case 't':
		{
			packet_filter = tcp_filter;
		}
		break;
		case 'u':
		{
			packet_filter = udp_filter;
		}
		break;
		case 'o':
		{
			//filname=
		}
		}
	}

	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);


	/*���ϴ�����WinPcap�����ĵ��ж������ҵ�������ARP���Ĵ�����Ҫ�Լ���д*/


	printf("���ݰ�����\n");
	int t;
	//printf("%d\n", argc);
	if (argc == 3)
	{
		//printf("!!!!!");
		t = atoi(argv[2]);
		//printf("%d\n", t);
	}

	for (i = 1; i < argc; i += 1)
	{

		switch (argv[i][0])
		{
		case 'i':
		{
			switch (argv[i][1])
			{
			case 'p':
			{
				proc_ip(adhandle, t);
			}
			break;
			case 'c':
			{
				proc_icmp(adhandle, t);
			}
			break;
			case 'g':
			{
				proc_igmp(adhandle, t);
			}
			break;
			}
		};
		break;
		case 'a':
		{
			proc_arp(adhandle, t);
		};
		break;
		case 'b':
		{
			proc_bootp(adhandle, t);
		};
		break;
		case 'd':
		{
			proc_dhcp(adhandle, t);
		}
		break;
		case 't':
		{
			proc_tcp(adhandle, t);
		}
		break;
		case 'u':
		{
			proc_udp(adhandle, t);
		}
		break;
		case 'o':
		{
			//filname=
		}
		}
	}

	/* ��ȡ���ݰ� */


	system("pause");
	return 0;
}
