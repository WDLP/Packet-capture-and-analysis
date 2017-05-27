
#include <pcap.h>
#include "proce.h"
#include "protocol.h"
#include "filter.h"
#include <stdlib.h>


	int main(int argc, char **argv)
{
	pcap_if_t *alldevs;   //所有网络适配器
	pcap_if_t *d;   //选中的网络适配器
	int inum;   //选择网络适配器
	int i = 0;   //for循环变量
	pcap_t *adhandle;   //打开网络适配器，捕捉实例,是pcap_open返回的对象
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	int res;   //抓包函数pcap_next_ex返回值，1-成功、0：获取报文超时、-1：发生错误、-2: 获取到离线记录文件的最后一个报文
	u_int netmask;    //子网掩码
					  //ether proto protocol：如果数据包属于某些以太协议（protocol）类型, 则与此对应的条件表达式为真，协议字段可以是ARP
	char *packet_filter;    //要抓取的包的类型，这里是抓取ARP包；
	packet_filter = 0;

	struct bpf_program fcode;   //pcap_compile所调用的结构体
								//struct tm *ltime;   //和时间处理有关的变量
								//char timestr[16];   //和时间处理有关的变量
								//time_t local_tv_sec;    //和时间处理有关的变量




								/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
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
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}


	/* 跳转到已选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 要捕捉的数据包的部分
						  // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;


	// 根据参数 选择filter
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

	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);


	/*以上代码在WinPcap开发文档中都可以找到，解析ARP包的代码则要自己编写*/


	printf("数据包解析\n");
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

	/* 获取数据包 */


	system("pause");
	return 0;
}
