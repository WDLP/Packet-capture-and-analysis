//#include "stdafx.h"
#include "winsock2.h"
#include <ws2tcpip.h>
#include "IP.h"
#include  <iostream>
using namespace std;

#define  IO_RCVALL   _WSAIOW(IOC_VENDOR,1)
#define BURRER_SIZE 65535

int main()
{
	//初始化Winsock DLL
	WSADATA  wsData;
	if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0)
	{
		cout << "Winsock DLL初始化失败！" << endl;
		return 1;
	}

	//创建socket
	SOCKET  sock;
	sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, 0);
	cout << INVALID_SOCKET<<endl;
	if (sock == INVALID_SOCKET)
	{
		cout << sock;
		cout << "socket创建失败！" << endl;
		return 2;
	}
	// 设置IP头操作选项，表示用户可以亲自对IP头进行处理
	BOOL bFlag = TRUE;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&bFlag, sizeof(bFlag)) == SOCKET_ERROR)
	{
		cout << "Setsockopt 失败!" << endl;
		return 3;
	}

	//绑定套接字
	//获得主机网络地址
	char  LocalName[256];
	gethostname(LocalName, 256);
	cout << LocalName;
	HOSTENT * pHost;
	pHost = gethostbyname(LocalName);


	//填充sockaddr_in结构

	sockaddr_in  addr_in;
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(8000);
	addr_in.sin_addr = *(in_addr *)pHost->h_addr_list[0];
	bind(sock, (sockaddr *)&addr_in, sizeof(addr_in));

	//将网卡设置为混杂模式，以便接收所有所有的IP数据包
	DWORD  dwBufferLen[10];
	DWORD dwBufferInLen = 1;
	DWORD dwBytesReturned = 0;
	WSAIoctl(sock, IO_RCVALL, &dwBufferInLen, sizeof(dwBufferInLen), &dwBufferLen,
		sizeof(dwBufferLen), &dwBytesReturned, NULL, NULL);

	// 把socket设置为非阻塞模式
	DWORD  dwTemp = 1;
	ioctlsocket(sock, FIONBIO, &dwTemp);

	// 设置接收缓冲区
	char pBuffer[BURRER_SIZE];

	CNodeList IpList;
	double dwDuration = 3;    // 捕获时间
	time_t beg;
	time_t end;
	time(&beg);        // 获得当前系统时间
					   // 输出本地IP地址
	cout << endl;
	cout << "本机IP:"
		<< inet_ntoa(*(in_addr *)&(addr_in.sin_addr.S_un.S_addr)) << endl << endl;
	cout << "开始捕获..." << endl << endl;

	while (1)
	{
		time(&end);            // 获得当前系统时间
							   //如果捕获时间到，就结束捕获
		if (end - beg >= dwDuration)
		{
			break;
		}

		// 捕获经过网卡的IP数据包
		int nPacketSize = recv(sock, pBuffer, BURRER_SIZE, 0);
		if (nPacketSize > 0)
		{
			IPHEADER * pIpHdr;
			// 通过指针把缓冲区中的内容强制转换为IPHEADER数据结构
			pIpHdr = (IPHEADER *)pBuffer;
			// 判断IP包的源IP地址或目的IP地址是否为本地主机的IP地址
			if (pIpHdr->SourceAddress == addr_in.sin_addr.S_un.S_addr
				|| pIpHdr->DestAddress == addr_in.sin_addr.S_un.S_addr)
			{
				// 如果源IP地址或目的IP地址是本机IP，则将该IP数据包加入链表
				IpList.addNode(pIpHdr->SourceAddress, pIpHdr->DestAddress, pIpHdr->Protocal, pIpHdr->TotalLength);
			}
		}
	}
	// 输出统计结果
	cout << "IP数据包统计结果: (" << dwDuration << " 秒)" << endl << endl;
	IpList.print();
	cout << endl;

	system("PAUSE");
	return 0;
}
