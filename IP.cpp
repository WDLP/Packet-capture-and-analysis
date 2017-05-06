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
	//��ʼ��Winsock DLL
	WSADATA  wsData;
	if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0)
	{
		cout << "Winsock DLL��ʼ��ʧ�ܣ�" << endl;
		return 1;
	}

	//����socket
	SOCKET  sock;
	sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, 0);
	cout << INVALID_SOCKET<<endl;
	if (sock == INVALID_SOCKET)
	{
		cout << sock;
		cout << "socket����ʧ�ܣ�" << endl;
		return 2;
	}
	// ����IPͷ����ѡ���ʾ�û��������Զ�IPͷ���д���
	BOOL bFlag = TRUE;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&bFlag, sizeof(bFlag)) == SOCKET_ERROR)
	{
		cout << "Setsockopt ʧ��!" << endl;
		return 3;
	}

	//���׽���
	//������������ַ
	char  LocalName[256];
	gethostname(LocalName, 256);
	cout << LocalName;
	HOSTENT * pHost;
	pHost = gethostbyname(LocalName);


	//���sockaddr_in�ṹ

	sockaddr_in  addr_in;
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(8000);
	addr_in.sin_addr = *(in_addr *)pHost->h_addr_list[0];
	bind(sock, (sockaddr *)&addr_in, sizeof(addr_in));

	//����������Ϊ����ģʽ���Ա�����������е�IP���ݰ�
	DWORD  dwBufferLen[10];
	DWORD dwBufferInLen = 1;
	DWORD dwBytesReturned = 0;
	WSAIoctl(sock, IO_RCVALL, &dwBufferInLen, sizeof(dwBufferInLen), &dwBufferLen,
		sizeof(dwBufferLen), &dwBytesReturned, NULL, NULL);

	// ��socket����Ϊ������ģʽ
	DWORD  dwTemp = 1;
	ioctlsocket(sock, FIONBIO, &dwTemp);

	// ���ý��ջ�����
	char pBuffer[BURRER_SIZE];

	CNodeList IpList;
	double dwDuration = 3;    // ����ʱ��
	time_t beg;
	time_t end;
	time(&beg);        // ��õ�ǰϵͳʱ��
					   // �������IP��ַ
	cout << endl;
	cout << "����IP:"
		<< inet_ntoa(*(in_addr *)&(addr_in.sin_addr.S_un.S_addr)) << endl << endl;
	cout << "��ʼ����..." << endl << endl;

	while (1)
	{
		time(&end);            // ��õ�ǰϵͳʱ��
							   //�������ʱ�䵽���ͽ�������
		if (end - beg >= dwDuration)
		{
			break;
		}

		// ���񾭹�������IP���ݰ�
		int nPacketSize = recv(sock, pBuffer, BURRER_SIZE, 0);
		if (nPacketSize > 0)
		{
			IPHEADER * pIpHdr;
			// ͨ��ָ��ѻ������е�����ǿ��ת��ΪIPHEADER���ݽṹ
			pIpHdr = (IPHEADER *)pBuffer;
			// �ж�IP����ԴIP��ַ��Ŀ��IP��ַ�Ƿ�Ϊ����������IP��ַ
			if (pIpHdr->SourceAddress == addr_in.sin_addr.S_un.S_addr
				|| pIpHdr->DestAddress == addr_in.sin_addr.S_un.S_addr)
			{
				// ���ԴIP��ַ��Ŀ��IP��ַ�Ǳ���IP���򽫸�IP���ݰ���������
				IpList.addNode(pIpHdr->SourceAddress, pIpHdr->DestAddress, pIpHdr->Protocal, pIpHdr->TotalLength);
			}
		}
	}
	// ���ͳ�ƽ��
	cout << "IP���ݰ�ͳ�ƽ��: (" << dwDuration << " ��)" << endl << endl;
	IpList.print();
	cout << endl;

	system("PAUSE");
	return 0;
}
