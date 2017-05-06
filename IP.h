#pragma once
#include<winsock2.h>
#include<ws2tcpip.h>

#include<time.h>
#include "IPNode.h"
#include "NodeList.h"

#pragma comment(lib, "Ws2_32.lib")

// ����IPͷ��
typedef struct IPHeader
{
	unsigned char    Version_HeaderLength;    // �汾(4λ)+�ײ�����(4λ)
	unsigned char     TypeOfService;            // ��������
	unsigned short  TotalLength;            // �ܳ���
	unsigned short  Identification;            // ��ʶ
	unsigned short  Flags_FragmentOffset;    // ��־(3λ)+��Ƭƫ��(13λ)
	unsigned char      TimeToLive;                // ����ʱ��
	unsigned char      Protocal;                // Э��
	unsigned short  HeaderChecksum;            // �ײ�У���
	unsigned long      SourceAddress;            // ԴIP��ַ
	unsigned long      DestAddress;            // Ŀ��IP��ַ
}IPHEADER;