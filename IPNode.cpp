//#include "stdafx.h"
#include "IPNode.h"


CIPNode::CIPNode(unsigned long dwSourceIP, unsigned long dwDestIP, unsigned char chPro, unsigned short dwFlow)
{
	m_dwSourceIPAddr = dwSourceIP;
	m_dwDestIPAddr = dwDestIP;
	m_chProtocol = chPro;
	m_dwCounter = 1;
	m_dwFlow = dwFlow;
}

CIPNode::CIPNode()
{
}


CIPNode::~CIPNode(void)
{
}

void CIPNode::addCount()
{
	m_dwCounter++;              //�������ݰ�����
}
void CIPNode::addFlow(unsigned short dwFlow)
{
	m_dwFlow += dwFlow;
}

//ȡ�����ݰ�����
unsigned  long  CIPNode::getCount()
{
	return  m_dwCounter;
}
unsigned short CIPNode::getFlow()
{
	return m_dwFlow;
}
//ȡ��ԴIP��ַ
unsigned  long  CIPNode::getSourceIPAddr()
{
	return  m_dwSourceIPAddr;
}
//ȡ��Ŀ��IP��ַ
unsigned long CIPNode::getDestIPAddr()
{
	return  m_dwDestIPAddr;
}
//ȡ��Э������
unsigned char CIPNode::getProtocol()
{
	return m_chProtocol;
}
// ȡ��Э������
char * CIPNode::getProtocol_String()
{
	switch (m_chProtocol)
	{
	case 1:
		return "ICMP";
		break;
	case 2:
		return "IGMP";
		break;
	case 4:
		return "IP in IP";
		break;
	case 6:
		return "TCP";
		break;
	case 8:
		return "EGP";
		break;
	case 17:
		return "UDP";
		break;
	case 41:
		return "IPv6";
		break;
	case 46:
		return "RSVP";
		break;
	case 89:
		return "OSPF";
		break;
	default:
		return "UNKNOWN";
	}
}