//#include "stdafx.h"
#include "NodeList.h"
#include "winsock2.h"
#include <iostream>
using namespace std;

CNodeList::CNodeList(void)
{
	pHead = pTail = NULL;
}


CNodeList::~CNodeList(void)
{
	if (pHead != NULL)
	{
		CIPNode * pTemp = pHead;
		pHead = pHead->pNext;
		delete  pTemp;
	}
}


void CNodeList::addNode(unsigned long dwSourceIP, unsigned long dwDestIP, unsigned char chpro, unsigned short dwFlow)
{
	if (pHead == NULL)             //链表为空
	{
		pTail = new  CIPNode(dwSourceIP, dwDestIP, chpro, dwFlow);
		pHead = pTail;
		pTail->pNext = NULL;
	}

	else
	{
		CIPNode *pTemp;
		for (pTemp = pHead; pTemp; pTemp = pTemp->pNext)
		{
			//如果链表中已存在该类型的IP包，则数据包个数加一
			if (pTemp->getSourceIPAddr() == dwSourceIP&&
				pTemp->getDestIPAddr() == dwDestIP&&pTemp->getProtocol() == chpro)
			{
				pTemp->addCount();
				pTemp->addFlow(dwFlow);
				break;
			}

		}
		//如果链表中不存在该类型的IP包，则创建新的节点加入链表
		if (pTemp == NULL)
		{
			pTail->pNext = new CIPNode(dwSourceIP, dwDestIP, chpro, dwFlow);
			pTail = pTail->pNext;
			pTail->pNext = NULL;
		}
	}
}

void CNodeList::print() 
{
	CIPNode * pTemp;
	if (pHead == NULL)
	{
		cout << "没有捕获到IP数据包!" << endl;
	}
	else
	{
		cout << "源地址  " << '\t' << "目的地址" << '\t' << "协议类型  " << "数量" <<'\t'<< "数据流量大小" << endl;
		for (pTemp = pHead; pTemp; pTemp = pTemp->pNext)
		{
			unsigned long dwSourTemp = pTemp->getSourceIPAddr();
			unsigned long dwDestTemp = pTemp->getDestIPAddr();
			cout << inet_ntoa(*(in_addr *)&(dwSourTemp)) << '\t';
			cout << inet_ntoa(*(in_addr *)&(dwDestTemp)) << '\t';
			cout << pTemp->getProtocol_String() << '\t' << pTemp->getCount() << "\t" << pTemp->getFlow() << endl;
		}
	}
}