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
	if (pHead == NULL)             //����Ϊ��
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
			//����������Ѵ��ڸ����͵�IP���������ݰ�������һ
			if (pTemp->getSourceIPAddr() == dwSourceIP&&
				pTemp->getDestIPAddr() == dwDestIP&&pTemp->getProtocol() == chpro)
			{
				pTemp->addCount();
				pTemp->addFlow(dwFlow);
				break;
			}

		}
		//��������в����ڸ����͵�IP�����򴴽��µĽڵ��������
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
		cout << "û�в���IP���ݰ�!" << endl;
	}
	else
	{
		cout << "Դ��ַ  " << '\t' << "Ŀ�ĵ�ַ" << '\t' << "Э������  " << "����" <<'\t'<< "����������С" << endl;
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