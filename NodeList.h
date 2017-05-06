#pragma once
#include "IPNode.h"
class CNodeList
{
public:
	CNodeList(void);
	~CNodeList(void);
	void  addNode(unsigned long dwSourIP, unsigned long dwDestIP, unsigned char chPro, unsigned short dwFlow);
	void  print();
private:
	CIPNode * pHead;             //Á´±íÍ·
	CIPNode * pTail;             //Á´±íÎ²

};