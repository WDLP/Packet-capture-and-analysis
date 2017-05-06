#pragma once

class CIPNode
{

private:
	unsigned  long m_dwSourceIPAddr;               //ԴIP��ַ
	unsigned  long m_dwDestIPAddr;                 //Ŀ��IP��ַ
	unsigned  char m_chProtocol;                  //IP��Э������ 
	unsigned  long m_dwCounter;                    //���ݰ�������
	unsigned short m_dwFlow;                     //���ݰ�������
public:
	CIPNode * pNext;
public:
	CIPNode(void);

	~CIPNode(void);
	CIPNode(unsigned long dwSourceIP, unsigned long dwDestIP, unsigned char chPro, unsigned short dwFlow);
	//�������ݰ�����
	void addCount();
	//�������ݰ�����
	void addFlow(unsigned short dwFlow);
	//ȡ�����ݰ�����
	unsigned  long  getCount();
	//ȡ�����ݰ�����
	unsigned short getFlow();
	//ȡ��ԴIP��ַ
	unsigned  long  getSourceIPAddr();
	//ȡ��Ŀ��IP��ַ
	unsigned long getDestIPAddr();
	//ȡ��Э������
	unsigned char getProtocol();
	// ȡ��Э������
	char * getProtocol_String();

};