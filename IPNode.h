#pragma once

class CIPNode
{

private:
	unsigned  long m_dwSourceIPAddr;               //源IP地址
	unsigned  long m_dwDestIPAddr;                 //目的IP地址
	unsigned  char m_chProtocol;                  //IP包协议类型 
	unsigned  long m_dwCounter;                    //数据包的数量
	unsigned short m_dwFlow;                     //数据包的流量
public:
	CIPNode * pNext;
public:
	CIPNode(void);

	~CIPNode(void);
	CIPNode(unsigned long dwSourceIP, unsigned long dwDestIP, unsigned char chPro, unsigned short dwFlow);
	//增加数据包数量
	void addCount();
	//增加数据包流量
	void addFlow(unsigned short dwFlow);
	//取得数据包数量
	unsigned  long  getCount();
	//取得数据包流量
	unsigned short getFlow();
	//取得源IP地址
	unsigned  long  getSourceIPAddr();
	//取得目的IP地址
	unsigned long getDestIPAddr();
	//取得协议类型
	unsigned char getProtocol();
	// 取得协议名称
	char * getProtocol_String();

};