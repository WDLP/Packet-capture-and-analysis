## Packet-capture-and-analysis

- vs编译的时候，因为用的函数接口比较老，会报错，可以在项目属性那边将c++ sdl检查修改为false。
- 生成的exe文件已管理员方式运行。


### 下载配置

- [winpcap下载](https://www.winpcap.org/devel.htm)
	- [winpcap.exe](https://www.winpcap.org/install/default.htm)
	- [dev lib](https://www.winpcap.org/install/default.htm)

- [winpcap配置](https://www.findhao.net/easycoding/871)

## 过滤设置
[pcap过滤器](http://blog.csdn.net/edger2heaven/article/details/50466498)
[过滤串表达式的语法](http://www.ferrisxu.com/WinPcap/html/group__language.html)

### arp
- [arp抓取](http://blog.csdn.net/u013539342/article/details/48525525)
有最小帧长度的限制，即使是arp 14+28=42字节，也需要增加填充数字到到最小的60字节

### 以太网帧类型字段
- [EtherType 字段中常用值及其对应的协议](http://www.cnblogs.com/xmphoenix/archive/2011/09/14/2176412.html)

### LLMNR
[safertos](http://blog.csdn.net/zhzht19861011/article/details/49819109)
[利用LLMNR名称解析缺陷劫持内网指定主机会话](http://www.2cto.com/article/201512/453332.html)
[freertos](http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/LLMNR.html)


### igmp
- [igmp v1 v2 区别](https://wenku.baidu.com/view/c3d5348ebceb19e8b8f6ba0e.html)
- [v3](http://blog.csdn.net/shanzhizi/article/details/7645330)

### snmp
- [SNMP协议入门](http://blog.csdn.net/jia18703423204/article/details/46372351)

### python调用命令
- [子进程是一个交互进程，需要一次输入输出，直接打开一个新窗口](http://blog.csdn.net/jtujtujtu/article/details/47949775)