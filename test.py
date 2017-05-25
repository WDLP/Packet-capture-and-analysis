#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2017-05-24 19:46:23
# @Author  : jiong (447991103@qq.com)
# @Link    : ${link}
# @Version : $Id$

"""
package capture and analysis

Usage:
	test.py [--arp] [--arp] [--icmp] [--igmp] [--dhcp] [--bootp] [--udp] [--tcp] [--ip]

Options:
	-h,--help 显示帮助
	--arp        分析arp包
	--icmp       分析icmp包
	--igmp       分析igmp包
	--dhcp       分析dhcp包
	--bootp      分析bootp包
	--udp        分析udp包
	--tcp        分析tcp包
	--ip         分析ip包

"""

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

from subprocess import *
from docopt import docopt
arguments = docopt(__doc__)
print arguments
if arguments['--arp']:
	print('analysis...')
	cmd = '{0} {1} '.format('arp.exe','a')
	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
elif arguments['--icmp']:
	print('analysis...')
	cmd = '{0} {1} '.format('arp.exe','icmp')
	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
elif arguments['--igmp']:
	print('analysis...')
	cmd = '{0} {1} '.format('arp.exe','igmp')
	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
elif arguments['--dhcp']:
	print('analysis...')
	cmd = '{0} {1} '.format('arp.exe','dhcp')
	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
elif arguments['--bootp']:
	print('analysis...')
	cmd = '{0} {1} '.format('arp.exe','bootp')
	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
elif arguments['--udp']:
	print('analysis...')
	cmd = '{0} {1} '.format('arp.exe','udp')
	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
elif arguments['--tcp']:
	print('analysis...')
	cmd = '{0} {1} '.format('arp.exe','tcp')
	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
elif arguments['--ip']:
	print('analysis...')
	cmd = '{0} {1} '.format('arp.exe','ip')
	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)






