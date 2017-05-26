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
	test.py [--arp | --icmp | --igmp | --dhcp | --bootp | --udp | --tcp | --ip] --time=t


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
	--time=t     捕获数据包时间

"""

import sys
reload(sys)
sys.setdefaultencoding('utf-8')


def analysis(command, *argu):
    # return

    if argu:
        print('analysis...')
        cmd = '{0} {1} {2}'.format('arp.exe', command, argu[0])
        print cmd
        proc = Popen(cmd, shell=False, creationflags=CREATE_NEW_CONSOLE)
    else:
        print('analysis...')
        cmd = '{0} {1} {2}'.format('arp.exe', command, 0)
        print cmd
        proc = Popen(cmd, shell=False, creationflags=CREATE_NEW_CONSOLE)

from subprocess import *
from docopt import docopt
arguments = docopt(__doc__)
# print arguments

command = ''
time = 0
for each in arguments:
    if arguments[each]:
        if each.strip('-') in ['arp', 'icmp', 'igmp','dhcp','bootp','udp','tcp','ip']:
            command = each.strip('-')
            print command
if arguments['--time']:
    time = arguments['--time']
    analysis(command, time)
else:
    analysis(command)


# if arguments['--arp']:
# 	if arguments['--time']:
# 	print('analysis...')
# 	cmd = '{0} {1} '.format('arp.exe','arp',int(t))
# 	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
# 	else
# elif arguments['--icmp']:
# 	print('analysis...')
# 	cmd = '{0} {1} '.format('arp.exe','icmp')
# 	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
# elif arguments['--igmp']:
# 	print('analysis...')
# 	cmd = '{0} {1} '.format('arp.exe','igmp')
# 	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
# elif arguments['--dhcp']:
# 	print('analysis...')
# 	cmd = '{0} {1} '.format('arp.exe','dhcp')
# 	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
# elif arguments['--bootp']:
# 	print('analysis...')
# 	cmd = '{0} {1} '.format('arp.exe','bootp')
# 	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
# elif arguments['--udp']:
# 	print('analysis...')
# 	cmd = '{0} {1} '.format('arp.exe','udp')
# 	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
# elif arguments['--tcp']:
# 	print('analysis...')
# 	cmd = '{0} {1} '.format('arp.exe','tcp')
# 	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
# elif arguments['--ip']:
# 	print('analysis...')
# 	cmd = '{0} {1} '.format('arp.exe','ip')
# 	proc=Popen(cmd, shell = False,creationflags =CREATE_NEW_CONSOLE)
