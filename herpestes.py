from IPy import IP
import optparse
import socket
import dns.resolver, dns.reversename
from scapy.all import ARP, Ether, srp
import subprocess
import re

def reverseDns(ip):
    ip2=IP(ip)
    print(ip2.reverseName())
    print(socket.getnameinfo((ip, 0),0))

def networkdiscover(net_ip):
    arp = ARP(pdst=net_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip':received.psrc, 'mac': received.hwsrc})
    print("Available devices in the network: ")
    print("IP" + " "*12+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

def osdetect(os_ip):
    p = subprocess.Popen(["ping", "-c", "1",os_ip], stdout=subprocess.PIPE)
    res=p.communicate()[0]
    if p.returncode > 0:
        print('server error')
    else:
        pattern = re.compile('ttl=\d*')
        f = open("ostypes.txt","r")
        for line in f:
            a = line.strip().split("-")
            if a[1] == pattern.search(str(res)).group():
                print(a[0])
    


def main():
    parser = optparse.OptionParser()
    parser.add_option('-r', dest='ip', help='Reversing ip.')
    parser.add_option('-n', dest='net_ip',help='Discover the available divaces same network .')
    parser.add_option('-o',dest='os_ip',help='Discover target operating system.')
    (options, arguments) = parser.parse_args()
 
    ip = options.ip
    reverseDns(ip)
    net_ip =options.net_ip
    networkdiscover(net_ip)
    os_ip = options.os_ip
    osdetect(os_ip)

if __name__ == "__main__":
    main()
