from IPy import IP
import optparse
import socket
import dns.resolver, dns.reversename
from scapy.all import ARP, Ether, srp


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
    


def main():
    parser = optparse.OptionParser()
    parser.add_option('-r', dest='ip', help='Reversing ip.')
    parser.add_option('-n', dest='net_ip',help='Discover the available divaces same network .')
    (options, arguments) = parser.parse_args()
 
    ip = options.ip
    reverseDns(ip)
    net_ip =options.net_ip
    networkdiscover(net_ip)

if __name__ == "__main__":
    main()
 
