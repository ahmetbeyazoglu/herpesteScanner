from IPy import IP
import optparse
import socket
import dns.resolver, dns.reversename

def reverseDns(ip):

    ip2=IP(ip)
    print(ip2.reverseName())
    print(socket.getnameinfo((ip, 0),0))


def main():
    parser = optparse.OptionParser()
    parser.add_option('-r', dest='ip', help='specify target.')
    (options, arguments) = parser.parse_args()
    ip = options.ip
    reverseDns(ip)

if __name__ == "__main__":
    main()
