import dpkt
import socket
f = open('f*cking_pcap+file.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)

    #checking if the packet is a DNS query
    if dns.qr == dpkt.dns.DNS_Q:
        #extracting the domain name from the query
        domain_name = dns.qd[0].name
        #extracting the IP address from the query
        ip_address = socket.inet_ntoa(ip.src)
        #printing the domain name and IP address
        print('Domain Name: %s, IP Address: %s' % (domain_name, ip_address))
