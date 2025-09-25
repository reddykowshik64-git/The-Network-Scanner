from scapy.all import ARP, Ether, srp
import socket
import ipaddress

def scan_network(network_cidr, timeout=2):
    arp = ARP(pdst=network_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    answered, _ = srp(packet, timeout=timeout, verbose=0)

    results = []
    for _, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = ""
        results.append({"ip": ip, "mac": mac, "hostname": hostname})
    return results

if __name__ == "__main__":
    devices = scan_network("192.168.1.0/24")
    for d in devices:
        print(f"{d['ip']:15} {d['mac']:20} {d['hostname']}")
