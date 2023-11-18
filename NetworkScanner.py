import ipaddress
from scapy.all import ARP, Ether, srp

def get_ip_range():
    while True:
        try:
            ip_range = input("Enter the IP range (CIDR notation or start-end format): ")
            ip_network = ipaddress.ip_network(ip_range, strict=False)
            return ip_network
        except ValueError:
            print("Invalid input. Please enter a valid IP range.")


def get_mac(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    return result[0][1].hwsrc

def get_mac_addresses(ip_range):
    mac_addresses = {}

    for ip in ip_range:
        mac = get_mac(ip)
        mac_addresses[ip] = mac

    return mac_addresses


ip_range = get_ip_range()

mac_addresses = get_mac_addresses(ip_range)

for ip, mac in mac_addresses.items():
    print(f"IP: {ip} => MAC: {mac}")


