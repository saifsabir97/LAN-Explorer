import socket
import threading

import netaddr
import netifaces as ni
import nmap


def get_internet_facing_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def get_internet_facing_subnet_mask():
    ip = get_internet_facing_ip()

    for interface in ni.interfaces():
        if ni.AF_INET in ni.ifaddresses(interface):
            for interface_address in ni.ifaddresses(interface)[ni.AF_INET]:
                if interface_address["addr"] == ip:
                    return interface_address["netmask"]


def get_internet_facing_gateway():
    print("fetching internet facing gateway")
    gateways = ni.gateways()
    default_gateway = gateways["default"][ni.AF_INET][0]
    return default_gateway


def get_network_cidr():
    print("fetching internet facing network")
    my_network = netaddr.IPNetwork(get_internet_facing_ip(), get_internet_facing_subnet_mask())
    network_id = str(my_network.network) + "/" + str(my_network).split('/')[1]
    return network_id


def port_scan_network(network_cidr):
    print(f"port scanning {network_cidr}")
    nm = nmap.PortScanner()
    nm.scan(network_cidr, '22-443')

    results = {}

    scan_threads = []

    for host in nm.all_hosts():
        t = threading.Thread(target=port_scan_host, args=(host, results, nm,))
        scan_threads.append(t)
        t.start()

    for t in scan_threads:
        t.join()

    return results


def port_scan_host(host, results, nm):
    print(f"    scanning {host}")
    results[host] = {"ip": host, "hostname": nm[host].hostname(), "state": nm[host].state()}
    open_ports = []
    for proto in nm[host].all_protocols():
        lport = list(nm[host][proto].keys())
        lport.sort()
        for port in lport:
            open_ports.append(f"{proto}/{port} ({nm[host][proto][port]['state']}) | ")
    results[host]["open_ports"] = "\n".join(open_ports)[:-2]
    if results[host]["open_ports"] == "":
        results[host]["open_ports"] = "No ports open"
