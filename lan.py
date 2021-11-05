import socket
import threading

import netifaces as ni
import netaddr
import nmap


class LAN:

    def __init__(self):
        self.__router_ip = self.__get_internet_facing_gateway()
        self.__network_cidr = self.__get_network_cidr()

    def get_router_ip(self):
        return self.__router_ip

    @staticmethod
    # Retrieves the IP address of the router which is connected to internet
    def __get_internet_facing_gateway():
        gateways = ni.gateways()
        default_gateway = gateways["default"][ni.AF_INET][0]
        return default_gateway

    # Retrieves the network address of the LAN in CIDR notation
    def __get_network_cidr(self):
        my_network = netaddr.IPNetwork(
            self.__router_ip,
            self.__get_internet_facing_subnet_mask()
        )
        network_id = str(my_network.network) + "/" + str(my_network).split('/')[1]
        return network_id

    @staticmethod
    def __get_internet_facing_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def __get_internet_facing_subnet_mask(self):
        ip = self.__get_internet_facing_ip()
        for interface in ni.interfaces():
            if ni.AF_INET in ni.ifaddresses(interface):
                for interface_address in ni.ifaddresses(interface)[ni.AF_INET]:
                    if interface_address["addr"] == ip:
                        return interface_address["netmask"]

    # Scans all the connected devices in LAN for open ports in range 22-443
    def port_scan_network(self):
        print(f"port scanning connected devices in {self.__network_cidr}")
        nm = nmap.PortScanner()
        nm.scan(self.__network_cidr, '22-443')
        results = {}
        scan_threads = []
        for host in nm.all_hosts():
            t = threading.Thread(target=self.__port_scan_host, args=(host, results, nm,))
            scan_threads.append(t)
            t.start()
        for t in scan_threads:
            t.join()
        return results

    @staticmethod
    def __port_scan_host(host, results, nm):
        print(f"-----scanning {host}")
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
