import draw
from lan import LAN


def process_network():
    lan = LAN()
    port_scan_results = lan.port_scan_network()
    # draw a graph with the results
    draw.create_graph(lan.get_router_ip(), port_scan_results)


if __name__ == "__main__":
    process_network()
