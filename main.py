import draw
from lan import LAN


if __name__ == "__main__":
    lan = LAN()
    port_scan_results = lan.port_scan_network()
    # draw a graph with the results
    draw.create_graph(lan.get_router_ip(), port_scan_results)
