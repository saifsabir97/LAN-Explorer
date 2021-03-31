from utils import network_utils, draw_utils


def process_network():
    # get internet facing subnet/gateway information
    internet_facing_subnet = network_utils.get_network_cidr()
    internet_facing_gateway = network_utils.get_internet_facing_gateway()

    # port scan all live hosts in the internet facing interface subnet
    port_scan_results = network_utils.port_scan_network(internet_facing_subnet)

    # draw a graph with the results
    draw_utils.draw_graph(internet_facing_gateway, port_scan_results)


if __name__ == "__main__":
    process_network()
