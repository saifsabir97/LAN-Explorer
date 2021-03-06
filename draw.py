import networkx as nx
from bokeh.models import HoverTool, Plot, Range1d, Circle, MultiLine
from bokeh.palettes import Spectral4
from bokeh.io import show
from bokeh.plotting import from_networkx


def create_graph(center, results_dict):
    edges = []

    for key, result in results_dict.items():
        if key != center:
            edges.append((center, result))

    tool_tips_list = [
        ("ip", "@ip"),
        ("scan results", "@open_ports")
    ]

    G = nx.Graph()
    G.add_edges_from(edges)
    edge_attrs = {}

    for start_node, end_node, _ in G.edges(data=True):
        edge_attrs[(start_node, end_node)] = "black"

    nx.set_edge_attributes(G, edge_attrs, "edge_color")
    nx.set_node_attributes(G, values=results_dict)

    plot = Plot(plot_width=600, plot_height=600,
                x_range=Range1d(-1.1, 1.1), y_range=Range1d(-1.1, 1.1))
    plot.title.text = "LAN port scan results"
    node_hover_tool = HoverTool(tooltips=tool_tips_list)
    plot.add_tools(node_hover_tool)

    graph_renderer = from_networkx(G, nx.spring_layout, scale=1, center=(0, 0))
    graph_renderer.node_renderer.glyph = Circle(size=15, fill_color=Spectral4[0])
    graph_renderer.edge_renderer.glyph = MultiLine(line_color="edge_color", line_alpha=0.8, line_width=1)

    plot.renderers.append(graph_renderer)

    show(plot)
