import networkx as nx
from pyvis.network import Network
import random

def build_datacenter_topology():
    """
    Builds a hierarchical network graph simulating the Neo4j schema:
    (DataCenter) -[:CONTAINS]-> (Router) -[:ROUTES]-> (Interface)
    """
    G = nx.Graph()

    # 1. Add the Core DataCenter
    G.add_node("DC_Iceland", group="datacenter", label="Iceland DataCenter\n(Reykjavik)", title="Type: DataCenter\nStatus: Active", size=40)

    # 2. Add Core Routers (The 'A', 'B', 'C' nodes from the AI model)
    routers = ['Router_A', 'Router_B', 'Router_C', 'Router_D', 'Router_E']
    for r in routers:
        G.add_node(r, group="router", label=r, title=f"Type: Core Router\nUptime: 99.9%", size=25)
        # DataCenter CONTAINS Router
        G.add_edge("DC_Iceland", r, title="[:CONTAINS]", color="#555555")

    # Connect Routers to each other (Backbone Links with Latency)
    backbone_links = [
        ('Router_A', 'Router_B', 10), ('Router_A', 'Router_C', 15),
        ('Router_B', 'Router_D', 20), ('Router_C', 'Router_E', 12),
        ('Router_D', 'Router_E', 8)
    ]
    for src, dst, lat in backbone_links:
        G.add_edge(src, dst, title=f"Latency: {lat}ms", value=lat, color="#555555")

    # 3. Add Interfaces (IP Addresses)
    # Simulating the Neo4j output: RETURN i.ip as ip
    for r in routers:
        # Generate 3-5 random interfaces for each router
        for _ in range(random.randint(3, 5)):
            ip = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
            G.add_node(ip, group="interface", label=ip, title="Type: Interface", size=15)
            # Router ROUTES to Interface
            G.add_edge(r, ip, title="[:ROUTES]", color="#888888", dashes=True)

    return G

def generate_interactive_html(G, output_file="iceland_network_map.html"):
    """
    Takes the NetworkX graph and converts it into a highly styled,
    interactive HTML dashboard using PyVis.
    """
    # Initialize the PyVis network with a dark theme
    net = Network(height="800px", width="100%", bgcolor="#121212", font_color="white", select_menu=True)

    # Translate the NetworkX graph to PyVis
    net.from_nx(G)

    # Apply styling based on node groups (Schema matching)
    for node in net.nodes:
        if node.get("group") == "datacenter":
            node["color"] = "#ff4d4d"  # Red for Datacenter
            node["shape"] = "hexagon"
        elif node.get("group") == "router":
            node["color"] = "#ffb84d"  # Orange for Routers
            node["shape"] = "square"
        elif node.get("group") == "interface":
            node["color"] = "#00ffcc"  # Cyan for IP Interfaces
            node["shape"] = "dot"

    # Add a glowing overlay for an "AI Optimized Route"
    # Let's say the AI chose to route a packet from Router_A -> Router_C -> Router_E -> 10.0.X.X
    ai_route = ['Router_A', 'Router_C', 'Router_E']

    for edge in net.edges:
        if edge['from'] in ai_route and edge['to'] in ai_route:
            edge['color'] = "#00ffcc" # Neon Cyan for active route
            edge['width'] = 4
            edge['title'] = "AI OPTIMIZED PATH - " + edge.get('title', '')

    # Configure physics for a smooth, organic layout
    net.set_options("""
    var options = {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -100,
          "centralGravity": 0.01,
          "springLength": 100,
          "springConstant": 0.08
        },
        "minVelocity": 0.75,
        "solver": "forceAtlas2Based"
      }
    }
    """)

    print(f"Generating visualization... Saving to {output_file}")
    net.write_html(output_file)

if __name__ == "__main__":
    print("Building DataCenter Topology based on Neo4j schema...")
    network_graph = build_datacenter_topology()

    generate_interactive_html(network_graph)
    print("Done! Open 'iceland_network_map.html' in your web browser.")
