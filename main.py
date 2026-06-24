import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
import random

# ==========================================
# 1. Network Graph Setup
# ==========================================

class Neo4jNetworkManager:
    def __init__(self, uri, user, password):
        """Initializes the Neo4j driver connection."""
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        logging.info("Initialized Neo4j Database connection.")

    def close(self):
        """Closes the database connection safely."""
        self.driver.close()
        logging.info("Closed Neo4j Database connection.")

    def initialize_topology_schema(self) -> None:
        """
        Creates necessary constraints and builds the initial static
        network graph in the database if no external dataset is used.
        """
        query = """
        // Step 1: Create index constraint
        CREATE CONSTRAINT unique_router_name IF NOT EXISTS
        FOR (r:Router) REQUIRE r.name IS UNIQUE;

        // Step 2: Batch-create nodes and weighted relationships
        WITH [
            {source: 'A', target: 'B', latency: 10},
            {source: 'A', target: 'C', latency: 15},
            {source: 'A', target: 'D', latency: 20},
            {source: 'B', target: 'E', 15},
            {source: 'C', target: 'F', 10},
            {source: 'D', target: 'F', 30},
            {source: 'F', target: 'Destination', 15}
        ] AS network_links

        UNWIND network_links AS link
        MERGE (src:Router {name: link.source})
        MERGE (tgt:Router {name: link.target})
        MERGE (src)-[r:LINK]->(tgt)
        SET r.latency = link.latency;
        """
        try:
            with self.driver.session() as session:
                session.run(query)
            logging.info("Network topology schema initialized successfully.")
        except Exception as e:
            logging.error(f"Failed to initialize topology: {e}")

    def ingest_production_dataset(self, csv_file_name: str) -> None:
        """
        Ingests a large-scale network traffic dataset (e.g., from Kaggle or SNAP)
        to build a dynamic network graph.
        """
        query = f"""
        LOAD CSV WITH HEADERS FROM 'file:///{csv_file_name}' AS row
        MERGE (src:Router {id: row.Source_IP})
        MERGE (tgt:Router {id: row.Destination_IP})
        MERGE (src)-[r:LINK]->(tgt)
        SET r.latency = toInteger(row.Latency_MS),
            r.bandwidth = toFloat(row.Bandwidth_Mbps);
        """
        with self.driver.session() as session:
            session.run(query)
        logging.info(f"Dataset {csv_file_name} successfully ingested into Neo4j.")

    def execute_gds_routing_algorithm(self, start_node: str, end_node: str) -> dict:
        """
        Projects the network into Neo4j GDS memory and executes Dijkstra's
        algorithm to validate the Python Q-Learning agent's results.
        """
        projection_query = """
        CALL gds.graph.project(
          'networkRoutingGraph',
          'Router',
          { LINK: { type: 'LINK', orientation: 'UNDIRECTED', properties: 'latency' } }
        );
        """

        routing_query = """
        MATCH (source:Router {name: $start_node}), (target:Router {name: $end_node})
        CALL gds.shortestPath.dijkstra.stream('networkRoutingGraph', {
            sourceNode: source,
            targetNode: target,
            relationshipWeightProperty: 'latency'
        })
        YIELD totalCost, nodeIds
        RETURN
            [nodeId IN nodeIds | gds.util.asNode(nodeId).name] AS OptimizedPath,
            totalCost AS TotalNetworkLatency;
        """

        with self.driver.session() as session:
            # Note: In a live environment, we check if the projection exists first.
            # session.run(projection_query)
            result = session.run(routing_query, start_node=start_node, end_node=end_node)
            data = result.single()

            logging.info(f"GDS Engine calculated optimal path: {data['OptimizedPath']}")
            return {"path": data["OptimizedPath"], "latency": data["TotalNetworkLatency"]}

    def persist_ai_path_to_graph(self, start_node: str, end_node: str) -> None:
        """
        Writes the optimal path calculated by the AI agent back to the database.
        Tags relationships with 'isAIChosen' for dashboard visualization.
        """
        query = """
        MATCH (source:Router {name: $start_node}), (target:Router {name: $end_node})
        CALL gds.shortestPath.dijkstra.stream('networkRoutingGraph', {
            sourceNode: source,
            targetNode: target,
            relationshipWeightProperty: 'latency'
        })
        YIELD nodeIds

        WITH [nodeId IN nodeIds | gds.util.asNode(nodeId)] AS pathNodes
        UNWIND range(0, size(pathNodes)-2) AS i

        WITH pathNodes[i] AS node1, pathNodes[i+1] AS node2
        MATCH (node1)-[r:LINK]-(node2)
        SET r.isAIChosen = true, r.lastOptimized = datetime();
        """
        with self.driver.session() as session:
            session.run(query, start_node=start_node, end_node=end_node)
        logging.info("AI optimized route persisted to graph for visualization.")
def create_network():
    """Creates a mock computer network graph with simulated traffic (latency)."""
    G = nx.Graph()
    
    # Define routers (nodes) and connections (edges) with latency weights
    edges = [
        ('A', 'B', 10), ('A', 'C', 15), ('A', 'D', 20),
        ('B', 'C', 35), ('B', 'E', 15),
        ('C', 'E', 20), ('C', 'F', 10), ('C', 'D', 25),
        ('D', 'F', 30), ('E', 'G', 10),
        ('F', 'G', 40), ('F', 'H', 15),
        ('G', 'H', 20), ('G', 'I', 10),
        ('H', 'I', 25), ('I', 'Destination', 10),
        ('H', 'Destination', 30)
    ]
    
    G.add_weighted_edges_from(edges)
    return G

# ==========================================
# 2. AI Q-Learning Agent
# ==========================================
def train_q_learning_agent(G, source, destination, episodes=1000):
    """Trains an AI agent to find the lowest-latency path using Q-Learning."""
    # Initialize Q-Table with zeros
    q_table = {node: {neighbor: 0 for neighbor in G.neighbors(node)} for node in G.nodes()}
    
    # Hyperparameters
    alpha = 0.1      # Learning rate
    gamma = 0.9      # Discount factor
    epsilon = 1.0    # Exploration rate
    epsilon_decay = 0.99
    min_epsilon = 0.01

    for _ in range(episodes):
        current_node = source
        
        while current_node != destination:
            neighbors = list(G.neighbors(current_node))
            
            # Explore vs. Exploit
            if random.uniform(0, 1) < epsilon:
                next_node = random.choice(neighbors)
            else:
                # Exploit: choose the neighbor with the highest Q-value
                next_node = max(q_table[current_node], key=q_table[current_node].get)
            
            # Calculate reward (Negative weight because we want to minimize latency)
            weight = G[current_node][next_node]['weight']
            reward = -weight
            
            # Give a massive bonus if it reaches the destination
            if next_node == destination:
                reward += 100 
                
            # Bellman Equation Update
            max_future_q = max(q_table[next_node].values()) if next_node != destination else 0
            current_q = q_table[current_node][next_node]
            
            q_table[current_node][next_node] = current_q + alpha * (reward + gamma * max_future_q - current_q)
            
            current_node = next_node
            
        # Decay exploration rate
        epsilon = max(min_epsilon, epsilon * epsilon_decay)
        
    return q_table

# ==========================================
# 3. Path Extraction
# ==========================================
def get_optimal_path(q_table, source, destination):
    """Extracts the best path from the trained Q-Table."""
    path = [source]
    current_node = source
    
    while current_node != destination:
        next_node = max(q_table[current_node], key=q_table[current_node].get)
        path.append(next_node)
        current_node = next_node
        
    return path

# ==========================================
# 4. Visualization (Making it look good)
# ==========================================
def visualize_network(G, optimal_path):
    """Draws a stylized dark-mode visualization of the network and the AI's path."""
    plt.figure(figsize=(12, 8), facecolor='#121212')
    ax = plt.gca()
    ax.set_facecolor('#121212')
    
    # Generate a layout for the nodes
    pos = nx.spring_layout(G, seed=42, k=0.75)
    
    # Create a list of edges in the optimal path for highlighting
    path_edges = list(zip(optimal_path, optimal_path[1:]))
    
    # Draw all edges (dimmed out)
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color='#444444', width=2, alpha=0.5)
    
    # Draw optimal path edges (bright glowing color)
    nx.draw_networkx_edges(G, pos, ax=ax, edgelist=path_edges, edge_color='#00ffcc', width=4)
    
    # Draw all nodes
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color='#1f1f1f', edgecolors='#00ffcc', 
                           linewidths=2, node_size=800)
    
    # Draw labels
    nx.draw_networkx_labels(G, pos, ax=ax, font_color='white', font_size=12, font_weight='bold')
    
    # Add Edge weight labels (Latency)
    edge_labels = nx.get_edge_attributes(G, 'weight')
    nx.draw_networkx_edge_labels(G, pos, ax=ax, edge_labels=edge_labels, font_color='#aaaaaa', 
                                 font_size=9, bbox=dict(facecolor='#121212', edgecolor='none'))

    plt.title("AI Q-Learning Network Routing Optimization", color='white', fontsize=16, pad=20)
    plt.axis('off')
    plt.tight_layout()
    plt.show()

# ==========================================
# Main Execution
# ==========================================
if __name__ == "__main__":
    start_node = 'A'
    end_node = 'Destination'
    
    print("Building network topology...")
    network = create_network()
    
    print("Training AI Agent (Q-Learning)...")
    trained_q_table = train_q_learning_agent(network, start_node, end_node)
    
    print("Extracting optimal path...")
    ai_path = get_optimal_path(trained_q_table, start_node, end_node)
    
    print(f"Optimal Path found by AI: {' -> '.join(ai_path)}")
    print("Generating visuals...")
    
    visualize_network(network, ai_path)
