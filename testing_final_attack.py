"""
another_final.py
----------------------------
Pure Python Interactive Dashboard for Temporal Knowledge Graphs (TKG).
Powered by Dash, Plotly, NetworkX, and Neo4j.
"""

import dash
from dash import dcc, html, Input, Output
import plotly.graph_objects as go
import networkx as nx
from neo4j import GraphDatabase, basic_auth
import sys

# ==========================================
# DATABASE CONFIGURATION
# ==========================================
NEO4J_URI = "bolt://3.236.156.185:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "projectiles-fantails-electrodes"

# ==========================================
# 1. DATA INGESTION (Neo4j & Fallback)
# ==========================================
def run_specific_report(driver):
    """Runs the exact Cypher query requested for the Iceland Data Centers."""
    print("[*] Running Custom Iceland Data Center Report...")
    cypher_query = '''
    MATCH (dc:DataCenter {location: $location})-[:CONTAINS]->(r:Router)-[:ROUTES]->(i:Interface)
    RETURN i.ip as ip
    '''
    try:
        with driver.session(database="neo4j") as session:
            # Using execute_read for newer Neo4j drivers
            results = session.execute_read(
                lambda tx: tx.run(cypher_query, location="Iceland").data()
            )
            print(f"    Found {len(results)} interfaces routing through Iceland:")
            for record in results:
                print(f"    -> IP: {record['ip']}")
    except Exception as e:
        print(f"[!] Warning: Custom report failed. Error: {e}")

def fetch_graph_data_from_neo4j(driver):
    """Extracts live graph structure and injects a simulated Zero-Day threat."""
    print("[*] Fetching network topology from Neo4j...")
    nodes_dict = {}
    edges = []

    # 1. PULL LIVE "NOISE" FROM YOUR DATABASE
    graph_query = 'MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 300'
    with driver.session() as session:
        results = session.run(graph_query)
        for record in results:
            n, m, r = record["n"], record["m"], record["r"]

            if n.element_id not in nodes_dict:
                group = list(n.labels)[0].lower() if n.labels else "endpoint"
                nodes_dict[n.element_id] = {"id": n.element_id, "label": n.get("name", n.get("ip", str(n.element_id))), "group": group, "scale_level": 3}

            if m.element_id not in nodes_dict:
                group = list(m.labels)[0].lower() if m.labels else "endpoint"
                nodes_dict[m.element_id] = {"id": m.element_id, "label": m.get("name", m.get("ip", str(m.element_id))), "group": group, "scale_level": 3}

            # Map all normal database traffic to time_step 1 and 2
            edges.append({
                "from": n.element_id, "to": m.element_id,
                "title": f"Relation: {r.type}",
                "time_step": 2, "scale_level": 3,
                "is_threat": False
            })

    # 2. INJECT THE RED ZERO-DAY THREAT INTO THE LIVE DATA
    if len(nodes_dict) > 1:
        print("[*] Injecting Zero-Day Attack Simulation into live topology...")
        live_node_ids = list(nodes_dict.keys())

        # Pick two random real nodes from your DB to act as the "Victims"
        victim_1 = live_node_ids[5]
        victim_2 = live_node_ids[10]

        # Add the external Attacker and C2 Server
        nodes_dict["Attacker"] = {"id": "Attacker", "label": "EXTERNAL THREAT", "group": "threat", "scale_level": 1}
        nodes_dict["C2"] = {"id": "C2", "label": "C2 SERVER", "group": "threat", "scale_level": 1}

        # Add the thick red malicious edges (Happening at Time Steps 3 and 4)
        edges.append({"from": "Attacker", "to": victim_1, "title": "EXPLOITS VULNERABILITY", "time_step": 3, "scale_level": 1, "is_threat": True, "z_score": "99.9"})
        edges.append({"from": victim_1, "to": victim_2, "title": "LATERAL MOVEMENT", "time_step": 3, "scale_level": 1, "is_threat": True, "z_score": "14.5"})
        edges.append({"from": victim_2, "to": "C2", "title": "DATA EXFILTRATION", "time_step": 4, "scale_level": 1, "is_threat": True, "z_score": "99.9"})

    return list(nodes_dict.values()), edges
def generate_procedural_fallback():
    """Fallback generator if Neo4j is empty or unreachable."""
    print("[!] Proceeding with Procedural Fallback Generation...")
    nodes = [
        {"id": "Attacker", "label": "External IP", "group": "threat", "scale_level": 1},
        {"id": "Web1", "label": "Web Server 01", "group": "server", "scale_level": 1},
        {"id": "Switch1", "label": "Core Switch", "group": "hardware", "scale_level": 1},
        {"id": "DB1", "label": "Primary DB", "group": "server", "scale_level": 1},
        {"id": "C2", "label": "Command & Control", "group": "threat", "scale_level": 1},
        {"id": "Host1", "label": "Host 10.0.1.5", "group": "endpoint", "scale_level": 2},
        {"id": "Host2", "label": "Host 10.0.1.6", "group": "endpoint", "scale_level": 3},
    ]
    edges = [
        {"from": "Host1", "to": "Switch1", "title": "SENDS", "time_step": 1, "scale_level": 2, "is_threat": False},
        {"from": "Host2", "to": "Switch1", "title": "SENDS", "time_step": 2, "scale_level": 3, "is_threat": False},
        {"from": "Switch1", "to": "Web1", "title": "POLLS", "time_step": 2, "scale_level": 1, "is_threat": False},
        {"from": "Attacker", "to": "Web1", "title": "EXPLOITS", "time_step": 3, "scale_level": 1, "is_threat": True, "z_score": "99.9"},
        {"from": "Web1", "to": "Switch1", "title": "PIVOTS", "time_step": 3, "scale_level": 1, "is_threat": True, "z_score": "14.5"},
        {"from": "Switch1", "to": "DB1", "title": "MALWARE", "time_step": 4, "scale_level": 1, "is_threat": True, "z_score": "22.1"},
        {"from": "DB1", "to": "C2", "title": "EXFIL", "time_step": 4, "scale_level": 1, "is_threat": True, "z_score": "99.9"},
    ]
    return nodes, edges

# --- Initialize Data ---
print("================================================================")
print("   Temporal Graph Knowledge (TKG) Compiler                      ")
print("================================================================")

try:
    print(f"[*] Attempting to connect to Neo4j at {NEO4J_URI}...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASS))
    driver.verify_connectivity()
    print("[+] Connection Successful!")
    run_specific_report(driver)
    raw_nodes, raw_edges = fetch_graph_data_from_neo4j(driver)
    driver.close()
    if not raw_nodes:
        print("[-] Database connected but empty. Using fallback data for visualization.")
        raw_nodes, raw_edges = generate_procedural_fallback()
except Exception as e:
    print(f"[-] Neo4j connection failed: {e}")
    raw_nodes, raw_edges = generate_procedural_fallback()

# ==========================================
# 2. PRE-COMPUTE GRAPH LAYOUT
# ==========================================
G = nx.DiGraph()
for n in raw_nodes:
    G.add_node(n['id'])
for e in raw_edges:
    G.add_edge(e['from'], e['to'])
# Pre-compute positions so the graph doesn't jump around when filtered
pos = nx.spring_layout(G, k=0.5, iterations=50, seed=42)

# ==========================================
# 3. DASH APPLICATION (Pure Python UI)
# ==========================================
app = dash.Dash(__name__)
app.title = "TKG Threat Analytics"

app.layout = html.Div(style={'backgroundColor': '#0c0e12', 'color': '#ffffff', 'fontFamily': 'sans-serif', 'padding': '20px', 'height': '100vh', 'display': 'flex', 'flexDirection': 'column'}, children=[
    html.H1("Zero-Day Anomaly Detection Dashboard", style={'textAlign': 'center', 'color': '#58a6ff'}),
    
    html.Div([
        html.Div([
            html.Label("Network Scale (Data Volume Noise)", style={'fontWeight': 'bold'}),
            dcc.Slider(1, 3, 1, id='scale-slider', marks={1: {'label': 'Low', 'style': {'color': 'white'}}, 2: {'label': 'Medium', 'style': {'color': 'white'}}, 3: {'label': 'High', 'style': {'color': 'white'}}}, value=3)
        ], style={'width': '45%', 'display': 'inline-block', 'padding': '20px'}),
        
        html.Div([
            html.Label("Temporal Timeline (Time Step)", style={'fontWeight': 'bold'}),
            dcc.Slider(1, 4, 1, id='time-slider', marks={1: {'label': 't1: Init', 'style': {'color': 'white'}}, 2: {'label': 't2: Ops', 'style': {'color': 'white'}}, 3: {'label': 't3: Breach', 'style': {'color': 'white'}}, 4: {'label': 't4: Exfil', 'style': {'color': 'white'}}}, value=4)
        ], style={'width': '45%', 'display': 'inline-block', 'padding': '20px'})
    ], style={'backgroundColor': '#161a22', 'borderRadius': '10px', 'marginBottom': '20px'}),

    html.Div([
        dcc.Graph(id='network-graph', style={'height': '60vh', 'width': '70%', 'display': 'inline-block', 'verticalAlign': 'top'}),
        html.Div(id='log-panel', style={'height': '60vh', 'width': '28%', 'display': 'inline-block', 'backgroundColor': '#000000', 'border': '1px solid #30363d', 'padding': '15px', 'overflowY': 'scroll', 'fontFamily': 'monospace', 'fontSize': '14px', 'marginLeft': '1%'})
    ])
])

@app.callback(
    Output('network-graph', 'figure'),
    Output('log-panel', 'children'),
    Input('scale-slider', 'value'),
    Input('time-slider', 'value')
)
def update_dashboard(scale_limit, time_limit):
    # Filter Nodes
    active_node_ids = {n['id'] for n in raw_nodes if n.get('scale_level', 1) <= scale_limit}
    
    # Map colors
    color_map = {'threat': '#ff4444', 'hardware': '#ffd166', 'server': '#06d6a0', 'subnet': '#4dadff', 'endpoint': '#8b949e'}
    
    edge_traces = []
    log_messages = []
    
    # Process Edges
    for edge in raw_edges:
        if edge['from'] in active_node_ids and edge['to'] in active_node_ids:
            if edge.get('scale_level', 1) <= scale_limit and edge.get('time_step', 1) <= time_limit:
                x0, y0 = pos[edge['from']]
                x1, y1 = pos[edge['to']]
                
                color = '#ff2a55' if edge.get('is_threat') else '#3a4b5c'
                width = 3 if edge.get('is_threat') else 1
                
                edge_traces.append(go.Scatter(
                    x=[x0, x1, None], y=[y0, y1, None],
                    line=dict(width=width, color=color),
                    hoverinfo='text', text=edge.get('title', ''),
                    mode='lines'
                ))
                
                # Update Logs for CURRENT time step
                if edge.get('time_step', 1) == time_limit:
                    if edge.get('is_threat'):
                        log_messages.append(html.Div(f"[CRITICAL] {edge['from']} -> {edge['to']} | Z-Score: {edge.get('z_score', '99')}", style={'color': '#ff4444', 'marginBottom': '10px'}))
                    else:
                        log_messages.append(html.Div(f"[OK] {edge['from']} -> {edge['to']}", style={'color': '#3fb950', 'marginBottom': '10px'}))

    # Process Nodes
    node_x, node_y, node_colors, node_text = [], [], [], []
    for n in raw_nodes:
        if n['id'] in active_node_ids:
            x, y = pos[n['id']]
            node_x.append(x)
            node_y.append(y)
            node_colors.append(color_map.get(n.get('group', 'endpoint'), '#a0a0a0'))
            node_text.append(n['label'])

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode='markers+text', text=node_text, textposition="top center",
        hoverinfo='text',
        marker=dict(size=20, color=node_colors, line=dict(width=2, color='white')),
        textfont=dict(color='white')
    )

    # Build Figure
    fig = go.Figure(data=edge_traces + [node_trace],
                    layout=go.Layout(
                        showlegend=False, hovermode='closest',
                        margin=dict(b=0, l=0, r=0, t=0),
                        plot_bgcolor='#0c0e12', paper_bgcolor='#0c0e12',
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                    ))
    
    if not log_messages:
        log_messages.append(html.Div("No new activity in this time block.", style={'color': '#8b949e'}))
        
    log_header = html.H3(f"Live Logs (t{time_limit})", style={'color': '#58a6ff', 'marginTop': '0'})
    
    return fig, [log_header] + log_messages

if __name__ == '__main__':
    print("[*] Starting Interactive Python Dashboard...")
    app.run(debug=False, use_reloader=False)
