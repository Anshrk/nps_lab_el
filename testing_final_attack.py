"""
cyber_threat_dashboard.py
----------------------------
High-Fidelity Cyber-Threat Visualization Dashboard for Temporal Knowledge Graphs (TKG).
Powered by Dash, Plotly, NetworkX, and Neo4j.
"""

import dash
from dash import dcc, html, Input, Output, State
import plotly.graph_objects as go
import networkx as nx
from neo4j import GraphDatabase, basic_auth
import sys
from datetime import datetime

# ==========================================
# DATABASE CONFIGURATION
# ==========================================
NEO4J_URI = "bolt://44.220.85.253:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "lamp-leaf-parallels"

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
        victim_1 = live_node_ids[5] if len(live_node_ids) > 5 else live_node_ids[0]
        victim_2 = live_node_ids[10] if len(live_node_ids) > 10 else live_node_ids[-1]

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
# 3. DASH APPLICATION (High-Fidelity Cyber-Design)
# ==========================================
app = dash.Dash(__name__)
app.title = "STORM-TKG // Threat Monitor"

# Inject modern styling sheets and keyframe alerts
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            @keyframes flash-threat {
                0% { background-color: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.7); box-shadow: 0 0 10px rgba(239, 68, 68, 0.3); }
                50% { background-color: rgba(239, 68, 68, 0.4); border-color: rgba(239, 68, 68, 1); box-shadow: 0 0 25px rgba(239, 68, 68, 0.7); }
                100% { background-color: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.7); box-shadow: 0 0 10px rgba(239, 68, 68, 0.3); }
            }
            @keyframes border-glow-ok {
                0% { box-shadow: 0 0 5px rgba(16, 185, 129, 0.1); }
                50% { box-shadow: 0 0 15px rgba(16, 185, 129, 0.4); }
                100% { box-shadow: 0 0 5px rgba(16, 185, 129, 0.1); }
            }
            .alert-banner-active {
                animation: flash-threat 2s infinite;
                border-radius: 12px;
                border: 2px solid #ef4444;
                padding: 15px;
                text-align: center;
                font-family: 'Space Grotesk', sans-serif;
                font-weight: 500;
                font-size: 15px;
                letter-spacing: 0.5px;
                color: #ffffff;
                transition: all 0.3s ease;
            }
            .alert-banner-secure {
                background-color: rgba(16, 185, 129, 0.05);
                border: 1px solid rgba(16, 185, 129, 0.3);
                animation: border-glow-ok 4s infinite;
                border-radius: 12px;
                padding: 15px;
                text-align: center;
                font-family: 'Space Grotesk', sans-serif;
                font-weight: 500;
                font-size: 15px;
                letter-spacing: 0.5px;
                color: #10b981;
                transition: all 0.3s ease;
            }
            body {
                margin: 0;
                background-color: #08090c;
                font-family: 'Space Grotesk', sans-serif;
                color: #f3f4f6;
            }
            .control-card {
                background: #0f111a;
                border: 1px solid #1e293b;
                border-radius: 16px;
                padding: 20px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
            }
            .log-card {
                background: #06070a;
                border: 1px solid #1e293b;
                border-radius: 10px;
                padding: 15px;
                overflow-y: auto;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                line-height: 1.6;
            }
            .play-btn {
                background: #ef4444;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 24px;
                font-weight: bold;
                font-size: 13px;
                letter-spacing: 0.5px;
                cursor: pointer;
                transition: all 0.2s ease;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                width: 100%;
            }
            .play-btn:hover {
                transform: translateY(-1px);
                box-shadow: 0 0 15px rgba(239, 68, 68, 0.4);
            }
            .play-btn:active {
                transform: translateY(0);
            }
            .play-btn.paused {
                background: #3b82f6;
            }
            .play-btn.paused:hover {
                box-shadow: 0 0 15px rgba(59, 130, 246, 0.4);
            }
            /* Custom Scrollbar for Logs */
            .log-card::-webkit-scrollbar {
                width: 6px;
            }
            .log-card::-webkit-scrollbar-track {
                background: #06070a;
            }
            .log-card::-webkit-scrollbar-thumb {
                background: #1e293b;
                border-radius: 3px;
            }
            .log-card::-webkit-scrollbar-thumb:hover {
                background: #334155;
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

app.layout = html.Div(
    style={
        'backgroundColor': '#08090c',
        'color': '#f3f4f6',
        'fontFamily': '"Space Grotesk", sans-serif',
        'padding': '0',
        'margin': '0',
        'minHeight': '100vh',
        'display': 'flex',
        'flexDirection': 'column'
    },
    children=[
        # Interval for Playback (default disabled)
        dcc.Interval(
            id='play-interval',
            interval=3500,  # 3.5 seconds loop
            n_intervals=0,
            disabled=True
        ),

        # Header Bar
        html.Div(
            style={
                'background': 'linear-gradient(90deg, #0d0e15 0%, #1e1b4b 100%)',
                'borderBottom': '1px solid #1e293b',
                'padding': '15px 30px',
                'display': 'flex',
                'alignItems': 'center',
                'justifyContent': 'space-between',
                'boxShadow': '0 4px 15px rgba(0, 0, 0, 0.4)'
            },
            children=[
                html.Div([
                    html.H1(
                        "🛡️ STORM-TKG // Zero-Day Threat Monitor",
                        style={
                            'margin': '0',
                            'fontSize': '24px',
                            'fontWeight': 'bold',
                            'letterSpacing': '1px',
                            'color': '#38bdf8',
                            'textShadow': '0 0 10px rgba(56, 189, 248, 0.3)'
                        }
                    ),
                    html.Div(
                        "Temporal Knowledge Graph Vulnerability & Lateral Movement Analyzer",
                        style={'fontSize': '12px', 'color': '#94a3b8', 'marginTop': '4px'}
                    )
                ]),
                html.Div(
                    style={'display': 'flex', 'gap': '15px'},
                    children=[
                        html.Div(
                            "LIVE INJECTION ENGINE ACTIVE",
                            style={
                                'background': 'rgba(56, 189, 248, 0.1)',
                                'border': '1px solid rgba(56, 189, 248, 0.3)',
                                'borderRadius': '6px',
                                'padding': '6px 14px',
                                'fontSize': '11px',
                                'color': '#38bdf8',
                                'fontWeight': 'bold',
                                'letterSpacing': '1px'
                            }
                        )
                    ]
                )
            ]
        ),

        # Status / Dynamic Alert Banner (Full width, visibly loud!)
        html.Div(
            id='alert-banner-container',
            style={'padding': '20px 30px 10px 30px'},
            children=[]
        ),

        # Main Workspace Container
        html.Div(
            style={
                'display': 'flex',
                'flexDirection': 'row',
                'padding': '10px 30px 30px 30px',
                'gap': '25px',
                'flex': '1'
            },
            children=[
                # Left Column: Graph Canvas (70% width)
                html.Div(
                    style={
                        'width': '70%',
                        'display': 'flex',
                        'flexDirection': 'column',
                        'background': '#0f111a',
                        'border': '1px solid #1e293b',
                        'borderRadius': '16px',
                        'padding': '18px',
                        'boxShadow': '0 10px 25px rgba(0, 0, 0, 0.5)',
                        'position': 'relative'
                    },
                    children=[
                        html.Div(
                            style={
                                'display': 'flex',
                                'justifyContent': 'space-between',
                                'alignItems': 'center',
                                'marginBottom': '10px',
                                'borderBottom': '1px solid #1e293b',
                                'paddingBottom': '10px'
                            },
                            children=[
                                html.Span("🖥️ GRAPH TELEMETRY WORKSPACE", style={'fontSize': '12px', 'fontWeight': 'bold', 'color': '#94a3b8', 'letterSpacing': '0.5px'}),
                                html.Span("Exploit path annotations appear dynamically as threats emerge.", style={'fontSize': '11px', 'color': '#64748b'})
                            ]
                        ),
                        dcc.Graph(
                            id='network-graph',
                            style={'height': '62vh', 'width': '100%'},
                            config={'displayModeBar': False}
                        )
                    ]
                ),

                # Right Column: Controls & Monitored Logs (30% width)
                html.Div(
                    style={
                        'width': '30%',
                        'display': 'flex',
                        'flexDirection': 'column',
                        'gap': '20px'
                    },
                    children=[
                        # Control panel card
                        html.Div(
                            className='control-card',
                            children=[
                                html.H3("🕹️ COMMAND CONTROLS", style={'margin': '0 0 20px 0', 'fontSize': '16px', 'color': '#38bdf8', 'borderBottom': '1px solid #1e293b', 'paddingBottom': '8px'}),

                                # Scale slider
                                html.Div(
                                    style={'marginBottom': '25px'},
                                    children=[
                                        html.Label("Network Complexity (Scale Noise Filter)", style={'fontSize': '12px', 'fontWeight': 'bold', 'color': '#94a3b8', 'display': 'block', 'marginBottom': '8px'}),
                                        dcc.Slider(
                                            id='scale-slider',
                                            min=1,
                                            max=3,
                                            step=1,
                                            marks={
                                                1: {'label': 'Filtered', 'style': {'color': '#94a3b8', 'fontSize': '10px'}},
                                                2: {'label': 'Standard', 'style': {'color': '#94a3b8', 'fontSize': '10px'}},
                                                3: {'label': 'Full DB Noise', 'style': {'color': '#94a3b8', 'fontSize': '10px'}}
                                            },
                                            value=3
                                        )
                                    ]
                                ),

                                # Time slider with auto-play
                                html.Div(
                                    children=[
                                        html.Label("Simulation Timeline Step", style={'fontSize': '12px', 'fontWeight': 'bold', 'color': '#94a3b8', 'display': 'block', 'marginBottom': '8px'}),
                                        dcc.Slider(
                                            id='time-slider',
                                            min=1,
                                            max=4,
                                            step=1,
                                            marks={
                                                1: {'label': 't1: Setup', 'style': {'color': '#94a3b8', 'fontSize': '10px'}},
                                                2: {'label': 't2: Operations', 'style': {'color': '#94a3b8', 'fontSize': '10px'}},
                                                3: {'label': 't3: Attack Pivot', 'style': {'color': '#ef4444', 'fontWeight': 'bold', 'fontSize': '10px'}},
                                                4: {'label': 't4: Exfiltration', 'style': {'color': '#ef4444', 'fontWeight': 'bold', 'fontSize': '10px'}}
                                            },
                                            value=4
                                        ),

                                        # Play / Pause Control Button
                                        html.Div(
                                            style={'marginTop': '25px', 'textAlign': 'center'},
                                            children=[
                                                html.Button(
                                                    "▶ Play Simulation",
                                                    id='play-button',
                                                    n_clicks=0,
                                                    className='play-btn paused'
                                                )
                                            ]
                                        )
                                    ]
                                )
                            ]
                        ),

                        # Security Log Terminal card
                        html.Div(
                            style={
                                'background': '#0f111a',
                                'border': '1px solid #1e293b',
                                'borderRadius': '12px',
                                'padding': '20px',
                                'flex': '1',
                                'display': 'flex',
                                'flexDirection': 'column',
                                'boxShadow': '0 10px 25px rgba(0, 0, 0, 0.4)'
                            },
                            children=[
                                html.H3("🚨 FORENSIC SECURITY CONSOLE", style={'margin': '0 0 15px 0', 'fontSize': '16px', 'color': '#38bdf8', 'borderBottom': '1px solid #1e293b', 'paddingBottom': '8px'}),
                                html.Div(
                                    id='log-panel',
                                    className='log-card',
                                    style={'flex': '1'}
                                )
                            ]
                        )
                    ]
                )
            ]
        )
    ]
)

# ==========================================
# 4. CALLBACKS FOR PLAYBACK AUTO-ADVANCE
# ==========================================
@app.callback(
    Output('play-interval', 'disabled'),
    Output('play-button', 'children'),
    Output('play-button', 'className'),
    Input('play-button', 'n_clicks'),
    State('play-interval', 'disabled')
)
def toggle_playback(n_clicks, is_disabled):
    if n_clicks == 0:
        return True, "▶ Play Simulation", "play-btn paused"

    if is_disabled:
        # Turn Play mode ON (disabled = False)
        return False, "⏸ Pause Simulation", "play-btn"
    else:
        # Turn Play mode OFF (disabled = True)
        return True, "▶ Play Simulation", "play-btn paused"

@app.callback(
    Output('time-slider', 'value'),
    Input('play-interval', 'n_intervals'),
    State('time-slider', 'value'),
    State('play-interval', 'disabled')
)
def auto_advance(n_intervals, current_value, is_disabled):
    if is_disabled:
        return current_value
    # Advance time step, looping back to 1
    next_value = current_value + 1
    if next_value > 4:
        next_value = 1
    return next_value

# ==========================================
# 5. DYNAMIC RENDERING CALLBACK
# ==========================================
@app.callback(
    Output('network-graph', 'figure'),
    Output('log-panel', 'children'),
    Output('alert-banner-container', 'children'),
    Input('scale-slider', 'value'),
    Input('time-slider', 'value')
)
def update_dashboard(scale_limit, time_limit):
    # 1. Filter active nodes based on scale level
    active_node_ids = {n['id'] for n in raw_nodes if n.get('scale_level', 1) <= scale_limit}

    # Identify compromised nodes dynamically based on active threat edges at this time limit
    compromised_nodes = set()
    for edge in raw_edges:
        if edge.get('is_threat') and edge.get('time_step', 1) <= time_limit:
            if edge['from'] in active_node_ids and edge['to'] in active_node_ids:
                compromised_nodes.add(edge['from'])
                compromised_nodes.add(edge['to'])

    # Traces configuration
    traces = []

    # 2. Add normal edges trace (muted slate gray)
    normal_edge_x = []
    normal_edge_y = []
    for edge in raw_edges:
        if edge['from'] in active_node_ids and edge['to'] in active_node_ids:
            if edge.get('scale_level', 1) <= scale_limit and edge.get('time_step', 1) <= time_limit:
                if not edge.get('is_threat'):
                    x0, y0 = pos[edge['from']]
                    x1, y1 = pos[edge['to']]
                    normal_edge_x.extend([x0, x1, None])
                    normal_edge_y.extend([y0, y1, None])

    traces.append(go.Scatter(
        x=normal_edge_x, y=normal_edge_y,
        line=dict(width=1.5, color='#1e293b'),
        hoverinfo='none',
        mode='lines',
        name='Normal Link'
    ))

    # 3. Add threat edges with a NEON GLOW effect
    threat_edge_glow_x = []
    threat_edge_glow_y = []
    threat_edge_x = []
    threat_edge_y = []

    for edge in raw_edges:
        if edge['from'] in active_node_ids and edge['to'] in active_node_ids:
            if edge.get('scale_level', 1) <= scale_limit and edge.get('time_step', 1) <= time_limit:
                if edge.get('is_threat'):
                    x0, y0 = pos[edge['from']]
                    x1, y1 = pos[edge['to']]
                    threat_edge_glow_x.extend([x0, x1, None])
                    threat_edge_glow_y.extend([y0, y1, None])
                    threat_edge_x.extend([x0, x1, None])
                    threat_edge_y.extend([y0, y1, None])

    if threat_edge_x:
        # Thick outer neon glow
        traces.append(go.Scatter(
            x=threat_edge_glow_x, y=threat_edge_glow_y,
            line=dict(width=8, color='rgba(239, 68, 68, 0.25)'),
            hoverinfo='none',
            mode='lines',
            showlegend=False
        ))
        # Thin sharp core line
        traces.append(go.Scatter(
            x=threat_edge_x, y=threat_edge_y,
            line=dict(width=3, color='#ef4444'),
            hoverinfo='none',
            mode='lines',
            name='🔥 Threat Path'
        ))

    # 4. Add compromised nodes HALO GLOW
    glow_node_x = []
    glow_node_y = []
    for node in raw_nodes:
        if node['id'] in active_node_ids and node['id'] in compromised_nodes:
            x, y = pos[node['id']]
            glow_node_x.append(x)
            glow_node_y.append(y)

    if glow_node_x:
        traces.append(go.Scatter(
            x=glow_node_x, y=glow_node_y,
            mode='markers',
            marker=dict(size=36, color='rgba(239, 68, 68, 0.25)'),
            hoverinfo='none',
            showlegend=False
        ))

    # 5. Group nodes and add configured scatter traces
    group_configs = {
        'threat': {'color': '#ef4444', 'symbol': 'triangle-up', 'size': 24, 'label': '🚨 Threat Origin'},
        'hardware': {'color': '#ffd166', 'symbol': 'square', 'size': 18, 'label': '🔌 Routing Switch'},
        'server': {'color': '#06d6a0', 'symbol': 'diamond', 'size': 20, 'label': '🖥️ Database/Server'},
        'subnet': {'color': '#4dadff', 'symbol': 'hexagon', 'size': 20, 'label': '🌐 Subnet Segment'},
        'endpoint': {'color': '#9ca3af', 'symbol': 'circle', 'size': 14, 'label': '💻 End Workstation'}
    }

    grouped_nodes = {grp: [] for grp in group_configs}
    for node in raw_nodes:
        if node['id'] in active_node_ids:
            grp = node.get('group', 'endpoint')
            if grp not in grouped_nodes:
                grp = 'endpoint'
            grouped_nodes[grp].append(node)

    for grp, nodes_in_group in grouped_nodes.items():
        if not nodes_in_group:
            continue

        cfg = group_configs[grp]
        nx_val = []
        ny_val = []
        labels = []
        hovers = []

        for n in nodes_in_group:
            x, y = pos[n['id']]
            nx_val.append(x)
            ny_val.append(y)
            labels.append(n['label'])

            status_text = "⚠️ COMPROMISED / INTRUDED" if n['id'] in compromised_nodes else "✅ OPERATIONAL / SECURE"
            hovers.append(
                f"<b>Node ID:</b> {n['id']}<br>"
                f"<b>Asset Label:</b> {n['label']}<br>"
                f"<b>Classification:</b> {grp.upper()}<br>"
                f"<b>Security Level:</b> {status_text}"
            )

        # Draw labels only for non-endpoints to prevent canvas text overlaps
        mode_val = 'markers+text' if grp != 'endpoint' else 'markers'

        traces.append(go.Scatter(
            x=nx_val, y=ny_val,
            mode=mode_val,
            text=labels if grp != 'endpoint' else None,
            textposition="top center",
            hoverinfo='text',
            hovertext=hovers,
            marker=dict(
                size=cfg['size'],
                color=cfg['color'],
                symbol=cfg['symbol'],
                line=dict(width=1.5, color='#ffffff' if grp == 'threat' else '#1e293b')
            ),
            textfont=dict(color='#f3f4f6', size=9, family="Space Grotesk"),
            name=cfg['label']
        ))

    # Dynamic Victim ID Resolution for dynamic text markers
    victim_1_id = None
    victim_2_id = None
    for edge in raw_edges:
        if edge.get('is_threat'):
            if edge['from'] == "Attacker":
                victim_1_id = edge['to']
            elif edge['to'] == "C2":
                victim_2_id = edge['from']

    # 6. Add dynamic visual markers / labels directly onto the canvas layout
    annotations = []

    if "Attacker" in active_node_ids and time_limit >= 3:
        ax, ay = pos.get("Attacker", (0, 0))
        annotations.append(dict(
            x=ax, y=ay, xref="x", yref="y",
            text="💥 BREACH ENTRY POINT",
            showarrow=True, arrowhead=2, arrowcolor="#ef4444", arrowsize=1.2,
            ax=0, ay=-45,
            font=dict(size=10, color="#ffffff", family="Space Grotesk"),
            bgcolor="#ef4444", bordercolor="#ffffff", borderwidth=1, borderpad=4
        ))

    if victim_1_id and victim_1_id in active_node_ids and time_limit >= 3:
        vx, vy = pos.get(victim_1_id, (0, 0))
        annotations.append(dict(
            x=vx, y=vy, xref="x", yref="y",
            text=f"⚠️ VULNERABLE RECON PIVOT: {victim_1_id}",
            showarrow=True, arrowhead=2, arrowcolor="#ffd166", arrowsize=1.2,
            ax=0, ay=45,
            font=dict(size=9, color="#ffffff", family="Space Grotesk"),
            bgcolor="#1e1b4b", bordercolor="#ffd166", borderwidth=1.5, borderpad=4
        ))

    if victim_2_id and victim_2_id in active_node_ids and time_limit >= 3:
        vx, vy = pos.get(victim_2_id, (0, 0))
        annotations.append(dict(
            x=vx, y=vy, xref="x", yref="y",
            text=f"🚨 EXPOSED HOST: {victim_2_id}",
            showarrow=True, arrowhead=2, arrowcolor="#ef4444", arrowsize=1.2,
            ax=50, ay=45,
            font=dict(size=9, color="#ffffff", family="Space Grotesk"),
            bgcolor="#31100f", bordercolor="#ef4444", borderwidth=1.5, borderpad=4
        ))

    if "C2" in active_node_ids and time_limit >= 4:
        cx, cy = pos.get("C2", (0, 0))
        annotations.append(dict(
            x=cx, y=cy, xref="x", yref="y",
            text="👿 COMMAND & CONTROL (C2 EXFIL)",
            showarrow=True, arrowhead=2, arrowcolor="#ef4444", arrowsize=1.2,
            ax=-50, ay=-45,
            font=dict(size=10, color="#ffffff", family="Space Grotesk"),
            bgcolor="#7f1d1d", bordercolor="#ffffff", borderwidth=1, borderpad=4
        ))

    fig = go.Figure(
        data=traces,
        layout=go.Layout(
            showlegend=True,
            hovermode='closest',
            margin=dict(b=0, l=0, r=0, t=0),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            legend=dict(
                font=dict(color='#94a3b8', size=11, family="Space Grotesk"),
                bgcolor='rgba(15, 17, 26, 0.85)',
                bordercolor='#1e293b',
                borderwidth=1,
                x=0.02, y=0.98,
                xanchor='left', yanchor='top'
            ),
            annotations=annotations
        )
    )

    # 7. Generate console logs
    log_messages = []
    current_time_str = datetime.now().strftime("%H:%M:%S")

    log_messages.append(
        html.Div([
            html.Span(f"[{current_time_str}] ", style={'color': '#64748b'}),
            html.Span("SYS_MONITOR: Active topological trace scan completed.", style={'color': '#38bdf8'})
        ], style={'marginBottom': '8px'})
    )

    has_threat = False

    # Trace active edge events for this specific timeline step
    for edge in raw_edges:
        if edge['from'] in active_node_ids and edge['to'] in active_node_ids:
            if edge.get('scale_level', 1) <= scale_limit and edge.get('time_step', 1) <= time_limit:
                if edge.get('time_step', 1) == time_limit:
                    is_threat = edge.get('is_threat')
                    if is_threat:
                        has_threat = True
                        log_messages.append(
                            html.Div([
                                html.Span(f"[{current_time_str}] ", style={'color': '#64748b'}),
                                html.Span("[CRITICAL ALARM] ", style={'color': '#ef4444', 'fontWeight': 'bold'}),
                                html.Span("Threat vector isolated from "),
                                html.Span(f"{edge['from']}", style={'color': '#fb7185', 'fontWeight': 'bold'}),
                                html.Span(" to "),
                                html.Span(f"{edge['to']}", style={'color': '#fb7185', 'fontWeight': 'bold'}),
                                html.Span(f" | Anomaly Weight (Z): {edge.get('z_score', 'N/A')}", style={'color': '#f43f5e'})
                            ], style={'marginBottom': '8px', 'background': 'rgba(239, 68, 68, 0.1)', 'padding': '5px 10px', 'borderRadius': '6px', 'borderLeft': '3px solid #ef4444'})
                        )
                    else:
                        log_messages.append(
                            html.Div([
                                html.Span(f"[{current_time_str}] ", style={'color': '#64748b'}),
                                html.Span("[INFO] ", style={'color': '#10b981'}),
                                html.Span(f"Operational session packet: {edge['from']} -> {edge['to']}")
                            ], style={'marginBottom': '6px'})
                        )

    # Contextual alerts inserted at the top of the logs
    if time_limit == 3 and has_threat:
        log_messages.insert(1,
            html.Div([
                html.Span(f"[{current_time_str}] ", style={'color': '#64748b'}),
                html.Span("[EXPLOIT IDENTIFIED] ", style={'color': '#f59e0b', 'fontWeight': 'bold'}),
                html.Span("External exploit payload successfully executed boundary vulnerability pivot.", style={'color': '#ffd166'})
            ], style={'marginBottom': '8px', 'background': 'rgba(245, 158, 11, 0.1)', 'padding': '5px 10px', 'borderRadius': '6px', 'borderLeft': '3px solid #f59e0b'})
        )
    elif time_limit == 4 and has_threat:
        log_messages.insert(1,
            html.Div([
                html.Span(f"[{current_time_str}] ", style={'color': '#64748b'}),
                html.Span("[TUNNEL ESTABLISHED] ", style={'color': '#ef4444', 'fontWeight': 'bold'}),
                html.Span("Unmapped TCP session socket exfiltrating target database payloads.", style={'color': '#fb7185'})
            ], style={'marginBottom': '8px', 'background': 'rgba(239, 68, 68, 0.15)', 'padding': '5px 10px', 'borderRadius': '6px', 'borderLeft': '3px solid #ef4444'})
        )

    # 8. Render full-width banner alerting details
    if time_limit == 1:
        banner = html.Div(
            className='alert-banner-secure',
            children=[
                html.Span("🔒 SYSTEM STATUS: OPERATIONAL & SECURE", style={'fontWeight': 'bold', 'fontSize': '16px'}),
                html.Span(" | Phase: Topology Initialization (t1). Baseline router-to-interface networks establishing sessions.", style={'fontSize': '13px', 'marginLeft': '10px'})
            ]
        )
    elif time_limit == 2:
        banner = html.Div(
            className='alert-banner-secure',
            children=[
                html.Span("🔒 SYSTEM STATUS: OPERATIONAL & SECURE", style={'fontWeight': 'bold', 'fontSize': '16px'}),
                html.Span(" | Phase: Standard Business Activity (t2). Active network polling and system replication streams checked.", style={'fontSize': '13px', 'marginLeft': '10px'})
            ]
        )
    elif time_limit == 3:
        banner = html.Div(
            className='alert-banner-active',
            children=[
                html.Span("🚨 SYSTEM BREACH DETECTED: INTRUSION ACTIVE", style={'fontWeight': 'bold', 'fontSize': '16px', 'textShadow': '0 0 8px rgba(255,255,255,0.4)'}),
                html.Span(" | Alert: Boundary interfaces exploited by unmapped IP node. Lateral pivot to local hardware routing detected!", style={'fontSize': '13px', 'marginLeft': '10px', 'color': '#fee2e2'})
            ]
        )
    else:  # time_limit == 4
        banner = html.Div(
            className='alert-banner-active',
            style={'background': 'rgba(220, 38, 38, 0.55)', 'borderColor': '#dc2626', 'boxShadow': '0 0 35px rgba(220, 38, 38, 0.8)'},
            children=[
                html.Span("💥 CRITICAL INCIDENT: NETWORK DATA EXFILTRATION", style={'fontWeight': 'bold', 'fontSize': '16px', 'textShadow': '0 0 10px rgba(255,255,255,0.5)'}),
                html.Span(" | Danger: System credentials compromised. Raw exfiltration stream established to external command server!", style={'fontSize': '13px', 'marginLeft': '10px', 'color': '#fee2e2'})
            ]
        )

    return fig, log_messages, banner

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8050))
    print(f"[*] Starting STORM-TKG Interactive Security Dashboard on port {port}...")
    app.run(debug=False, use_reloader=False, port=port)
