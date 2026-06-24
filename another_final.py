"""
tkg_interactive_dashboard.py
----------------------------
Advanced Python Graph Compiler. Generates a standalone, interactive HTML dashboard 
for visualizing Temporal Knowledge Graphs (TKG) and Zero-Day anomaly detection 
across multiple network scales and time steps.
"""

import json
import os
import random
from datetime import datetime, timezone

def generate_graph_data():
    """
    Procedurally generates the graph topology. 
    Tags every node and edge with a 'scale_level' and 'time_step' 
    so the Javascript frontend can filter them dynamically.
    """
    nodes = []
    edges = []
    edge_id_counter = 1

    def add_node(n_id, label, group, scale):
        nodes.append({"id": n_id, "label": label, "group": group, "scale_level": scale})

    def add_edge(src, dst, rel, t_step, scale, is_threat=False, z_score="0.0"):
        nonlocal edge_id_counter
        color = "#ff2a55" if is_threat else "#3a4b5c"
        width = 4 if is_threat else 1
        edges.append({
            "id": edge_id_counter, "from": src, "to": dst, 
            "title": f"Relation: {rel}<br>Z-Score: {z_score}", 
            "time_step": t_step, "scale_level": scale,
            "color": {"color": color, "highlight": color}, 
            "width": width, "is_threat": is_threat,
            "arrows": "to"
        })
        edge_id_counter += 1

    # ==========================================
    # NODE DEFINITIONS (By Scale Level)
    # ==========================================
    # Scale 1: Low (Core Infrastructure)
    add_node("Ext_Attacker", "External IP", "threat", 1)
    add_node("Web_01", "Web Server 01", "server", 1)
    add_node("Switch_Core", "Core Switch", "hardware", 1)
    add_node("DB_Active", "Primary DB", "server", 1)
    add_node("Ext_C2", "Command & Control", "threat", 1)
    add_node("Subnet_Alpha", "Subnet Alpha", "subnet", 1)

    # Scale 2: Medium (Adding Redundancy and Endpoints)
    add_node("Web_02", "Web Server 02", "server", 2)
    add_node("Switch_Edge", "Edge Switch", "hardware", 2)
    add_node("DB_Replica", "Replica DB", "server", 2)
    add_node("Subnet_Beta", "Subnet Beta", "subnet", 2)
    for i in range(1, 6):
        add_node(f"Host_A_{i}", f"Host 10.0.1.{i}", "endpoint", 2)

    # Scale 3: High (Enterprise Noise)
    add_node("Switch_DMZ", "DMZ Gateway", "hardware", 3)
    add_node("Subnet_Gamma", "Subnet Gamma", "subnet", 3)
    add_node("Subnet_Delta", "Subnet Delta", "subnet", 3)
    for i in range(1, 16):
        add_node(f"Host_B_{i}", f"Host 172.16.{i}.10", "endpoint", 3)

    # ==========================================
    # EDGE DEFINITIONS (By Time Step)
    # ==========================================
    # TIME STEP 1: Baseline Initialization
    add_edge("Subnet_Alpha", "Switch_Core", "ROUTES_TO", 1, 1)
    add_edge("Subnet_Beta", "Switch_Edge", "ROUTES_TO", 1, 2)
    add_edge("Subnet_Gamma", "Switch_DMZ", "ROUTES_TO", 1, 3)
    add_edge("Subnet_Delta", "Switch_DMZ", "ROUTES_TO", 1, 3)

    # TIME STEP 2: Normal Operations (The "Noise")
    add_edge("Switch_Core", "Web_01", "POLLS_STATUS", 2, 1)
    add_edge("Web_01", "DB_Active", "QUERIES_DATA", 2, 1)
    add_edge("Switch_Edge", "Switch_Core", "UPLINK", 2, 2)
    add_edge("DB_Active", "DB_Replica", "REPLICATES", 2, 2)
    add_edge("Switch_DMZ", "Web_02", "FORWARDS", 2, 3)
    for i in range(1, 6):
        add_edge(f"Host_A_{i}", "Switch_Edge", "SENDS_PACKET", 2, 2)
    for i in range(1, 16):
        add_edge(f"Host_B_{i}", "Switch_DMZ", "SENDS_PACKET", 2, 3)

    # TIME STEP 3: Zero-Day Attack Ingress (Anomaly Detected)
    add_edge("Ext_Attacker", "Web_01", "EXPLOITS_VULN", 3, 1, is_threat=True, z_score="99.9")
    add_edge("Web_01", "Switch_Core", "PIVOTS", 3, 1, is_threat=True, z_score="14.5")

    # TIME STEP 4: Exploit Chain Completion
    add_edge("Switch_Core", "DB_Active", "MALICIOUS_FIRMWARE", 4, 1, is_threat=True, z_score="22.1")
    add_edge("DB_Active", "Ext_C2", "EXFILTRATES_DATA", 4, 1, is_threat=True, z_score="99.9")

    return nodes, edges

def build_html_dashboard(nodes, edges, filename="tkg_zero_day_dashboard.html"):
    """Compiles the JSON data into a standalone HTML/JS application."""
    
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>TKG Zero-Day Threat Analytics</title>
        <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
        <style>
            body {{ margin: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0c0e12; color: #fff; display: flex; height: 100vh; overflow: hidden; }}
            #sidebar {{ width: 350px; background-color: #161a22; padding: 20px; border-right: 1px solid #30363d; display: flex; flex-direction: column; }}
            #network-canvas {{ flex-grow: 1; height: 100%; }}
            h2 {{ font-size: 18px; border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-top: 0; color: #58a6ff; }}
            .control-group {{ margin-bottom: 25px; }}
            label {{ display: block; margin-bottom: 8px; font-size: 14px; font-weight: bold; }}
            input[type=range] {{ width: 100%; cursor: pointer; }}
            .slider-ticks {{ display: flex; justify-content: space-between; font-size: 12px; color: #8b949e; padding-top: 5px; }}
            #log-panel {{ background-color: #000; flex-grow: 1; border-radius: 5px; padding: 10px; font-family: 'Courier New', Courier, monospace; font-size: 12px; overflow-y: auto; border: 1px solid #30363d; }}
            .log-entry {{ margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px dashed #333; }}
            .log-alert {{ color: #ff4444; font-weight: bold; }}
            .log-safe {{ color: #3fb950; }}
        </style>
    </head>
    <body>

    <div id="sidebar">
        <h2>Threat Detection Controls</h2>
        
        <div class="control-group">
            <label>Network Scale (Data Volume Noise)</label>
            <input type="range" id="scaleSlider" min="1" max="3" value="3" oninput="updateGraph()">
            <div class="slider-ticks"><span>Low</span><span>Medium</span><span>High</span></div>
        </div>

        <div class="control-group">
            <label>Temporal Timeline (Time Step)</label>
            <input type="range" id="timeSlider" min="1" max="4" value="4" oninput="updateGraph()">
            <div class="slider-ticks"><span>t1: Init</span><span>t2: Ops</span><span>t3: Breach</span><span>t4: Exfil</span></div>
        </div>

        <h2>Live Security Log</h2>
        <div id="log-panel"></div>
    </div>

    <div id="network-canvas"></div>

    <script type="text/javascript">
        // Data Injected from Python
        const rawNodes = {json.dumps(nodes)};
        const rawEdges = {json.dumps(edges)};
        
        // Initialize Vis.js Datasets
        const nodesData = new vis.DataSet(rawNodes);
        const edgesData = new vis.DataSet(rawEdges);

        const container = document.getElementById('network-canvas');
        const data = {{ nodes: nodesData, edges: edgesData }};
        const options = {{
            nodes: {{
                font: {{ color: '#ffffff' }},
                borderWidth: 2
            }},
            groups: {{
                threat: {{ shape: 'triangle', color: '#ff4444', size: 30 }},
                hardware: {{ shape: 'square', color: '#ffd166', size: 20 }},
                server: {{ shape: 'database', color: '#06d6a0', size: 25 }},
                subnet: {{ shape: 'hexagon', color: '#4dadff', size: 25 }},
                endpoint: {{ shape: 'dot', color: '#8b949e', size: 12 }}
            }},
            physics: {{
                forceAtlas2Based: {{ gravitationalConstant: -150, centralGravity: 0.02, springLength: 100 }},
                solver: 'forceAtlas2Based'
            }}
        }};

        const network = new vis.Network(container, data, options);

        function updateGraph() {{
            const currentScale = parseInt(document.getElementById('scaleSlider').value);
            const currentTime = parseInt(document.getElementById('timeSlider').value);
            const logPanel = document.getElementById('log-panel');
            
            // 1. Filter Nodes based on Scale
            const nodesToUpdate = rawNodes.map(node => ({{
                id: node.id,
                hidden: node.scale_level > currentScale
            }}));
            nodesData.update(nodesToUpdate);

            // 2. Filter Edges based on Scale AND Time Step
            let activeLogs = "";
            const edgesToUpdate = rawEdges.map(edge => {{
                const isHidden = (edge.scale_level > currentScale) || (edge.time_step > currentTime);
                
                // Update the security log if the edge is visible
                if (!isHidden && edge.time_step === currentTime) {{
                    if (edge.is_threat) {{
                        activeLogs += `<div class="log-entry log-alert">[CRITICAL] Temporal Anomaly!<br>Velocity Z-Score: ${{edge.z_score}}<br>${{edge.from}} &rarr; ${{edge.to}}</div>`;
                    }} else {{
                        activeLogs += `<div class="log-entry log-safe">[OK] Baseline Op<br>${{edge.from}} &rarr; ${{edge.to}}</div>`;
                    }}
                }}
                
                return {{ id: edge.id, hidden: isHidden }};
            }});
            edgesData.update(edgesToUpdate);
            
            // Generate contextual log headers
            let timeContext = "t1: Baseline Topology Initialization";
            if (currentTime === 2) timeContext = "t2: Normal Network Operations (Baseline Locked)";
            if (currentTime === 3) timeContext = "t3: ALARM - Structural Velocity Spike Detected";
            if (currentTime === 4) timeContext = "t4: ALARM - Lateral Movement & Exfiltration";
            
            logPanel.innerHTML = `<strong>Current State: ${{timeContext}}</strong><br><br>` + activeLogs;
        }}

        // Initialize state on load
        updateGraph();
    </script>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html_template)
    print(f"================================================================")
    print(f"[SUCCESS] Standalone Interactive Dashboard Generated!")
    print(f"File Path: {os.path.abspath(filename)}")
    print(f"================================================================")

if __name__ == "__main__":
    n, e = generate_graph_data()
    build_html_dashboard(n, e)
