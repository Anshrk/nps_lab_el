"""
tkg_interactive_dashboard.py
----------------------------
Advanced Python Graph Compiler. Generates a standalone, interactive HTML dashboard
for visualizing Temporal Knowledge Graphs (TKG) and Zero-Day anomaly detection.
Features dual-mode ingestion: Live Neo4j integration with a procedural fallback.
"""

import json
import os
import sys
from neo4j import GraphDatabase, basic_auth

# ==========================================
# DATABASE CONFIGURATION
# ==========================================
# IMPORTANT: Replace these with your actual credentials before running.
# ==========================================
# DATABASE CONFIGURATION
# ==========================================
NEO4J_URI = "bolt://3.236.156.185:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "projectiles-fantails-electrodes"

def run_specific_report(driver):
    """Runs the exact Cypher query requested for the Iceland Data Centers."""
    print("[*] Running Custom Iceland Data Center Report...")
    cypher_query = '''
    MATCH (dc:DataCenter {location: $location})-[:CONTAINS]->(r:Router)-[:ROUTES]->(i:Interface)
    RETURN i.ip as ip
    '''
    try:
        with driver.session(database="neo4j") as session:
            # CHANGED: read_transaction is now execute_read in Neo4j driver v5+
            results = session.execute_read(
                lambda tx: tx.run(cypher_query, location="Iceland").data()
            )
            print(f"    Found {len(results)} interfaces routing through Iceland:")
            for record in results:
                print(f"    -> IP: {record['ip']}")
    except Exception as e:
        print(f"[!] Warning: Custom report failed. Check database schema. Error: {e}")
def fetch_graph_data_from_neo4j(driver):
    """
    Extracts the graph structure from Neo4j and formats it for the Vis.js dashboard.
    Maps Neo4j labels to dashboard groups, and handles missing temporal/scale properties.
    """
    print("[*] Fetching network topology from Neo4j...")
    nodes_dict = {}
    edges = []

    # Generic query to pull relationships. Adjust LIMIT based on database size.
    graph_query = '''
    MATCH (n)-[r]->(m)
    RETURN n, r, m LIMIT 300
    '''

    with driver.session() as session:
        results = session.run(graph_query)

        edge_id_counter = 1
        for record in results:
            n = record["n"]
            m = record["m"]
            r = record["r"]

            # --- Parse Source Node ---
            if n.element_id not in nodes_dict:
                # Use the first label as the group, default to 'endpoint'
                group = list(n.labels)[0].lower() if n.labels else "endpoint"
                nodes_dict[n.element_id] = {
                    "id": n.element_id,
                    "label": n.get("name", n.get("ip", str(n.element_id))),
                    "group": group,
                    "scale_level": n.get("scale_level", 1) # Default to 1 if missing
                }

            # --- Parse Target Node ---
            if m.element_id not in nodes_dict:
                group = list(m.labels)[0].lower() if m.labels else "endpoint"
                nodes_dict[m.element_id] = {
                    "id": m.element_id,
                    "label": m.get("name", m.get("ip", str(m.element_id))),
                    "group": group,
                    "scale_level": m.get("scale_level", 1)
                }

            # --- Parse Edge ---
            is_threat = r.get("is_threat", False)
            color = "#ff2a55" if is_threat else "#3a4b5c"

            edges.append({
                "id": edge_id_counter,
                "from": n.element_id,
                "to": m.element_id,
                "title": f"Relation: {r.type}<br>Z-Score: {r.get('z_score', '0.0')}",
                "time_step": r.get("time_step", 1), # Default to 1 if missing
                "scale_level": r.get("scale_level", 1),
                "color": {"color": color, "highlight": color},
                "width": 4 if is_threat else 1,
                "is_threat": is_threat,
                "z_score": r.get("z_score", "0.0"),
                "arrows": "to"
            })
            edge_id_counter += 1

    return list(nodes_dict.values()), edges

def generate_procedural_fallback():
    """Fallback generator if Neo4j is unreachable."""
    print("[!] Proceeding with Procedural Fallback Generation...")
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
            "width": width, "is_threat": is_threat, "z_score": z_score,
            "arrows": "to"
        })
        edge_id_counter += 1

    # --- Procedural Data (Unchanged from original) ---
    add_node("Ext_Attacker", "External IP", "threat", 1)
    add_node("Web_01", "Web Server 01", "server", 1)
    add_node("Switch_Core", "Core Switch", "hardware", 1)
    add_node("DB_Active", "Primary DB", "server", 1)
    add_node("Ext_C2", "Command & Control", "threat", 1)
    add_edge("Ext_Attacker", "Web_01", "EXPLOITS_VULN", 3, 1, is_threat=True, z_score="99.9")
    add_edge("Web_01", "Switch_Core", "PIVOTS", 3, 1, is_threat=True, z_score="14.5")
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
            .db-status {{ font-size: 12px; color: #3fb950; text-align: center; margin-top: auto; padding-top: 10px; border-top: 1px solid #30363d; }}
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
            <div class="slider-ticks"><span>t1</span><span>t2</span><span>t3</span><span>t4</span></div>
        </div>

        <h2>Live Security Log</h2>
        <div id="log-panel"></div>

        <div class="db-status">&#9679; Data Engine Active ({len(nodes)} Nodes)</div>
    </div>

    <div id="network-canvas"></div>

    <script type="text/javascript">
        const rawNodes = {json.dumps(nodes)};
        const rawEdges = {json.dumps(edges)};

        const nodesData = new vis.DataSet(rawNodes);
        const edgesData = new vis.DataSet(rawEdges);

        const container = document.getElementById('network-canvas');
        const data = {{ nodes: nodesData, edges: edgesData }};
        const options = {{
            nodes: {{ font: {{ color: '#ffffff' }}, borderWidth: 2 }},
            groups: {{
                threat: {{ shape: 'triangle', color: '#ff4444', size: 30 }},
                hardware: {{ shape: 'square', color: '#ffd166', size: 20 }},
                server: {{ shape: 'database', color: '#06d6a0', size: 25 }},
                subnet: {{ shape: 'hexagon', color: '#4dadff', size: 25 }},
                endpoint: {{ shape: 'dot', color: '#8b949e', size: 12 }},
                default: {{ shape: 'dot', color: '#a0a0a0', size: 15 }}
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

            const nodesToUpdate = rawNodes.map(node => ({{
                id: node.id,
                hidden: (node.scale_level || 1) > currentScale
            }}));
            nodesData.update(nodesToUpdate);

            let activeLogs = "";
            const edgesToUpdate = rawEdges.map(edge => {{
                const isHidden = ((edge.scale_level || 1) > currentScale) || ((edge.time_step || 1) > currentTime);

                if (!isHidden && (edge.time_step || 1) === currentTime) {{
                    if (edge.is_threat) {{
                        activeLogs += `<div class="log-entry log-alert">[CRITICAL] Anomaly!<br>Z-Score: ${{edge.z_score}}<br>${{edge.from}} &rarr; ${{edge.to}}</div>`;
                    }} else {{
                        activeLogs += `<div class="log-entry log-safe">[OK] Standard Route<br>${{edge.from}} &rarr; ${{edge.to}}</div>`;
                    }}
                }}
                return {{ id: edge.id, hidden: isHidden }};
            }});
            edgesData.update(edgesToUpdate);

            logPanel.innerHTML = `<strong>Current Time Step: t${{currentTime}}</strong><br><br>` + activeLogs;
        }}

        updateGraph();
    </script>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html_template)
    print(f"\n================================================================")
    print(f"[SUCCESS] Standalone Interactive Dashboard Generated!")
    print(f"File Path: {os.path.abspath(filename)}")
    print(f"================================================================")

if __name__ == "__main__":
    print("================================================================")
    print("   Temporal Graph Knowledge (TKG) Compiler                      ")
    print("================================================================")

    nodes, edges = [], []

    try:
        print(f"[*] Attempting to connect to Neo4j at {NEO4J_URI}...")
        driver = GraphDatabase.driver(NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASS))

        # Verify connection
        driver.verify_connectivity()
        print("[+] Connection Successful!")

        # 1. Run the specific custom report
        run_specific_report(driver)

        # 2. Fetch the graph topology for the UI
        nodes, edges = fetch_graph_data_from_neo4j(driver)
        driver.close()

    except Exception as e:
        print(f"[-] Neo4j connection failed: {e}")
        # Graceful fallback ensures you still get a dashboard for your project
        nodes, edges = generate_procedural_fallback()

    # Build the final output regardless of source
    build_html_dashboard(nodes, edges)
