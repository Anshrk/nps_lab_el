"""
generate_synthetic_netflow.py
-----------------------------------
Generates a massive, randomized NetFlow dataset for training
Temporal Graph Autoencoders. Simulates baseline enterprise traffic 
and injects Zero-Day structural anomalies.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

def generate_dataset(num_rows=100000, anomaly_ratio=0.02, output_file="synthetic_netflow_data.csv"):
    print(f"[*] Initializing Synthetic Data Generator...")
    print(f"[*] Target Rows: {num_rows} | Anomaly Ratio: {anomaly_ratio*100}%")

    # ==========================================
    # 1. DEFINE THE NETWORK TOPOLOGY POOLS
    # ==========================================
    # Normal internal subnets
    web_servers = [f"10.1.1.{i}" for i in range(10, 30)]
    db_servers = [f"10.3.8.{i}" for i in range(10, 20)]
    endpoints = [f"192.168.100.{i}" for i in range(2, 200)]
    
    # External IP pool (for simulated normal web traffic and attacks)
    external_ips = [f"{random.randint(8, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(500)]

    # Standard ports
    normal_ports = [80, 443, 53, 3389, 1433]

    # ==========================================
    # 2. GENERATE BASELINE DATA (Normal Traffic)
    # ==========================================
    num_normal = int(num_rows * (1 - anomaly_ratio))
    
    print("[*] Generating baseline temporal patterns...")
    # Generate timestamps spread over 30 days
    start_time = datetime.now() - timedelta(days=30)
    timestamps = [start_time + timedelta(minutes=random.randint(1, 43200)) for _ in range(num_normal)]
    
    # Baseline Routing (Endpoints -> Web, Web -> DB, External -> Web)
    src_ips = np.random.choice(endpoints + external_ips, num_normal)
    dst_ips = np.random.choice(web_servers + db_servers, num_normal)
    ports = np.random.choice(normal_ports, num_normal)

    # Baseline Behavior (Standard steady math)
    duration = np.random.uniform(0.1, 120.0, num_normal)
    bytes_sent = np.random.normal(5000, 1000, num_normal).clip(min=100)
    bytes_recv = np.random.normal(20000, 5000, num_normal).clip(min=100)
    pkts_sent = (bytes_sent / 1500).astype(int) + 1
    pkts_recv = (bytes_recv / 1500).astype(int) + 1

    normal_df = pd.DataFrame({
        'timestamp': timestamps,
        'src_ip': src_ips,
        'dst_ip': dst_ips,
        'dst_port': ports,
        'duration': duration,
        'bytes_sent': bytes_sent,
        'bytes_recv': bytes_recv,
        'packets_sent': pkts_sent,
        'packets_recv': pkts_recv,
        'is_threat': 0
    })

    # ==========================================
    # 3. GENERATE ZERO-DAY ANOMALIES (The Threats)
    # ==========================================
    num_anomalies = num_rows - num_normal
    
    print("[*] Injecting Zero-Day structural anomalies...")
    anomaly_timestamps = [start_time + timedelta(minutes=random.randint(1, 43200)) for _ in range(num_anomalies)]
    
    # Anomalous Routing (External directly hitting DBs, Endpoints port scanning)
    anom_src_ips = np.random.choice(external_ips + endpoints, num_anomalies)
    anom_dst_ips = np.random.choice(db_servers, num_anomalies) # Direct DB hits
    anom_ports = np.random.choice([4444, 9999, 1337, 22], num_anomalies) # Weird ports

    # Anomalous Behavior (Massive data exfiltration or rapid micro-connections)
    anom_duration = np.random.uniform(0.01, 2.0, num_anomalies) # Extremely fast
    anom_bytes_sent = np.random.normal(500, 50, num_anomalies).clip(min=10) # Tiny payload in
    anom_bytes_recv = np.random.normal(5000000, 1000000, num_anomalies) # MASSIVE payload out (Exfil)
    anom_pkts_sent = (anom_bytes_sent / 1500).astype(int) + 1
    anom_pkts_recv = (anom_bytes_recv / 1500).astype(int) + 1

    anomaly_df = pd.DataFrame({
        'timestamp': anomaly_timestamps,
        'src_ip': anom_src_ips,
        'dst_ip': anom_dst_ips,
        'dst_port': anom_ports,
        'duration': anom_duration,
        'bytes_sent': anom_bytes_sent,
        'bytes_recv': anom_bytes_recv,
        'packets_sent': anom_pkts_sent,
        'packets_recv': anom_pkts_recv,
        'is_threat': 1
    })

    # ==========================================
    # 4. MERGE, SORT, AND EXPORT
    # ==========================================
    print("[*] Compiling and shuffling dataset...")
    final_df = pd.concat([normal_df, anomaly_df], ignore_index=True)
    
    # Sort chronologically to simulate a real log file
    final_df = final_df.sort_values(by='timestamp').reset_index(drop=True)
    
    # Round numerical columns for cleanliness
    final_df['duration'] = final_df['duration'].round(3)
    final_df['bytes_sent'] = final_df['bytes_sent'].astype(int)
    final_df['bytes_recv'] = final_df['bytes_recv'].astype(int)

    # Save to CSV
    final_df.to_csv(output_file, index=False)
    print(f"[SUCCESS] Dataset generated and saved to: {output_file}")
    print(f"          Total Rows: {len(final_df)} | Threats Injected: {num_anomalies}")

if __name__ == "__main__":
    # You can change 100000 to 1,000,000 for a massive dataset
    generate_dataset(num_rows=100000, anomaly_ratio=0.01)
