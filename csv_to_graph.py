"""
mass_topology_generator.py
---------------------------
Advanced large-scale dataset engine. Generates up to 10,000 normalized,
multi-column infrastructure telemetry records for network performance and
cybersecurity threat profiling.
"""

import csv
import os
import random
import time
from datetime import datetime, timedelta

# Target Configuration
OUTPUT_FILE = "enterprise_network_topology_10k.csv"
ROW_LIMIT = 10000

# Procedural Matrix Foundations
LOCATIONS = [
    "Iceland (Reykjavik-HQ)", "Ireland (Dublin-East)", "Germany (Frankfurt-Central)",
    "US (Virginia-East)", "Singapore (South-Asia)", "Japan (Tokyo-North)"
]

ROUTER_TYPES = ["Core_Backbone", "Edge_Aggregation", "Distribution_Layer", "Border_Gateway"]

def generate_bulk_topology(filename, total_rows):
    """
    Streams structurally sound network data rows directly to disk,
    bypassing high memory overhead arrays.
    """
    print("=" * 80)
    print(f"INITIALIZING MASS DATA ENGINERING PIPELINE: TARGETING {total_rows} ROWS")
    print("=" * 80)

    start_time = time.time()

    # Define the 9-column comprehensive schema
    headers = [
        'datacenter_location', 'router_name', 'interface_ip',
        'link_type', 'latency_ms', 'bandwidth_gbps',
        'vulnerability_score', 'node_status', 'last_security_scan'
    ]

    # Pre-generate unique router identifiers to simulate real, recurring hardware entities
    router_pool = []
    for loc in LOCATIONS:
        short_loc = loc.split(" ")[0].upper()
        for r_type in ROUTER_TYPES:
            for i in range(1, 6): # 5 routers per type per location
                router_pool.append({
                    "location": loc,
                    "name": f"{short_loc}_{r_type}_{i:02d}"
                })

    print(f"[INFO] Initialized virtual hardware map with {len(router_pool)} unique core routing nodes.")
    print("Streaming records to CSV layout layer...")

    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=headers)
            writer.writeheader()

            for current_row in range(1, total_rows + 1):
                # Bind relationship context to a specific router entity from the pool
                selected_router = random.choice(router_pool)

                # Generate unique, structured Class A/B private subnet IPs
                # E.g., 10.124.45.13 or 172.16.89.244
                if random.choice([True, False]):
                    ip_address = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                else:
                    ip_address = f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

                # Context-aware telemetry logic based on router classification
                r_name = selected_router["name"]
                if "Core_Backbone" in r_name:
                    bandwidth = random.choice([100, 200, 400]) # Modern ultra-fast backbone ports
                    latency = random.randint(1, 8)               # Low latency paths
                    link_type = "Backbone Trunk"
                elif "Border_Gateway" in r_name:
                    bandwidth = random.choice([40, 100])
                    latency = random.randint(12, 35)
                    link_type = "Inter-DC Transit"
                else:
                    bandwidth = random.choice([10, 40])
                    latency = random.randint(5, 22)
                    link_type = "Edge Distribution"

                # Cybersecurity evaluation vector (Deterministic anomalies)
                # Intentionally insert clusters of high risk to simulate real target zones
                if current_row % 13 == 0: # 13th row anomaly distribution pattern
                    vuln_score = round(random.uniform(0.71, 0.99), 2)
                    status = "Critical Exposure"
                elif current_row % 29 == 0:
                    vuln_score = round(random.uniform(0.55, 0.70), 2)
                    status = "Mitigation Required"
                else:
                    vuln_score = round(random.uniform(0.01, 0.45), 2)
                    status = "Operational / Patch Compliant"

                # Historical monitoring window (Spread over the prior 7 days)
                days_delta = random.randint(0, 7)
                hours_delta = random.randint(0, 23)
                minutes_delta = random.randint(0, 59)
                scan_timestamp = (datetime.utcnow() - timedelta(days=days_delta, hours=hours_delta, minutes=minutes_delta)).strftime('%Y-%m-%dT%H:%M:%SZ')

                # Compile unified flat row mapping
                writer.writerow({
                    'datacenter_location': selected_router["location"],
                    'router_name': r_name,
                    'interface_ip': ip_address,
                    'link_type': link_type,
                    'latency_ms': latency,
                    'bandwidth_gbps': bandwidth,
                    'vulnerability_score': vuln_score,
                    'node_status': status,
                    'last_security_scan': scan_timestamp
                })

                # Visual console progress increments
                if current_row % 2500 == 0:
                    print(f" -> Synchronization Progress: Checked & committed {current_row} records...")

        execution_duration = round(time.time() - start_time, 3)
        file_bytes = os.path.getsize(filename)
        file_megabytes = round(file_bytes / (1024 * 1024), 2)

        print("\n" + "=" * 80)
        print("[SUCCESS] PIPELINE PROCESSING COMPLETED SUCCESSFULLY")
        print("=" * 80)
        print(f"Total Database Rows Generated : {total_rows}")
        print(f"Target Export Path            : {os.path.abspath(filename)}")
        print(f"Resulting File Footprint      : {file_megabytes} MB")
        print(f"Processing Pipeline Clock Time: {execution_duration} seconds")
        print("=" * 80)

    except IOError as io_err:
        print(f"[CRITICAL FAILURE] Disk write execution halted: {io_err}")


if __name__ == "__main__":
    generate_bulk_topology(OUTPUT_FILE, ROW_LIMIT)
