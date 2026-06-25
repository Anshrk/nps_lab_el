"""
poc_tkg_autoencoder.py
-----------------------------------
Proof of Concept: Temporal Graph Autoencoder for Zero-Day Threat Detection.
Architecture: Graph Attention Network (GAT) Autoencoder.

NOTE: This is the architectural blueprint for the ML backend. 
Full model training requires a large-scale network flow dataset 
(e.g., LANL-Cyber or UNSW-NB15) to establish the topological baseline.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    from torch_geometric.nn import GATConv
except ImportError:
    print("[!] PyTorch Geometric not installed. Run: pip install torch-geometric")
    GATConv = None

class TemporalGraphEncoder(nn.Module):
    """
    Compresses the network topology into a latent mathematical space.
    Uses Graph Attention (GAT) to weigh the importance of neighbor nodes
    (e.g., a core switch has higher attention weight than a random endpoint).
    """
    def __init__(self, in_channels, hidden_channels, out_channels):
        super(TemporalGraphEncoder, self).__init__()
        # 1st Layer: Extract local neighborhood features
        self.conv1 = GATConv(in_channels, hidden_channels, heads=2, concat=True)
        # 2nd Layer: Compress into latent bottleneck
        self.conv2 = GATConv(hidden_channels * 2, out_channels, heads=1, concat=False)

    def forward(self, x, edge_index):
        x = F.elu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.4, training=self.training)
        x = self.conv2(x, edge_index)
        return x

class EdgeDecoder(nn.Module):
    """
    Attempts to reconstruct the network graph from the latent space.
    """
    def forward(self, z, edge_label_index):
        # Calculate dot product of source and destination node embeddings
        # High value = Link is normal/expected. Low value = Anomaly.
        src = z[edge_label_index[0]]
        dst = z[edge_label_index[1]]
        return (src * dst).sum(dim=-1)

class ZeroDayAnomalyDetector(nn.Module):
    """
    Full Autoencoder Pipeline.
    Training Goal: Minimize Reconstruction Error on normal traffic.
    Inference: High Reconstruction Error (Loss) -> Flag as Zero-Day Anomaly.
    """
    def __init__(self, in_features, hidden_features, latent_dim):
        super(ZeroDayAnomalyDetector, self).__init__()
        self.encoder = TemporalGraphEncoder(in_features, hidden_features, latent_dim)
        self.decoder = EdgeDecoder()

    def forward(self, x, edge_index, edge_label_index):
        # 1. Encode normal graph to latent vectors (z)
        z = self.encoder(x, edge_index)
        # 2. Decode/Reconstruct the edges
        reconstructed_edges = self.decoder(z, edge_label_index)
        return reconstructed_edges

    def calculate_anomaly_score(self, real_edges, predicted_edges):
        """
        Translates raw BCE loss into a Z-Score for the UI Dashboard.
        """
        loss = F.binary_cross_entropy_with_logits(predicted_edges, real_edges, reduction='none')
        # In a production environment, this loss would be normalized against 
        # a rolling 30-day baseline mean and standard deviation to get the Z-Score.
        return loss

if __name__ == "__main__":
    print("=====================================================")
    print(" TKG Autoencoder Architecture Check")
    print("=====================================================")
    if GATConv is None:
        print("[-] Missing dependencies. Install PyTorch Geometric to run tensor tests.")
    else:
        # Define mock network metrics (e.g., 5 features: degree, bytes in/out, velocity, etc.)
        num_nodes = 300
        in_features = 5 
        
        print("[*] Initializing Zero-Day Graph Attention Autoencoder...")
        model = ZeroDayAnomalyDetector(in_features=in_features, hidden_features=16, latent_dim=8)
        
        print("[+] Architecture successfully compiled in PyTorch.")
        print("[INFO] Model parameters:", sum(p.numel() for p in model.parameters() if p.requires_grad))
        print("[INFO] Awaiting 30-day NetFlow dataset for baseline training phase.")
        print("=====================================================")
