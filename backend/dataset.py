"""
Synthetic CICIDS2018 + UNSW-NB15 dataset generator.
12 attack categories matching paper Table II.
Generates 78-dimensional feature vectors with per-class realistic distributions.
"""
import numpy as np
from typing import Tuple

ATTACK_LABELS = [
    "Benign", "DoS-Hulk", "PortScan", "DDoS", "DoS-GoldenEye",
    "FTP-Patator", "SSH-Patator", "Bot", "Web-BruteForce",
    "Infiltration", "Heartbleed", "Ransomware",
]
N_CLASSES = len(ATTACK_LABELS)   # 12
N_FEATURES = 78


# Per-class mean vectors (78 features, grouped)
# Values are in raw scale before robust z-score; generator adds noise.
def _class_profile(cls: int, n: int, rng: np.random.Generator) -> np.ndarray:
    """Return (n, 78) raw feature matrix for class cls."""

    def gauss(mu, sigma, lo=0, size=None):
        return np.clip(rng.normal(mu, sigma, size if size else n), lo, None)

    def choice(options, size=None):
        return rng.choice(options, size if size else n)

    # Allocate feature matrix
    X = np.zeros((n, N_FEATURES), dtype=np.float32)

    # ── Feature indices by group ──────────────────────────────────────────────
    # G1: duration(0) tot_fwd(1) tot_bwd(2) len_fwd(3) len_bwd(4)
    #     pkt_max_f(5) pkt_min_f(6) pkt_mu_f(7) pkt_sd_f(8)
    #     pkt_max_b(9) pkt_min_b(10) pkt_mu_b(11) pkt_sd_b(12)
    # G2: bps(13) pps(14)
    # G3: fwd_iat_tot(15)..flow_iat_min(28)
    # G4: psh/urg flags(29-32) hdr(33-34) fin/syn/rst/psh/ack/urg/cwe/ece(35-42)
    # G5: bulk (43-48)
    # G6: subflow (49-52)
    # G7: active/idle (53-60)
    # G8: entropy (61-62)
    # G9: behaviour (63-66)
    # G10: protocol/ports (67-69)
    # G11: pkt stats (70-77)

    if cls == 0:  # Benign
        X[:, 0]  = gauss(1.5, 1.0, 0.01)         # duration
        X[:, 1]  = gauss(12, 8, 1)                # tot_fwd_pkts
        X[:, 2]  = gauss(8, 5, 1)                 # tot_bwd_pkts
        X[:, 3]  = gauss(6500, 3000, 100)
        X[:, 4]  = gauss(4200, 2000, 50)
        X[:, 13] = gauss(18000, 8000, 0)          # bps
        X[:, 14] = gauss(35, 15, 0)               # pps
        X[:, 37] = gauss(1, 0.5, 0)               # syn
        X[:, 40] = gauss(5, 3, 0)                 # ack
        X[:, 61] = gauss(3.2, 0.6, 0)             # payload_entropy
        X[:, 62] = gauss(1.5, 0.5, 0)             # domain_entropy
        X[:, 63] = gauss(0.1, 0.05, 0)            # baseline_dev
        X[:, 67] = choice([6, 17, 1])             # protocol
        X[:, 68] = choice([80, 443, 8080, 22, 25, 53])
        X[:, 70] = gauss(0.85, 0.2, 0)            # down/up ratio

    elif cls == 1:  # DoS-Hulk
        X[:, 0]  = gauss(0.008, 0.003, 0.001)
        X[:, 1]  = gauss(480, 60, 10)
        X[:, 2]  = gauss(300, 40, 5)
        X[:, 3]  = gauss(280000, 30000, 0)
        X[:, 4]  = gauss(180000, 20000, 0)
        X[:, 13] = gauss(3.5e7, 5e6, 0)
        X[:, 14] = gauss(6000, 800, 0)
        X[:, 37] = gauss(2, 0.5, 0)
        X[:, 40] = gauss(480, 60, 0)
        X[:, 61] = gauss(4.5, 0.4, 0)
        X[:, 63] = gauss(3.5, 0.3, 0)
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = choice([80, 8080])
        X[:, 70] = gauss(0.6, 0.1, 0)

    elif cls == 2:  # PortScan
        X[:, 0]  = gauss(0.001, 0.0005, 0.0001)
        X[:, 1]  = gauss(2, 0.5, 1)
        X[:, 2]  = gauss(0.5, 0.3, 0)
        X[:, 3]  = gauss(80, 20, 0)
        X[:, 4]  = gauss(40, 15, 0)
        X[:, 13] = gauss(80000, 10000, 0)
        X[:, 14] = gauss(2000, 300, 0)
        X[:, 37] = gauss(1, 0.2, 0)               # syn
        X[:, 39] = gauss(1, 0.2, 0)               # rst
        X[:, 61] = gauss(2.0, 0.4, 0)
        X[:, 63] = gauss(2.8, 0.3, 0)
        X[:, 64] = gauss(50, 10, 0)               # ip_diversity
        X[:, 65] = gauss(200, 30, 0)              # port_diversity
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = rng.integers(1, 65535, n).astype(np.float32)
        X[:, 70] = gauss(0.05, 0.02, 0)

    elif cls == 3:  # DDoS
        X[:, 0]  = gauss(0.003, 0.001, 0.0005)
        X[:, 1]  = gauss(600, 80, 10)
        X[:, 2]  = gauss(200, 30, 0)
        X[:, 13] = gauss(5e7, 8e6, 0)
        X[:, 14] = gauss(15000, 2000, 0)
        X[:, 37] = gauss(150, 25, 0)              # syn flood
        X[:, 40] = gauss(200, 30, 0)
        X[:, 61] = gauss(5.0, 0.5, 0)
        X[:, 63] = gauss(4.0, 0.3, 0)
        X[:, 64] = gauss(120, 20, 0)              # many IPs
        X[:, 67] = np.full(n, 17, dtype=np.float32)  # UDP
        X[:, 68] = choice([80, 443, 53])
        X[:, 70] = gauss(0.2, 0.05, 0)

    elif cls == 4:  # DoS-GoldenEye
        X[:, 0]  = gauss(0.8, 0.3, 0.05)
        X[:, 1]  = gauss(120, 20, 5)
        X[:, 2]  = gauss(80, 15, 0)
        X[:, 13] = gauss(600000, 80000, 0)
        X[:, 14] = gauss(200, 30, 0)
        X[:, 40] = gauss(120, 20, 0)
        X[:, 61] = gauss(4.2, 0.4, 0)
        X[:, 63] = gauss(3.0, 0.3, 0)
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = choice([80, 443])
        X[:, 70] = gauss(0.7, 0.1, 0)

    elif cls == 5:  # FTP-Patator
        X[:, 0]  = gauss(0.15, 0.05, 0.01)
        X[:, 1]  = gauss(10, 2, 2)
        X[:, 2]  = gauss(8, 2, 1)
        X[:, 13] = gauss(8000, 1500, 0)
        X[:, 14] = gauss(80, 15, 0)
        X[:, 37] = gauss(1, 0.2, 0)
        X[:, 40] = gauss(10, 2, 0)
        X[:, 61] = gauss(4.5, 0.5, 0)             # auth payloads
        X[:, 63] = gauss(2.0, 0.3, 0)
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = np.full(n, 21, dtype=np.float32)   # FTP
        X[:, 70] = gauss(0.8, 0.1, 0)

    elif cls == 6:  # SSH-Patator
        X[:, 0]  = gauss(0.5, 0.2, 0.05)
        X[:, 1]  = gauss(12, 3, 2)
        X[:, 2]  = gauss(10, 3, 1)
        X[:, 13] = gauss(15000, 3000, 0)
        X[:, 14] = gauss(40, 8, 0)
        X[:, 37] = gauss(1, 0.2, 0)
        X[:, 40] = gauss(12, 3, 0)
        X[:, 61] = gauss(5.5, 0.5, 0)             # encrypted
        X[:, 63] = gauss(2.2, 0.3, 0)
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = np.full(n, 22, dtype=np.float32)   # SSH
        X[:, 70] = gauss(0.85, 0.1, 0)

    elif cls == 7:  # Bot / beaconing
        X[:, 0]  = gauss(0.05, 0.01, 0.005)
        X[:, 1]  = gauss(5, 1, 1)
        X[:, 2]  = gauss(4, 1, 0)
        X[:, 13] = gauss(3000, 500, 0)
        X[:, 14] = gauss(15, 3, 0)
        # Very regular IAT (beaconing signature)
        X[:, 16] = gauss(3600, 50, 0)             # fwd_iat_mean — hourly
        X[:, 17] = gauss(8, 1, 0)                 # fwd_iat_std — very low
        X[:, 61] = gauss(3.8, 0.3, 0)
        X[:, 62] = gauss(5.0, 0.5, 0)             # DGA domain entropy
        X[:, 63] = gauss(2.5, 0.2, 0)
        X[:, 66] = gauss(0.5, 0.1, 0)             # temporal_anomaly
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = choice([443, 80, 8443])
        X[:, 70] = gauss(0.5, 0.1, 0)

    elif cls == 8:  # Web-BruteForce
        X[:, 0]  = gauss(0.01, 0.003, 0.001)
        X[:, 1]  = gauss(8, 2, 1)
        X[:, 2]  = gauss(6, 2, 0)
        X[:, 13] = gauss(50000, 8000, 0)
        X[:, 14] = gauss(800, 100, 0)
        X[:, 37] = gauss(1, 0.2, 0)
        X[:, 40] = gauss(8, 2, 0)
        X[:, 41] = gauss(4, 1, 0)                 # psh
        X[:, 61] = gauss(4.0, 0.4, 0)
        X[:, 63] = gauss(2.3, 0.3, 0)
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = choice([80, 443, 8080])
        X[:, 70] = gauss(0.4, 0.1, 0)

    elif cls == 9:  # Infiltration (low-and-slow)
        X[:, 0]  = gauss(12, 4, 1)                # long duration
        X[:, 1]  = gauss(20, 5, 2)
        X[:, 2]  = gauss(15, 4, 1)
        X[:, 13] = gauss(1200, 400, 0)            # low rate
        X[:, 14] = gauss(5, 1, 0)
        X[:, 61] = gauss(4.8, 0.4, 0)
        X[:, 63] = gauss(2.5, 0.4, 0)
        X[:, 66] = gauss(3.0, 0.5, 0)             # temporal anomaly
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = choice([443, 80])
        X[:, 70] = gauss(2.5, 0.5, 0)             # high down/up

    elif cls == 10:  # Heartbleed
        X[:, 0]  = gauss(0.3, 0.1, 0.01)
        X[:, 1]  = gauss(8, 2, 1)
        X[:, 2]  = gauss(200, 30, 5)              # large response
        X[:, 3]  = gauss(500, 100, 0)
        X[:, 4]  = gauss(65000, 5000, 0)          # large bwd bytes
        X[:, 13] = gauss(250000, 40000, 0)
        X[:, 61] = gauss(7.0, 0.4, 0)             # very high entropy
        X[:, 63] = gauss(3.8, 0.3, 0)
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = np.full(n, 443, dtype=np.float32)
        X[:, 76] = np.full(n, 65535, dtype=np.float32)  # max init window
        X[:, 70] = gauss(100, 20, 0)               # huge down/up

    elif cls == 11:  # Ransomware pre-staging
        X[:, 0]  = gauss(3.0, 1.0, 0.5)
        X[:, 1]  = gauss(50, 10, 5)
        X[:, 2]  = gauss(200, 40, 10)             # high outbound
        X[:, 3]  = gauss(20000, 3000, 0)
        X[:, 4]  = gauss(150000, 25000, 0)        # large outbound data
        X[:, 13] = gauss(600000, 100000, 0)
        X[:, 61] = gauss(6.5, 0.4, 0)             # encrypted content
        X[:, 62] = gauss(5.5, 0.5, 0)             # DGA domains
        X[:, 63] = gauss(4.0, 0.4, 0)
        X[:, 66] = gauss(4.0, 0.4, 0)             # temporal anomaly
        X[:, 67] = np.full(n, 6, dtype=np.float32)
        X[:, 68] = choice([443, 8443])
        X[:, 70] = gauss(8.0, 1.5, 0)             # high down/up

    # Fill remaining features with realistic noise
    unfilled_mask = X == 0
    X[unfilled_mask] = np.abs(rng.normal(0, 0.5, unfilled_mask.sum())).astype(np.float32)
    X = np.clip(X, 0, None)
    return X.astype(np.float32)


def generate_dataset(
    n_total: int = 60000,
    random_state: int = 42,
    noise_level: float = 0.18,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic CICIDS2018 + UNSW-NB15 style dataset.
    Returns X (n_total, 78) raw features and y (n_total,) integer labels.
    """
    rng = np.random.default_rng(random_state)

    # Class imbalance resembling CICIDS2018 (~45% benign)
    class_weights = [0.35, 0.08, 0.08, 0.07, 0.06,
                     0.06, 0.06, 0.06, 0.05, 0.05, 0.04, 0.04]
    class_counts  = [max(1, int(n_total * w)) for w in class_weights]
    # Adjust to hit exact total
    diff = n_total - sum(class_counts)
    class_counts[0] += diff

    X_parts, y_parts = [], []
    for cls, cnt in enumerate(class_counts):
        Xc = _class_profile(cls, cnt, rng)
        # Add Gaussian noise to create realistic overlap at class boundaries
        noise = rng.normal(0, noise_level, Xc.shape).astype(np.float32)
        Xc += noise * np.abs(Xc + 1e-3)
        Xc = np.clip(Xc, 0, None)
        X_parts.append(Xc)
        y_parts.append(np.full(cnt, cls, dtype=np.int32))

    X = np.vstack(X_parts)
    y = np.concatenate(y_parts)

    idx = rng.permutation(len(y))
    return X[idx].astype(np.float32), y[idx].astype(np.int32)


def make_sequences(X: np.ndarray, y: np.ndarray, seq_len: int = 20
                   ) -> Tuple[np.ndarray, np.ndarray]:
    """
    Reshape flat (N, 78) into (N//seq_len, seq_len, 78) sequences for BiLSTM.
    Label of each sequence = majority label in window.
    """
    n_seq = len(X) // seq_len
    Xs = X[:n_seq * seq_len].reshape(n_seq, seq_len, -1)
    ys_raw = y[:n_seq * seq_len].reshape(n_seq, seq_len)
    ys = np.array([np.bincount(row, minlength=N_CLASSES).argmax() for row in ys_raw],
                  dtype=np.int32)
    return Xs, ys
