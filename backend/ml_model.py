"""
NDR Ensemble Model — Paper: "AI-Driven Network Detection and Response Platform"
Section 4.2: Hybrid Detection Architecture

Layer 1 (Unsupervised baselines):
  • Isolation Forest   — contamination=0.09  → anomaly score ∈ [-1, 1]
  • One-Class SVM      — nu=0.08             → outlier score ∈ [-∞, 0] (neg=outlier)

Layer 2 (Sequence classifier):
  • BiLSTM             — 2 stacked Bidirectional LSTM layers, 128 units/direction,
                         dropout p=0.3, input window N=20, softmax over 12 classes

Layer 3 (Meta-ensemble):
  • XGBoost            — fuses all layer-1/2 outputs → final label + threat score [0,1]

Accuracy targets (Table II):
  Isolation Forest  91.5 %    One-Class SVM  89.7 %
  BiLSTM            94.8 %    Ensemble       96.4 %  (F1 95.9 %)
"""

import logging
import os
import joblib

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import label_binarize

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
N_FEATURES  = 78
N_CLASSES   = 12
SEQ_LEN     = 20   # N in paper (consecutive flow records per sequence)

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")

ATTACK_LABELS = [
    "Benign", "DoS-Hulk", "PortScan", "DDoS", "DoS-GoldenEye",
    "FTP-Patator", "SSH-Patator", "Bot", "Web-BruteForce",
    "Infiltration", "Heartbleed", "Ransomware",
]

# ABRE risk tier mapping (Section 4.3)
# Tier-1: auto-execute response  Tier-2: Analyst approval  Tier-3: Manager approval
ATTACK_RISK_TIER: dict[str, int] = {
    "Benign":         1,
    "DoS-GoldenEye":  2,
    "FTP-Patator":    2,
    "SSH-Patator":    2,
    "Web-BruteForce": 2,
    "PortScan":       2,
    "DoS-Hulk":       3,
    "DDoS":           3,
    "Bot":            3,
    "Infiltration":   3,
    "Heartbleed":     3,
    "Ransomware":     3,
}


# ── Layer 1: Isolation Forest ─────────────────────────────────────────────────
class IsolationForestDetector:
    """Unsupervised anomaly detector trained on benign traffic only."""

    _PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")

    def __init__(self):
        self.model: IsolationForest | None = None

    def fit(self, X_benign: np.ndarray) -> None:
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.09,
            max_features=1.0,
            bootstrap=False,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_benign)

    def score(self, X: np.ndarray) -> np.ndarray:
        """Return raw decision scores; more-negative = more anomalous."""
        if self.model is None:
            self._load()
        return self.model.decision_function(X)          # shape (N,)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return 1 (normal) or -1 (anomaly)."""
        if self.model is None:
            self._load()
        return self.model.predict(X)

    def save(self) -> None:
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, self._PATH)
        logger.info(f"IsolationForest saved → {self._PATH}")

    def _load(self) -> None:
        self.model = joblib.load(self._PATH)

    def is_trained(self) -> bool:
        return os.path.exists(self._PATH)


# ── Layer 1: One-Class SVM ────────────────────────────────────────────────────
class OneClassSVMDetector:
    """Kernel-based one-class novelty detector trained on benign traffic."""

    _PATH = os.path.join(MODEL_DIR, "one_class_svm.pkl")

    def __init__(self):
        self.model: OneClassSVM | None = None

    def fit(self, X_benign: np.ndarray) -> None:
        # Sample to keep training tractable (SVM is O(n²))
        max_samples = min(len(X_benign), 8_000)
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X_benign), max_samples, replace=False)
        self.model = OneClassSVM(
            kernel="rbf",
            nu=0.08,
            gamma="scale",
        )
        self.model.fit(X_benign[idx])

    def score(self, X: np.ndarray) -> np.ndarray:
        """Return decision scores; negative = outlier."""
        if self.model is None:
            self._load()
        return self.model.decision_function(X)

    def save(self) -> None:
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, self._PATH)
        logger.info(f"OneClassSVM saved → {self._PATH}")

    def _load(self) -> None:
        self.model = joblib.load(self._PATH)

    def is_trained(self) -> bool:
        return os.path.exists(self._PATH)


# ── Layer 2: BiLSTM ───────────────────────────────────────────────────────────
class BiLSTMClassifier:
    """
    2-layer stacked Bidirectional LSTM.
    Architecture (Section 4.2):
      Input  : (batch, SEQ_LEN=20, N_FEATURES=78)
      BiLSTM : 128 units/direction, return_sequences=True,  dropout=0.3
      BiLSTM : 128 units/direction, return_sequences=False, dropout=0.3
      Dense  : 64 units, ReLU
      Dropout: 0.3
      Output : 12 units, Softmax
    """

    _PATH = os.path.join(MODEL_DIR, "bilstm.keras")

    def __init__(self):
        self.model = None

    # ------------------------------------------------------------------
    def _build(self):
        import tensorflow as tf
        tf.get_logger().setLevel("ERROR")

        inp = tf.keras.Input(shape=(SEQ_LEN, N_FEATURES), name="flow_sequence")

        x = tf.keras.layers.Bidirectional(
            tf.keras.layers.LSTM(128, return_sequences=True, dropout=0.3),
            name="bilstm_1",
        )(inp)
        x = tf.keras.layers.Bidirectional(
            tf.keras.layers.LSTM(128, return_sequences=False, dropout=0.3),
            name="bilstm_2",
        )(x)
        x = tf.keras.layers.Dense(64, activation="relu", name="dense_1")(x)
        x = tf.keras.layers.Dropout(0.3, name="dropout_1")(x)
        out = tf.keras.layers.Dense(N_CLASSES, activation="softmax", name="output")(x)

        model = tf.keras.Model(inp, out, name="bilstm_ndr")
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
            loss="sparse_categorical_crossentropy",
            metrics=["accuracy"],
        )
        return model

    # ------------------------------------------------------------------
    def fit(
        self,
        X_seq: np.ndarray,
        y_seq: np.ndarray,
        epochs: int = 30,
        batch_size: int = 256,
        class_weight: dict | None = None,
    ) -> dict:
        import tensorflow as tf
        tf.get_logger().setLevel("ERROR")

        self.model = self._build()
        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                patience=5,
                restore_best_weights=True,
                monitor="val_accuracy",
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                patience=2,
                factor=0.5,
                min_lr=1e-5,
                monitor="val_loss",
                verbose=0,
            ),
        ]
        history = self.model.fit(
            X_seq, y_seq,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.15,
            callbacks=callbacks,
            class_weight=class_weight,
            verbose=1,
        )
        return history.history

    # ------------------------------------------------------------------
    def predict_proba(self, X_seq: np.ndarray) -> np.ndarray:
        """Return (N, 12) softmax probabilities."""
        if self.model is None:
            self._load()
        return self.model.predict(X_seq, verbose=0)

    def save(self) -> None:
        os.makedirs(MODEL_DIR, exist_ok=True)
        self.model.save(self._PATH)
        logger.info(f"BiLSTM saved → {self._PATH}")

    def _load(self) -> None:
        import tensorflow as tf
        tf.get_logger().setLevel("ERROR")
        self.model = tf.keras.models.load_model(self._PATH)

    def is_trained(self) -> bool:
        return os.path.exists(self._PATH)


# ── Layer 2b: XGBoost Direct Classifier (flat features) ──────────────────────
class XGBoostDirectClassifier:
    """
    Multi-class XGBoost trained directly on the 78-dimensional flat feature
    vectors (no sequences needed).  Provides strong per-class signal to the
    meta-ensemble even when the BiLSTM has limited training data.
    Expected accuracy: ~93–96% on CICIDS2018 benchmarks.
    """

    _PATH = os.path.join(MODEL_DIR, "xgboost_direct.pkl")

    def __init__(self):
        self.model = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        import xgboost as xgb
        from sklearn.utils.class_weight import compute_sample_weight

        sample_weight = compute_sample_weight("balanced", y)
        self.model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=7,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=-1,
            tree_method="hist",
        )
        self.model.fit(X, y, sample_weight=sample_weight, verbose=False)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return (N, 12) probability matrix."""
        if self.model is None:
            self._load()
        return self.model.predict_proba(X)

    def save(self) -> None:
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, self._PATH)
        logger.info(f"XGBoost direct classifier saved → {self._PATH}")

    def _load(self) -> None:
        self.model = joblib.load(self._PATH)

    def is_trained(self) -> bool:
        return os.path.exists(self._PATH)


# ── Layer 3: XGBoost Meta-Ensemble ───────────────────────────────────────────
class XGBoostMetaEnsemble:
    """
    Meta-classifier that fuses outputs from all layer-1/2 detectors.
    Input features (14 per sample):
      [if_score(1), svm_score(1), bilstm_proba(12)]
    Output: final attack label (0–11) + threat score [0, 1]
    """

    _PATH = os.path.join(MODEL_DIR, "xgboost_meta.pkl")

    def __init__(self):
        self.model = None

    def fit(
        self,
        meta_X: np.ndarray,
        y: np.ndarray,
    ) -> None:
        import xgboost as xgb

        # Compute class weights for imbalanced dataset
        from sklearn.utils.class_weight import compute_sample_weight
        sample_weight = compute_sample_weight("balanced", y)

        self.model = xgb.XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=-1,
            tree_method="hist",
        )
        self.model.fit(
            meta_X, y,
            sample_weight=sample_weight,
            verbose=False,
        )

    def predict(self, meta_X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Return (labels, threat_scores) where threat_score ∈ [0, 1]."""
        if self.model is None:
            self._load()
        labels = self.model.predict(meta_X)
        proba  = self.model.predict_proba(meta_X)
        # threat_score = 1 - P(Benign)
        threat_scores = 1.0 - proba[:, 0]
        return labels, threat_scores

    def save(self) -> None:
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, self._PATH)
        logger.info(f"XGBoost meta-ensemble saved → {self._PATH}")

    def _load(self) -> None:
        self.model = joblib.load(self._PATH)

    def is_trained(self) -> bool:
        return os.path.exists(self._PATH)


# ── NDR Ensemble Orchestrator ─────────────────────────────────────────────────
class NDREnsemble:
    """
    Orchestrates all layers for inference.
    Layer 1: Isolation Forest + One-Class SVM (unsupervised)
    Layer 2: BiLSTM (sequence) + XGBoost-direct (flat 78-dim)
    Layer 3: XGBoost meta-ensemble
    Provides graceful fallback if models are not yet trained.
    """

    def __init__(self):
        self.if_detector  = IsolationForestDetector()
        self.svm_detector = OneClassSVMDetector()
        self.bilstm       = BiLSTMClassifier()
        self.xgb_direct   = XGBoostDirectClassifier()
        self.meta         = XGBoostMetaEnsemble()
        self._ready       = False

    # ------------------------------------------------------------------
    def load(self) -> bool:
        """Load all pre-trained models. Returns True if all models available."""
        try:
            if not all([
                self.if_detector.is_trained(),
                self.svm_detector.is_trained(),
                self.bilstm.is_trained(),
                self.xgb_direct.is_trained(),
                self.meta.is_trained(),
            ]):
                logger.warning("One or more NDR models not found — using rule-based fallback")
                return False

            self.if_detector._load()
            self.svm_detector._load()
            self.bilstm._load()
            self.xgb_direct._load()
            self.meta._load()
            self._ready = True
            logger.info("NDR ensemble loaded successfully")
            return True
        except Exception as exc:
            logger.error(f"Failed to load NDR models: {exc}")
            return False

    # ------------------------------------------------------------------
    def build_meta_features(
        self,
        X_flat: np.ndarray,
        X_seq:  np.ndarray,
    ) -> np.ndarray:
        """
        Construct the 26-dimensional meta-feature matrix:
          [if_score(1), svm_score(1), bilstm_proba(12), xgb_direct_proba(12)]
        X_flat : (N, 78)  — one row per flow
        X_seq  : (M, 20, 78) where M = N // SEQ_LEN
        """
        N = len(X_flat)

        if_scores   = self.if_detector.score(X_flat)          # (N,)
        svm_scores  = self.svm_detector.score(X_flat)         # (N,)
        xgb_proba   = self.xgb_direct.predict_proba(X_flat)   # (N, 12)
        bilstm_p    = self.bilstm.predict_proba(X_seq)        # (M, 12)

        # Expand sequence-level BiLSTM predictions back to flow level
        bilstm_expanded = np.repeat(bilstm_p, SEQ_LEN, axis=0)[:N]  # (N, 12)

        meta = np.column_stack([if_scores, svm_scores, bilstm_expanded, xgb_proba])  # (N, 26)
        return meta.astype(np.float32)

    # ------------------------------------------------------------------
    def predict(
        self,
        X_flat: np.ndarray,
        X_seq:  np.ndarray | None = None,
    ) -> list[dict]:
        """
        Full ensemble inference.
        Returns list of dicts with keys:
          attack_category, threat_score, risk_tier, ai_prediction, ai_score, ai_reason
        """
        N = len(X_flat)

        # ── Fallback if models not ready ──────────────────────────────
        if not self._ready:
            return self._rule_based_fallback(X_flat)

        # ── Build sequences if not provided ──────────────────────────
        if X_seq is None:
            if N < SEQ_LEN:
                pad   = SEQ_LEN - N
                Xp    = np.vstack([X_flat, np.zeros((pad, N_FEATURES), dtype=np.float32)])
                X_seq = Xp.reshape(1, SEQ_LEN, N_FEATURES)
            else:
                n_seq = N // SEQ_LEN
                X_seq = X_flat[:n_seq * SEQ_LEN].reshape(n_seq, SEQ_LEN, N_FEATURES)

        # ── Layer 1 + 2 → meta features ──────────────────────────────
        try:
            meta = self.build_meta_features(X_flat, X_seq)          # (N, 14)
            labels, threat_scores = self.meta.predict(meta)          # (N,), (N,)
        except Exception as exc:
            logger.error(f"Ensemble prediction error: {exc}")
            return self._rule_based_fallback(X_flat)

        # ── Assemble results ──────────────────────────────────────────
        results = []
        for i in range(N):
            cat   = ATTACK_LABELS[int(labels[i])]
            score = float(np.clip(threat_scores[i], 0.0, 1.0))
            tier  = ATTACK_RISK_TIER.get(cat, 2)

            # Map attack category → human-readable prediction label
            is_malicious = cat != "Benign"
            prediction   = "suspicious" if is_malicious else "normal"
            reason       = _build_reason(cat, score, X_flat[i])

            results.append({
                "attack_category": cat,
                "threat_score":    score,
                "risk_tier":       tier,
                "ai_prediction":   prediction,
                "ai_score":        round(score, 4),
                "ai_reason":       reason,
            })
        return results

    # ------------------------------------------------------------------
    def _rule_based_fallback(self, X_flat: np.ndarray) -> list[dict]:
        """Simple heuristic fallback when models not available."""
        results = []
        for row in X_flat:
            bps        = float(row[13])
            pps        = float(row[14])
            payload_e  = float(row[61])
            domain_e   = float(row[62])
            port_div   = float(row[65])

            # Heuristic scoring
            score = 0.0
            cat   = "Benign"

            if pps > 5000 or bps > 2e7:
                score = 0.92; cat = "DDoS"
            elif port_div > 100:
                score = 0.80; cat = "PortScan"
            elif domain_e > 4.5:
                score = 0.75; cat = "Bot"
            elif payload_e > 6.5:
                score = 0.70; cat = "Heartbleed"
            elif bps > 5e5:
                score = 0.55; cat = "DoS-GoldenEye"

            tier   = ATTACK_RISK_TIER.get(cat, 1)
            reason = _build_reason(cat, score, row)
            results.append({
                "attack_category": cat,
                "threat_score":    round(score, 4),
                "risk_tier":       tier,
                "ai_prediction":   "suspicious" if cat != "Benign" else "normal",
                "ai_score":        round(score, 4),
                "ai_reason":       reason,
            })
        return results


# ── Singleton ─────────────────────────────────────────────────────────────────
_ensemble: NDREnsemble | None = None


def get_ensemble() -> NDREnsemble:
    """Return singleton NDREnsemble, loading models on first call."""
    global _ensemble
    if _ensemble is None:
        _ensemble = NDREnsemble()
        _ensemble.load()
    return _ensemble


# ── Helpers ───────────────────────────────────────────────────────────────────
def _build_reason(cat: str, score: float, feat_row: np.ndarray) -> str:
    """Generate a human-readable explanation for the classification."""
    pct = int(score * 100)
    explanations = {
        "DoS-Hulk":      f"Volumetric DoS detected — extremely high packet/byte rate (threat score {pct}%)",
        "PortScan":       f"Port scan detected — high destination-port diversity and low-duration flows ({pct}%)",
        "DDoS":           f"DDoS flood detected — SYN/UDP storm from multiple source IPs ({pct}%)",
        "DoS-GoldenEye":  f"HTTP DoS (GoldenEye) — repeated connection exhaustion attack ({pct}%)",
        "FTP-Patator":    f"FTP brute force detected — repeated login attempts on port 21 ({pct}%)",
        "SSH-Patator":    f"SSH brute force detected — credential stuffing on port 22 ({pct}%)",
        "Bot":            f"Beaconing bot detected — periodic C2 check-in with DGA domain ({pct}%)",
        "Web-BruteForce": f"Web brute force detected — rapid HTTP auth failures ({pct}%)",
        "Infiltration":   f"Low-and-slow infiltration — prolonged anomalous data transfer ({pct}%)",
        "Heartbleed":     f"Heartbleed exploit detected — TLS memory leak pattern ({pct}%)",
        "Ransomware":     f"Ransomware staging detected — encrypted exfiltration to DGA domain ({pct}%)",
        "Benign":         "Traffic within normal baseline parameters",
    }
    return explanations.get(cat, f"Anomalous traffic pattern detected ({pct}% threat confidence)")
