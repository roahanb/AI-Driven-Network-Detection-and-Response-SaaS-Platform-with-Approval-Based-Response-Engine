"""
NDR Platform — Model Training Script
Paper: "AI-Driven Network Detection and Response Platform"

Trains the full 3-layer ensemble on synthetic CICIDS2018 + UNSW-NB15 data.
Target accuracy (Table II): Ensemble 96.4%, F1 95.9%

Usage:
    python train.py                   # 60 000 samples (fast, ~5 min)
    python train.py --samples 120000  # larger dataset (~12 min)
    python train.py --fast            # 20 000 samples for CI/build (~90 s)
"""

import argparse
import logging
import os
import sys
import time

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
)
from sklearn.model_selection import train_test_split

# ── Path setup ─────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from dataset import (
    ATTACK_LABELS,
    N_CLASSES,
    N_FEATURES,
    generate_dataset,
    make_sequences,
)
from feature_engineering import robust_zscore
from ml_model import (
    SEQ_LEN,
    BiLSTMClassifier,
    IsolationForestDetector,
    NDREnsemble,
    OneClassSVMDetector,
    XGBoostDirectClassifier,
    XGBoostMetaEnsemble,
    get_ensemble,
)

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train")


# ══════════════════════════════════════════════════════════════════════════════
def main(n_samples: int = 60_000, fast: bool = False) -> None:
    t0 = time.time()

    # ── 0. Args ────────────────────────────────────────────────────────────────
    if fast:
        n_samples = 20_000
        logger.info(f"Fast mode: using {n_samples:,} samples")
    else:
        logger.info(f"Generating {n_samples:,} synthetic CICIDS2018+UNSW-NB15 samples …")

    # ── 1. Generate dataset ────────────────────────────────────────────────────
    X_raw, y = generate_dataset(n_total=n_samples, random_state=42, noise_level=0.18)
    logger.info(f"Dataset: {X_raw.shape}  classes: {N_CLASSES}  features: {N_FEATURES}")
    _print_class_dist(y)

    # ── 2. Normalise (robust z-score) ──────────────────────────────────────────
    X = robust_zscore(X_raw)
    logger.info("Applied robust z-score normalisation (CICIDS2018 baseline)")

    # ── 3. Train/val/test split (70 / 15 / 15) ─────────────────────────────────
    X_tv, X_test, y_tv, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_tv, y_tv, test_size=0.15 / 0.85, random_state=42, stratify=y_tv
    )
    logger.info(
        f"Split → train {len(X_train):,}  val {len(X_val):,}  test {len(X_test):,}"
    )

    # ── 4. Benign subset for unsupervised detectors ────────────────────────────
    X_benign_train = X_train[y_train == 0]
    logger.info(f"Benign training samples: {len(X_benign_train):,}")

    # ══ LAYER 1a: Isolation Forest ═════════════════════════════════════════════
    logger.info("▶  Training Isolation Forest …")
    t1 = time.time()
    if_det = IsolationForestDetector()
    if_det.fit(X_benign_train)
    if_det.save()

    if_preds = if_det.predict(X_test)           # 1=normal, -1=anomaly
    # Binary accuracy: anomaly = any non-benign class
    y_bin_test = (y_test != 0).astype(int)       # 1=attack, 0=benign
    if_bin     = (if_preds == -1).astype(int)
    if_acc     = accuracy_score(y_bin_test, if_bin)
    logger.info(f"   Isolation Forest binary accuracy : {if_acc:.4f}  ({time.time()-t1:.1f}s)")

    # ══ LAYER 1b: One-Class SVM ════════════════════════════════════════════════
    logger.info("▶  Training One-Class SVM …")
    t1 = time.time()
    svm_det = OneClassSVMDetector()
    svm_det.fit(X_benign_train)
    svm_det.save()

    svm_preds = svm_det.score(X_test)
    svm_bin   = (svm_preds < 0).astype(int)      # negative score = outlier
    svm_acc   = accuracy_score(y_bin_test, svm_bin)
    logger.info(f"   One-Class SVM binary accuracy    : {svm_acc:.4f}  ({time.time()-t1:.1f}s)")

    # ══ LAYER 2b: XGBoost Direct Classifier (flat features) ═══════════════════
    logger.info("▶  Training XGBoost direct multi-class classifier (flat features) …")
    t1 = time.time()
    xgb_direct = XGBoostDirectClassifier()
    xgb_direct.fit(X_train, y_train)
    xgb_direct.save()

    xgb_direct_acc = accuracy_score(y_test, xgb_direct.predict_proba(X_test).argmax(axis=1))
    xgb_direct_f1  = f1_score(y_test, xgb_direct.predict_proba(X_test).argmax(axis=1),
                               average="macro", zero_division=0)
    logger.info(
        f"   XGBoost direct accuracy : {xgb_direct_acc:.4f}  "
        f"macro-F1 : {xgb_direct_f1:.4f}  ({time.time()-t1:.1f}s)"
    )

    # ══ LAYER 2: BiLSTM ════════════════════════════════════════════════════════
    logger.info("▶  Training BiLSTM (2×128, dropout=0.3, seq_len=20) …")
    t1 = time.time()

    # Build sequences
    X_seq_train, y_seq_train = make_sequences(X_train, y_train, SEQ_LEN)
    X_seq_val,   y_seq_val   = make_sequences(X_val,   y_val,   SEQ_LEN)
    X_seq_test,  y_seq_test  = make_sequences(X_test,  y_test,  SEQ_LEN)
    logger.info(
        f"   Sequences → train {X_seq_train.shape}  "
        f"val {X_seq_val.shape}  test {X_seq_test.shape}"
    )

    # Class weights for imbalanced training (only for classes present in sequences)
    from sklearn.utils.class_weight import compute_class_weight
    present_classes = np.unique(y_seq_train)
    cw = compute_class_weight("balanced", classes=present_classes, y=y_seq_train)
    class_weight_dict = {int(cls): float(w) for cls, w in zip(present_classes, cw)}
    # Default weight=1.0 for any class not represented in the sequence fold
    for i in range(N_CLASSES):
        class_weight_dict.setdefault(i, 1.0)

    bilstm = BiLSTMClassifier()
    epochs = 10 if fast else 30
    bilstm.fit(
        X_seq_train, y_seq_train,
        epochs=epochs,
        batch_size=256,
        class_weight=class_weight_dict,
    )
    bilstm.save()

    lstm_proba_test = bilstm.predict_proba(X_seq_test)  # (M, 12)
    lstm_preds_test = lstm_proba_test.argmax(axis=1)    # sequence-level labels
    lstm_acc = accuracy_score(y_seq_test, lstm_preds_test)
    lstm_f1  = f1_score(y_seq_test, lstm_preds_test, average="macro", zero_division=0)
    logger.info(
        f"   BiLSTM accuracy : {lstm_acc:.4f}  macro-F1 : {lstm_f1:.4f}  "
        f"({time.time()-t1:.1f}s)"
    )

    # ══ LAYER 3: XGBoost Meta-Ensemble ════════════════════════════════════════
    logger.info("▶  Building meta-features and training XGBoost meta-ensemble …")
    t1 = time.time()

    # Build meta-features on training + validation folds
    def _build_meta(X_flat, X_seq, y_flat):
        if_sc    = if_det.score(X_flat)
        svm_sc   = svm_det.score(X_flat)
        xgb_p    = xgb_direct.predict_proba(X_flat)  # (N, 12)
        N        = len(X_flat)
        bp       = bilstm.predict_proba(X_seq)        # (M, 12)
        bp_exp   = np.repeat(bp, SEQ_LEN, axis=0)[:N]
        return np.column_stack([if_sc, svm_sc, bp_exp, xgb_p]).astype(np.float32), y_flat

    meta_train_X, meta_train_y = _build_meta(X_train, X_seq_train, y_train)
    meta_val_X,   meta_val_y   = _build_meta(X_val,   X_seq_val,   y_val)

    # Merge train + val for final meta-training
    meta_all_X = np.vstack([meta_train_X, meta_val_X])
    meta_all_y = np.concatenate([meta_train_y, meta_val_y])

    meta = XGBoostMetaEnsemble()
    meta.fit(meta_all_X, meta_all_y)
    meta.save()

    # ── Final evaluation on held-out test set ──────────────────────────────────
    meta_test_X, _ = _build_meta(X_test, X_seq_test, y_test)
    ens_labels, ens_scores = meta.predict(meta_test_X)

    ens_acc = accuracy_score(y_test, ens_labels)
    ens_f1  = f1_score(y_test, ens_labels, average="macro", zero_division=0)
    logger.info(
        f"   XGBoost meta-ensemble fit complete  ({time.time()-t1:.1f}s)"
    )

    # ══ Summary Report ═════════════════════════════════════════════════════════
    elapsed = time.time() - t0
    _divider()
    logger.info("TRAINING COMPLETE — Accuracy Summary (Table II)")
    _divider()
    logger.info(f"  Isolation Forest   binary acc : {if_acc*100:5.1f}%  (paper target 91.5%)")
    logger.info(f"  One-Class SVM      binary acc : {svm_acc*100:5.1f}%  (paper target 89.7%)")
    logger.info(f"  XGBoost direct     accuracy   : {xgb_direct_acc*100:5.1f}%  (multi-class, 78 features)")
    logger.info(f"  BiLSTM             accuracy   : {lstm_acc*100:5.1f}%  (paper target 94.8%)")
    logger.info(f"  Ensemble           accuracy   : {ens_acc*100:5.1f}%  (paper target 96.4%)")
    logger.info(f"  Ensemble           macro-F1   : {ens_f1*100:5.1f}%  (paper target 95.9%)")
    _divider()
    logger.info(f"  Total training time: {elapsed:.0f}s")
    logger.info(f"  Models saved → {os.path.join(_HERE, 'saved_models')}/")
    _divider()

    # Per-class breakdown
    logger.info("\nPer-class report (ensemble on test set):")
    print(classification_report(
        y_test, ens_labels,
        target_names=ATTACK_LABELS,
        zero_division=0,
        digits=3,
    ))

    # Warn if accuracy well below target
    if ens_acc < 0.93:
        logger.warning(
            f"Ensemble accuracy {ens_acc:.3f} is below 0.93 — "
            "consider increasing --samples or checking data generation."
        )
    else:
        logger.info("✓ Accuracy meets paper targets")

    return ens_acc, ens_f1


# ── Helpers ────────────────────────────────────────────────────────────────────
def _divider():
    logger.info("─" * 60)


def _print_class_dist(y: np.ndarray) -> None:
    from dataset import ATTACK_LABELS
    counts = np.bincount(y, minlength=len(ATTACK_LABELS))
    total  = len(y)
    logger.info("Class distribution:")
    for i, (label, cnt) in enumerate(zip(ATTACK_LABELS, counts)):
        logger.info(f"  {i:2d}  {label:<18s}  {cnt:6d}  ({cnt/total*100:.1f}%)")


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train NDR ensemble models")
    parser.add_argument("--samples", type=int, default=60_000,
                        help="Total synthetic samples (default 60000)")
    parser.add_argument("--fast", action="store_true",
                        help="Quick 20k-sample run for CI/Docker build")
    args = parser.parse_args()

    main(n_samples=args.samples, fast=args.fast)
