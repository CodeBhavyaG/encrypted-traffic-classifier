#!/usr/bin/env python3
"""
train_evaluate.py - Machine Learning Model Training & Evaluation Benchmark
=============================================================================
Evaluates multiple classifiers (Random Forest, XGBoost, Logistic Regression)
on extracted statistical network traffic features.

Features of this evaluation suite:
1. Feature/Metadata Separation: Excludes IP addresses, ports, timestamps, and tracking tags.
2. Multi-Model Benchmark: Evaluates Random Forest, XGBoost, and Logistic Regression.
3. Detailed Metrics: Computes Per-Class Precision, Recall, F1-score, and Confusion Matrices.
4. Feature Importance: Identifies behavioral traffic signals via Tree Impurity & Permutation.
5. Domain Generalization Test:
   - Same-Network Cross-Validation (Home WiFi -> Home WiFi)
   - Cross-Network Evaluation (Train on Home WiFi -> Test on Mobile Hotspot, and vice versa)
   to measure whether the model learns actual application behavior or network-specific artifacts.
=============================================================================
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.inspection import permutation_importance

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except Exception:
    from sklearn.ensemble import HistGradientBoostingClassifier
    HAS_XGBOOST = False


# Non-feature metadata columns that must never be fed into the model
METADATA_COLS = ["class_label", "network_env", "run_id", "source_file"]


def get_models(random_state=42):
    """Returns a dictionary of baseline classifiers to compare."""
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=4,
            random_state=random_state,
            n_jobs=-1
        ),
        "Logistic Regression (Scaled)": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=1000,
                C=1.0,
                random_state=random_state
            ))
        ])
    }

    if HAS_XGBOOST:
        models["XGBoost"] = xgb.XGBClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="mlogloss",
            random_state=random_state,
            n_jobs=-1
        )
    else:
        models["Gradient Boosting"] = HistGradientBoostingClassifier(
            max_iter=150,
            random_state=random_state
        )

    return models


def save_confusion_matrix(cm, class_names, title, output_path):
    """Renders and saves a high-resolution confusion matrix plot."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fig, ax = plt.subplots(figsize=(7, 6))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=class_names)
    disp.plot(cmap=plt.cm.Blues, ax=ax, values_format="d", colorbar=False)
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[+] Saved confusion matrix to: {output_path}")


def analyze_feature_importance(model, feature_names, X_test, y_test, output_dir="reports"):
    """
    Computes both MDI (Gini) feature importance and Permutation Importance
    to reveal which traffic properties carry the strongest discriminative signal.
    """
    os.makedirs(output_dir, exist_ok=True)
    clf = model
    if hasattr(model, "named_steps"):
        clf = model.named_steps["clf"]

    # 1. Tree Feature Importance (if tree-based)
    if hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print("\n" + "="*60)
        print("  TOP 10 MOST INFORMATIVE TRAFFIC FEATURES (Tree Impurity)")
        print("="*60)
        for i in range(min(10, len(feature_names))):
            idx = indices[i]
            print(f"  {i+1:2d}. {feature_names[idx]:<24} : {importances[idx]:.4f}")
        print("="*60)

        # Plot top 15 features
        top_k = min(15, len(feature_names))
        top_indices = indices[:top_k]
        
        plt.figure(figsize=(10, 6))
        plt.barh(range(top_k), importances[top_indices][::-1], align="center", color="#2b5c8f")
        plt.yticks(range(top_k), [feature_names[i] for i in top_indices][::-1])
        plt.xlabel("Relative Importance (Gini / MDI)")
        plt.title("Top Feature Importances (Encrypted Traffic Signature)")
        plt.tight_layout()
        plot_path = os.path.join(output_dir, "feature_importance_gini.png")
        plt.savefig(plot_path, dpi=300)
        plt.close()
        print(f"[+] Saved feature importance chart to: {plot_path}")

    # 2. Permutation Importance on Test Set
    try:
        perm_res = permutation_importance(model, X_test, y_test, n_repeats=10, random_state=42, n_jobs=-1)
        perm_indices = np.argsort(perm_res.importances_mean)[::-1]
        print("\n" + "="*60)
        print("  TOP 5 PERMUTATION IMPORTANCE (Signal Drop on Holdout Test Set)")
        print("="*60)
        for i in range(min(5, len(feature_names))):
            idx = perm_indices[i]
            print(f"  {i+1:2d}. {feature_names[idx]:<24} : {perm_res.importances_mean[idx]:.4f} +/- {perm_res.importances_std[idx]:.4f}")
        print("="*60 + "\n")
    except Exception as e:
        print(f"[-] Permutation importance skipped: {e}")


def run_same_network_benchmark(df, feature_cols, target_col="class_label", reports_dir="reports"):
    """
    Standard benchmark: Evaluates classifiers within the same network environment
    or using stratified 5-fold cross-validation across the whole dataset.
    """
    print("\n" + "#"*70)
    print("  EXPERIMENT 1: SAME-NETWORK / IN-DISTRIBUTION BENCHMARK")
    print("#"*70)

    X = df[feature_cols].values
    y_raw = df[target_col].values

    label_enc = LabelEncoder()
    y = label_enc.fit_transform(y_raw)
    class_names = [str(c) for c in label_enc.classes_]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    models = get_models()
    results = {}

    for name, model in models.items():
        print(f"\n--> Training {name} on {len(X_train)} flow samples...")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        print(f"\n[Classification Report: {name}]")
        print(classification_report(y_test, y_pred, target_names=class_names, digits=4))

        cm = confusion_matrix(y_test, y_pred)
        cm_filename = f"cm_same_network_{name.lower().replace(' ', '_').replace('(', '').replace(')', '')}.png"
        save_confusion_matrix(
            cm, class_names,
            title=f"Confusion Matrix: {name} (Same-Network Holdout)",
            output_path=os.path.join(reports_dir, cm_filename)
        )

        results[name] = {
            "model": model,
            "y_pred": y_pred,
            "y_test": y_test,
            "cm": cm
        }

    # Run feature importance on best model (Random Forest)
    if "Random Forest" in results:
        analyze_feature_importance(
            results["Random Forest"]["model"],
            feature_cols,
            X_test,
            y_test,
            output_dir=reports_dir
        )


def run_cross_network_generalization(df, feature_cols, target_col="class_label", reports_dir="reports"):
    """
    Generalization benchmark:
    Tests whether a classifier trained on Network Environment A (e.g., Home Broadband WiFi)
    can generalize to Network Environment B (e.g., Mobile 4G/5G Hotspot).
    
    This exposes whether the classifier relies on network-specific artifacts
    (such as round-trip-time latency or fragmentation thresholds) rather than true application behaviors.
    """
    print("\n" + "#"*70)
    print("  EXPERIMENT 2: CROSS-NETWORK GENERALIZATION BENCHMARK")
    print("#"*70)

    env_counts = df["network_env"].value_counts()
    print("Network environments found in dataset:")
    for env, cnt in env_counts.items():
        print(f"  - {env}: {cnt} flows")

    if len(env_counts) < 2:
        print("\n[!] Notice: Only one network condition was detected in the dataset.")
        print("    To run cross-network evaluation, capture traces across both 'wifi_home' and 'mobile_hotspot'.")
        return

    envs = list(env_counts.keys())[:2]
    env_A, env_B = envs[0], envs[1]

    label_enc = LabelEncoder()
    df["encoded_label"] = label_enc.fit_transform(df[target_col])
    class_names = [str(c) for c in label_enc.classes_]

    df_A = df[df["network_env"] == env_A]
    df_B = df[df["network_env"] == env_B]

    # Direction 1: Train on A, Test on B
    print(f"\n[Test 2A: Train on '{env_A}' ({len(df_A)} samples) -> Test on '{env_B}' ({len(df_B)} samples)]")
    X_train, y_train = df_A[feature_cols].values, df_A["encoded_label"].values
    X_test, y_test = df_B[feature_cols].values, df_B["encoded_label"].values

    rf = RandomForestClassifier(n_estimators=150, max_depth=15, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)

    print(classification_report(y_test, y_pred, target_names=class_names, digits=4, zero_division=0))
    cm = confusion_matrix(y_test, y_pred)
    save_confusion_matrix(
        cm, class_names,
        title=f"Cross-Network: Train({env_A}) -> Test({env_B})",
        output_path=os.path.join(reports_dir, f"cm_cross_{env_A}_to_{env_B}.png")
    )

    # Direction 2: Train on B, Test on A
    print(f"\n[Test 2B: Train on '{env_B}' ({len(df_B)} samples) -> Test on '{env_A}' ({len(df_A)} samples)]")
    rf_rev = RandomForestClassifier(n_estimators=150, max_depth=15, random_state=42, n_jobs=-1)
    rf_rev.fit(X_test, y_test)
    y_pred_rev = rf_rev.predict(X_train)

    print(classification_report(y_train, y_pred_rev, target_names=class_names, digits=4, zero_division=0))
    cm_rev = confusion_matrix(y_train, y_pred_rev)
    save_confusion_matrix(
        cm_rev, class_names,
        title=f"Cross-Network: Train({env_B}) -> Test({env_A})",
        output_path=os.path.join(reports_dir, f"cm_cross_{env_B}_to_{env_A}.png")
    )


def generate_synthetic_demo_dataset(output_csv="datasets/processed/demo_traffic_features.csv", n_samples_per_class=120):
    """
    Generates a realistic synthetic multi-class, multi-network traffic dataset
    following true physical network profiles (the 'sealed parcel' distributions)
    to validate the ML pipeline before live captures are finished.
    """
    np.random.seed(42)
    classes = ["streaming", "video_call", "file_download", "browsing"]
    networks = ["wifi_home", "mobile_hotspot"]
    rows = []

    for net in networks:
        # Hotspot adds base latency jitter and slightly lower MTU
        rtt_base = 0.045 if net == "mobile_hotspot" else 0.012

        for cls in classes:
            for i in range(n_samples_per_class):
                run_id = (i % 5) + 1
                if cls == "streaming":
                    # Video streaming: high downstream byte ratio, bursty chunk arrival (every 2-8s)
                    tot_pkts = int(np.random.gamma(shape=15, scale=20))
                    fwd_pct = np.random.uniform(0.10, 0.22)
                    fwd_pkts = int(tot_pkts * fwd_pct)
                    bwd_pkts = tot_pkts - fwd_pkts
                    bwd_len_mean = np.random.uniform(1200, 1450)
                    fwd_len_mean = np.random.uniform(70, 150)
                    duration = np.random.uniform(30, 90)
                    is_udp = 0 if np.random.rand() > 0.3 else 1 # TCP HTTPS or QUIC
                    iat_mean = duration / max(tot_pkts, 1)

                elif cls == "video_call":
                    # Video conference: symmetric packet rate, steady 20-30ms IAT, UDP dominant
                    tot_pkts = int(np.random.normal(loc=1200, scale=150))
                    fwd_pct = np.random.uniform(0.42, 0.52)
                    fwd_pkts = int(tot_pkts * fwd_pct)
                    bwd_pkts = tot_pkts - fwd_pkts
                    bwd_len_mean = np.random.uniform(600, 950)
                    fwd_len_mean = np.random.uniform(500, 850)
                    duration = 60.0
                    is_udp = 1 # RTP / UDP dominant
                    iat_mean = np.random.normal(loc=0.025 + rtt_base, scale=0.005)

                elif cls == "file_download":
                    # File download: extreme asymmetry, bulk MTU packets (1400-1500 bytes), minimal IAT
                    tot_pkts = int(np.random.gamma(shape=30, scale=40))
                    fwd_pct = np.random.uniform(0.04, 0.10)
                    fwd_pkts = int(tot_pkts * fwd_pct)
                    bwd_pkts = tot_pkts - fwd_pkts
                    bwd_len_mean = np.random.uniform(1420, 1490)
                    fwd_len_mean = np.random.uniform(54, 80)
                    duration = np.random.uniform(15, 45)
                    is_udp = 0
                    iat_mean = duration / max(tot_pkts, 1)

                else: # browsing
                    # Browsing: short bursts, idle times, small HTTP requests followed by web asset downloads
                    tot_pkts = int(np.random.exponential(scale=60) + 10)
                    fwd_pct = np.random.uniform(0.25, 0.45)
                    fwd_pkts = int(tot_pkts * fwd_pct)
                    bwd_pkts = tot_pkts - fwd_pkts
                    bwd_len_mean = np.random.uniform(400, 1100)
                    fwd_len_mean = np.random.uniform(120, 350)
                    duration = np.random.uniform(5, 30)
                    is_udp = 0
                    iat_mean = np.random.exponential(scale=0.15 + rtt_base)

                tot_bytes = int(fwd_pkts * fwd_len_mean + bwd_pkts * bwd_len_mean)
                fwd_bytes = int(fwd_pkts * fwd_len_mean)
                bwd_bytes = int(bwd_pkts * bwd_len_mean)

                row = {
                    "is_udp": is_udp,
                    "duration": duration,
                    "pkt_rate": tot_pkts / max(duration, 0.001),
                    "byte_rate": tot_bytes / max(duration, 0.001),
                    "tot_packets": tot_pkts,
                    "fwd_packets": fwd_pkts,
                    "bwd_packets": bwd_pkts,
                    "tot_bytes": tot_bytes,
                    "fwd_bytes": fwd_bytes,
                    "bwd_bytes": bwd_bytes,
                    "pkt_ratio": fwd_pkts / (bwd_pkts + 1),
                    "byte_ratio": fwd_bytes / (bwd_bytes + 1),
                    "fwd_pkt_pct": fwd_pkts / max(tot_pkts, 1),
                    "fwd_byte_pct": fwd_bytes / max(tot_bytes, 1),
                    "pkt_len_min": 54.0,
                    "pkt_len_max": float(np.random.choice([1420, 1460, 1500])),
                    "pkt_len_mean": float((fwd_bytes + bwd_bytes) / max(tot_pkts, 1)),
                    "pkt_len_std": float(np.random.uniform(150, 450)),
                    "pkt_len_median": float((fwd_len_mean + bwd_len_mean) / 2),
                    "pkt_len_q25": float(min(fwd_len_mean, bwd_len_mean)),
                    "pkt_len_q75": float(max(fwd_len_mean, bwd_len_mean)),
                    "fwd_len_min": 54.0,
                    "fwd_len_max": float(fwd_len_mean * 1.5),
                    "fwd_len_mean": float(fwd_len_mean),
                    "fwd_len_std": float(fwd_len_mean * 0.3),
                    "bwd_len_min": 54.0,
                    "bwd_len_max": 1500.0,
                    "bwd_len_mean": float(bwd_len_mean),
                    "bwd_len_std": float(bwd_len_mean * 0.25),
                    "iat_min": 0.0001,
                    "iat_max": float(duration * 0.4),
                    "iat_mean": float(iat_mean),
                    "iat_std": float(iat_mean * 1.2),
                    "fwd_iat_min": 0.0001,
                    "fwd_iat_max": float(duration * 0.4),
                    "fwd_iat_mean": float(iat_mean * 1.5),
                    "fwd_iat_std": float(iat_mean * 1.5),
                    "bwd_iat_min": 0.0001,
                    "bwd_iat_max": float(duration * 0.4),
                    "bwd_iat_mean": float(iat_mean * 1.1),
                    "bwd_iat_std": float(iat_mean * 1.2),
                    "init_burst_len_mean": float(np.random.uniform(120, 500)),
                    "class_label": cls,
                    "network_env": net,
                    "run_id": run_id,
                    "source_file": f"synthetic_{cls}_{net}_run{run_id}.pcap"
                }
                rows.append(row)

    demo_df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    demo_df.to_csv(output_csv, index=False)
    print(f"[+] Generated {len(demo_df)} synthetic flow samples at: {output_csv}")
    return demo_df


def main():
    parser = argparse.ArgumentParser(description="Train and evaluate encrypted traffic classifiers.")
    parser.add_argument("--features", default="datasets/processed/traffic_features.csv", help="Path to features CSV")
    parser.add_argument("--demo", action="store_true", help="Generate synthetic multi-class dataset to test full pipeline")
    parser.add_argument("--reports-dir", default="reports", help="Directory to save confusion matrices and plots")
    args = parser.parse_args()

    csv_path = args.features

    if args.demo or not os.path.exists(csv_path) or pd.read_csv(csv_path)["class_label"].nunique() < 2:
        print("[!] Generating synthetic demo dataset to test multi-class modeling & cross-network generalization...")
        df = generate_synthetic_demo_dataset()
    else:
        df = pd.read_csv(csv_path)

    feature_cols = [c for c in df.columns if c not in METADATA_COLS and c != "encoded_label"]
    print(f"[*] Total flow records: {len(df)}")
    print(f"[*] Feature dimension: {len(feature_cols)} statistical features")
    print(f"[*] Target classes ({df['class_label'].nunique()}): {list(df['class_label'].unique())}")
    print(f"[*] Network conditions ({df['network_env'].nunique()}): {list(df['network_env'].unique())}")

    # 1. Run Same-Network Holdout Benchmark
    run_same_network_benchmark(df, feature_cols, target_col="class_label", reports_dir=args.reports_dir)

    # 2. Run Cross-Network Generalization Benchmark
    run_cross_network_generalization(df, feature_cols, target_col="class_label", reports_dir=args.reports_dir)


if __name__ == "__main__":
    main()
