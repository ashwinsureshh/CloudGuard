"""
preprocess.py — Data Preprocessing for CloudGuard
Loads and merges all CIC-IDS2017 CSV files, cleans, and encodes labels.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
import os
import glob

DATA_PATH = "data/"
OUTPUT_PATH = "data/"

# Map verbose CIC-IDS2017 label names → short attack types
LABEL_MAP = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Bot": "BruteForce",
    "Web Attack \x96 Brute Force": "BruteForce",
    "Web Attack – Brute Force": "BruteForce",
    "Web Attack \x96 XSS": "Infiltration",
    "Web Attack – XSS": "Infiltration",
    "Web Attack \x96 Sql Injection": "Infiltration",
    "Web Attack – Sql Injection": "Infiltration",
    "Infiltration": "Infiltration",
    "Heartbleed": "Infiltration",
}

def load_all_csvs():
    """Load and concatenate all CSV files from data/"""
    files = sorted(glob.glob(os.path.join(DATA_PATH, "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {DATA_PATH}")

    print(f"[*] Found {len(files)} CSV files:")
    dfs = []
    for f in files:
        print(f"    Loading {os.path.basename(f)}...")
        df = pd.read_csv(f, low_memory=False)
        # Strip leading/trailing whitespace from column names (CIC-IDS2017 quirk)
        df.columns = df.columns.str.strip()
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    print(f"[+] Total rows loaded: {len(combined):,}, columns: {len(combined.columns)}")
    return combined

def clean_data(df):
    print("[*] Cleaning data...")
    df = df.drop_duplicates()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    # Drop non-numeric columns except Label
    non_numeric = [c for c in df.columns if c != "Label" and df[c].dtype == object]
    if non_numeric:
        print(f"    Dropping non-numeric columns: {non_numeric}")
        df = df.drop(columns=non_numeric)
    print(f"[+] After cleaning: {len(df):,} rows")
    return df

def encode_labels(df, label_col="Label"):
    print("[*] Encoding labels...")
    # Normalize verbose labels → short attack types
    df[label_col] = df[label_col].map(lambda x: LABEL_MAP.get(str(x).strip(), "Other"))
    df = df[df[label_col] != "Other"]  # drop unmapped
    le = LabelEncoder()
    df = df.copy()
    df["label_encoded"] = le.fit_transform(df[label_col])
    print(f"[+] Classes: {list(le.classes_)}")
    print(f"[+] Class distribution:\n{df[label_col].value_counts()}")
    return df, le

def preprocess():
    df = load_all_csvs()
    df = clean_data(df)
    df, le = encode_labels(df)

    out = os.path.join(OUTPUT_PATH, "processed.csv")
    df.to_csv(out, index=False)
    print(f"[+] Saved processed data to {out}")
    return df, le

if __name__ == "__main__":
    preprocess()
