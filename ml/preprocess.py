"""
preprocess.py — Data Preprocessing for CloudGuard
Person 1's script to clean and prepare the CIC-IDS dataset.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import os

DATA_PATH = "data/"
OUTPUT_PATH = "data/"

def load_data(filename="traffic.csv"):
    path = os.path.join(DATA_PATH, filename)
    print(f"[*] Loading data from {path}...")
    df = pd.read_csv(path)
    print(f"[+] Loaded {len(df)} rows, {len(df.columns)} columns")
    return df

def clean_data(df):
    print("[*] Cleaning data...")
    # Drop duplicates and infinite values
    df = df.drop_duplicates()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    print(f"[+] After cleaning: {len(df)} rows")
    return df

def encode_labels(df, label_col="Label"):
    print("[*] Encoding labels...")
    le = LabelEncoder()
    df["label_encoded"] = le.fit_transform(df[label_col])
    print(f"[+] Classes: {list(le.classes_)}")
    return df, le

def scale_features(X_train, X_test):
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    return X_train_scaled, X_test_scaled, scaler

def preprocess(filename="traffic.csv"):
    df = load_data(filename)
    df = clean_data(df)
    df, le = encode_labels(df)

    # Save processed
    out = os.path.join(OUTPUT_PATH, "processed.csv")
    df.to_csv(out, index=False)
    print(f"[+] Saved processed data to {out}")
    return df, le

if __name__ == "__main__":
    preprocess()
