"""
train_model.py — Model Training for CloudGuard
Person 1's script to train and export the intrusion detection model.
"""

import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from preprocess import preprocess, scale_features

MODEL_PATH = "model/"

def train(data_file="traffic.csv"):
    df, le = preprocess(data_file)

    label_col = "label_encoded"
    feature_cols = [c for c in df.columns if c not in ["Label", label_col]]

    X = df[feature_cols].values
    y = df[label_col].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    X_train, X_test, scaler = scale_features(X_train, X_test)

    print("[*] Training Random Forest model...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        n_jobs=-1,
        random_state=42
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n[+] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Save model artifacts
    os.makedirs(MODEL_PATH, exist_ok=True)
    with open(os.path.join(MODEL_PATH, "model.pkl"), "wb") as f:
        pickle.dump(clf, f)
    with open(os.path.join(MODEL_PATH, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    with open(os.path.join(MODEL_PATH, "label_encoder.pkl"), "wb") as f:
        pickle.dump(le, f)
    with open(os.path.join(MODEL_PATH, "feature_cols.pkl"), "wb") as f:
        pickle.dump(feature_cols, f)

    print(f"[+] Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
