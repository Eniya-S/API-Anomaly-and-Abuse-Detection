import os
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report, confusion_matrix

from feature_engineering import engineer_features, get_feature_matrix

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_FILE = DATA_DIR / "access_logs.csv"
LABELS_FILE = DATA_DIR / "simulation_labels.csv"
MODELS_DIR = BASE_DIR / "models"

def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    if not LOG_FILE.exists():
        print(f"Error: Access logs file not found at {LOG_FILE}.")
        print("Please start the Flask app ('python app.py') and run the simulator ('python simulator/traffic_simulator.py --fast') first.")
        return

    if not LABELS_FILE.exists():
        print(f"Error: Simulation labels file not found at {LABELS_FILE}.")
        print("Please run the traffic simulator first to generate labelled training data.")
        return

    # 1. Load access logs and simulation labels
    print(f"Loading access logs from {LOG_FILE}...")
    logs_df = pd.read_csv(LOG_FILE)
    print(f"Loaded {len(logs_df)} access log records.")

    print(f"Loading simulation labels from {LABELS_FILE}...")
    labels_df = pd.read_csv(LABELS_FILE)
    print(f"Loaded {len(labels_df)} simulation label records.")

    # 2. Re-engineer features on all access logs
    print("Running feature engineering on access logs...")
    logs_featured = engineer_features(logs_df)
    X_full = get_feature_matrix(logs_featured)

    # 3. Fit Isolation Forest to identify anomalous traffic
    print("Fitting Isolation Forest model on all access logs...")
    iforest = IsolationForest(n_estimators=100, contamination=0.25, random_state=42)
    iforest.fit(X_full)
    logs_featured["Anomaly_Label"] = iforest.predict(X_full)

    # 4. Join access logs and simulation labels using Request_ID
    # We do an inner join to only keep requests that were generated and labelled by the simulator
    print("Joining access logs with simulation labels using Request_ID...")
    joined_df = pd.merge(logs_featured, labels_df, on="Request_ID", how="inner")

    # 5. Report stats before training
    total_labelled = len(joined_df)
    print("\n=============================================")
    print("TRAINING DATASET STATISTICS REPORT")
    print("=============================================")
    print(f"Total labelled simulator records: {total_labelled}")
    
    print("\nLabelled records per attack type:")
    type_counts = joined_df["Attack_Type"].value_counts()
    for attack_type, count in type_counts.items():
        print(f"  - {attack_type}: {count}")

    # Flagged as anomalies by Isolation Forest
    anomalous_joined = joined_df[joined_df["Anomaly_Label"] == -1]
    total_anomalies = len(anomalous_joined)
    print(f"\nLabelled records flagged as anomalies by Isolation Forest: {total_anomalies}")

    print("\nAnomaly counts per attack type:")
    anomaly_type_counts = anomalous_joined["Attack_Type"].value_counts()
    for attack_type, count in anomaly_type_counts.items():
        print(f"  - {attack_type}: {count}")
    print("=============================================\n")

    # 6. Check class balance & sample sufficiency
    required_classes = ["Brute_Force", "Endpoint_Scanning", "Request_Flooding"]
    insufficient = False
    for r_class in required_classes:
        count = anomaly_type_counts.get(r_class, 0)
        if count < 5:
            print(f"WARNING: Attack class '{r_class}' has insufficient training samples ({count} < 5) flagged as anomalies.")
            insufficient = True

    if insufficient:
        print("\nERROR: Cannot train the classifier due to insufficient samples for one or more attack types.")
        print("Please run the simulator ('python simulator/traffic_simulator.py --fast') again to generate more attack traffic.")
        return

    # 7. Filter labelled training data to only anomalous requests belonging to attack classes
    # (Normal requests are handled by Isolation Forest directly and not passed to classifier)
    classifier_df = anomalous_joined[anomalous_joined["Attack_Type"].isin(required_classes)].copy()
    
    X_clf = get_feature_matrix(classifier_df)
    y_clf = classifier_df["Attack_Type"]
    sessions = classifier_df["Session_ID"]

    # 8. Split train/test using GroupShuffleSplit on Session_ID to prevent data leakage
    print("Splitting dataset into train/test using GroupShuffleSplit (session-aware)...")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    try:
        train_idx, test_idx = next(gss.split(X_clf, y_clf, groups=sessions))
    except Exception as e:
        print(f"Error splitting data: {e}")
        return

    X_train, X_test = X_clf.iloc[train_idx], X_clf.iloc[test_idx]
    y_train, y_test = y_clf.iloc[train_idx], y_clf.iloc[test_idx]

    print(f"Training subset size: {len(X_train)} samples")
    print(f"Testing subset size:  {len(X_test)} samples\n")

    # 9. Train and compare models
    results = {}

    # --- Random Forest ---
    print("Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)
    y_pred_rf = rf_model.predict(X_test)
    
    acc_rf = accuracy_score(y_test, y_pred_rf)
    p_rf, r_rf, f1_rf, _ = precision_recall_fscore_support(y_test, y_pred_rf, average='weighted')
    results['Random Forest'] = {
        'model': rf_model,
        'accuracy': acc_rf,
        'precision': p_rf,
        'recall': r_rf,
        'f1': f1_rf,
        'preds': y_pred_rf
    }

    # --- Logistic Regression with scaling ---
    print("Training Logistic Regression Classifier...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    lr_model = LogisticRegression(max_iter=1000, random_state=42)
    lr_model.fit(X_train_scaled, y_train)
    y_pred_lr = lr_model.predict(X_test_scaled)
    
    acc_lr = accuracy_score(y_test, y_pred_lr)
    p_lr, r_lr, f1_lr, _ = precision_recall_fscore_support(y_test, y_pred_lr, average='weighted')
    results['Logistic Regression'] = {
        'model': lr_model,
        'scaler': scaler,
        'accuracy': acc_lr,
        'precision': p_lr,
        'recall': r_lr,
        'f1': f1_lr,
        'preds': y_pred_lr
    }

    # 10. Print Model Evaluation Report
    print("\n" + "="*45)
    print("MODEL COMPARISON REPORT")
    print("="*45)
    for model_name, metrics in results.items():
        print(f"\nModel: {model_name}")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1-Score:  {metrics['f1']:.4f}")
        print("\n  Classification Report:")
        print(classification_report(y_test, metrics['preds'], target_names=np.unique(y_test)))
        print("  Confusion Matrix:")
        print(confusion_matrix(y_test, metrics['preds']))
        print("-" * 35)

    # Feature Importance for Random Forest
    print("\nRandom Forest Feature Importances:")
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    for f in range(X_train.shape[1]):
        print(f"  {f + 1}. {X_train.columns[indices[f]]:<30} : {importances[indices[f]]:.4f}")
    print("="*45 + "\n")

    # 11. Choose the best model based on weighted F1-score
    best_name = max(results, key=lambda k: results[k]['f1'])
    best_metrics = results[best_name]
    print(f"Selected Model based on F1-score: {best_name} (F1-score: {best_metrics['f1']:.4f})")

    # Save models
    iforest_path = MODELS_DIR / "isolation_forest.joblib"
    classifier_path = MODELS_DIR / "attack_classifier.joblib"
    scaler_path = MODELS_DIR / "scaler.joblib"

    print(f"Saving Isolation Forest model to {iforest_path}...")
    joblib.dump(iforest, iforest_path)

    print(f"Saving {best_name} classifier to {classifier_path}...")
    joblib.dump(best_metrics['model'], classifier_path)

    if best_name == 'Logistic Regression':
        print(f"Saving StandardScaler to {scaler_path}...")
        joblib.dump(best_metrics['scaler'], scaler_path)
    elif scaler_path.exists():
        # Remove scaler file if Random Forest was chosen so inference does not use stale scaler
        os.remove(scaler_path)

    print("\nModel training and persistence successfully completed!")

if __name__ == "__main__":
    main()
