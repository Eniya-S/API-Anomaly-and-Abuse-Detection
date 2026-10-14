import json
import os
import warnings

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.base import clone
from sklearn.model_selection import train_test_split, StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier

warnings.filterwarnings("ignore")

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

DATA_PATH = "data/request_features.csv"
OUTPUT_DIR = "data"

LABEL_COL = "label"

FEATURES = [
    "url_length",
    "path_length",
    "path_depth",
    "query_param_count",
    "encoded_char_count",
    "special_char_count",
    "encoded_ratio",
    "special_char_ratio",
    "query_length",
    "request_header_count",
    "user_agent_length",
    "total_header_length",
    "max_header_value_length",
    "body_length",
    "dollar_count",
    "brace_count",
    "expression_count",
    "jndi_count",
    "status_code",
    "response_body_length",
    "response_header_count",
    "response_body_to_url_ratio",
    "method_encoded",
]

RANDOM_STATE = 42
TEST_SIZE = 0.20

os.makedirs(OUTPUT_DIR, exist_ok=True)

# --------------------------------------------------
# LOAD AND PREPARE DATA
# --------------------------------------------------

def load_data():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}\n"
            "Make sure request_features.csv exists in the data folder."
        )

    df = pd.read_csv(DATA_PATH)

    missing_columns = [
        col for col in FEATURES + [LABEL_COL]
        if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing columns in dataset: {missing_columns}"
        )

    df = df[FEATURES + [LABEL_COL]].copy()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=[LABEL_COL])

    for col in FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df[FEATURES] = df[FEATURES].fillna(
        df[FEATURES].median()
    )

    df[LABEL_COL] = df[LABEL_COL].astype(str)

    print("\nDataset loaded successfully")
    print(f"Total rows: {len(df)}")
    print("\nClass distribution:")
    print(df[LABEL_COL].value_counts())

    return df


# --------------------------------------------------
# DEFINE MODELS
# --------------------------------------------------

def get_models():
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),

        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced",
            random_state=RANDOM_STATE,
        ),

        "SVM": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", SVC(
                kernel="rbf",
                class_weight="balanced",
                random_state=RANDOM_STATE,
            )),
        ]),

        # KNN does not support sample_weight in fit().
        # Scaling is important because KNN uses distances.
        "KNN": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", KNeighborsClassifier(
                n_neighbors=5,
                weights="distance",
            )),
        ]),
    }

    try:
        from xgboost import XGBClassifier

        models["XGBoost"] = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )

    except ImportError:
        print("\nXGBoost not installed; skipping XGBoost.")

    return models


# --------------------------------------------------
# SPLIT DATA
# --------------------------------------------------

def make_row_split(df):
    X = df[FEATURES]
    y = df[LABEL_COL]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    return X_train, X_test, y_train, y_test


def make_group_split(df):

    X = df[FEATURES]
    y = df[LABEL_COL]

    group_ids = pd.util.hash_pandas_object(
        X,
        index=False,
    ).astype(str)

    splitter = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    try:
        train_idx, test_idx = next(
            splitter.split(X, y, groups=group_ids)
        )

        X_train = X.iloc[train_idx]
        X_test = X.iloc[test_idx]
        y_train = y.iloc[train_idx]
        y_test = y.iloc[test_idx]

        train_groups = set(group_ids.iloc[train_idx])
        test_groups = set(group_ids.iloc[test_idx])

        if train_groups.intersection(test_groups):
            raise ValueError(
                "Duplicate feature groups overlap between train and test."
            )

        return X_train, X_test, y_train, y_test

    except ValueError as exc:
        print(
            "\nGrouped split unavailable for this dataset:",
            exc,
        )
        print("Falling back to the stratified row split.")

        return make_row_split(df)


# --------------------------------------------------
# EVALUATE MODEL
# --------------------------------------------------

def evaluate_model(
    model_name,
    model,
    X_train,
    X_test,
    y_train,
    y_test,
    split_name,
):
    print(f"\nEvaluating {model_name} [{split_name}]...")

    fitted_model = clone(model)

    # Encode labels for XGBoost compatibility.
    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)
    y_test_encoded = label_encoder.transform(y_test)

    fitted_model.fit(X_train, y_train_encoded)
    predictions_encoded = fitted_model.predict(X_test).astype(int)

    predictions = label_encoder.inverse_transform(
        predictions_encoded
    )

    # Use only classes that actually occur in the test set
    # for macro and weighted metrics.
    accuracy = accuracy_score(y_test, predictions)

    precision_macro = precision_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    )

    recall_macro = recall_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    )

    f1_macro = f1_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    )

    precision_weighted = precision_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0,
    )

    recall_weighted = recall_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0,
    )

    f1_weighted = f1_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0,
    )

    labels = sorted(
        set(y_test.astype(str)) |
        set(pd.Series(predictions).astype(str))
    )

    report = classification_report(
        y_test,
        predictions,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )

    cm = confusion_matrix(
        y_test,
        predictions,
        labels=labels,
    )

    metrics = {
        "model": model_name,
        "split": split_name,
        "accuracy": accuracy,
        "precision_macro": precision_macro,
        "recall_macro": recall_macro,
        "f1_macro": f1_macro,
        "precision_weighted": precision_weighted,
        "recall_weighted": recall_weighted,
        "f1_weighted": f1_weighted,
    }

    print(f"Accuracy:          {accuracy:.4f}")
    print(f"Macro Precision:   {precision_macro:.4f}")
    print(f"Macro Recall:      {recall_macro:.4f}")
    print(f"Macro F1:          {f1_macro:.4f}")
    print(f"Weighted F1:       {f1_weighted:.4f}")

    return metrics, report, cm, labels


# --------------------------------------------------
# SAVE CONFUSION MATRIX
# --------------------------------------------------

def save_confusion_matrix(
    model_name,
    split_name,
    cm,
    labels,
):
    safe_model_name = (
        model_name.lower()
        .replace(" ", "_")
        .replace("/", "_")
    )

    safe_split_name = split_name.lower().replace(" ", "_")

    matrix_dir = os.path.join(
        OUTPUT_DIR,
        "model_comparison_confusion_matrices",
    )

    os.makedirs(matrix_dir, exist_ok=True)

    base_name = f"{safe_model_name}_{safe_split_name}"

    cm_df = pd.DataFrame(
        cm,
        index=labels,
        columns=labels,
    )

    cm_df.to_csv(
        os.path.join(matrix_dir, f"{base_name}.csv")
    )

    plt.figure(figsize=(10, 8))
    plt.imshow(cm, interpolation="nearest")
    plt.title(f"{model_name} - {split_name}")
    plt.colorbar()

    positions = np.arange(len(labels))

    plt.xticks(
        positions,
        labels,
        rotation=45,
        ha="right",
    )

    plt.yticks(positions, labels)
    plt.xlabel("Predicted Label")
    plt.ylabel("Actual Label")
    plt.tight_layout()

    plt.savefig(
        os.path.join(matrix_dir, f"{base_name}.png"),
        dpi=200,
        bbox_inches="tight",
    )

    plt.close()


# --------------------------------------------------
# MAIN EXECUTION
# --------------------------------------------------

def main():
    df = load_data()

    # Preserve the original approach: split first, then remove
    # Normal records from the training and test sets.
    X_train, X_test, y_train, y_test = make_row_split(df)

    normal_labels = {"normal"}

    train_mask = ~y_train.str.lower().isin(normal_labels)
    test_mask = ~y_test.str.lower().isin(normal_labels)

    X_train = X_train.loc[train_mask]
    y_train = y_train.loc[train_mask]

    X_test = X_test.loc[test_mask]
    y_test = y_test.loc[test_mask]

    if y_train.nunique() < 2:
        raise ValueError(
            "Training data must contain at least two attack classes."
        )

    if len(X_test) == 0:
        raise ValueError(
            "No test rows remain after removing Normal records."
        )

    print("\nRow split after removing Normal records:")
    print(f"Training rows: {len(X_train)}")
    print(f"Testing rows:  {len(X_test)}")

    models = get_models()

    all_metrics = []
    all_reports = {}
    all_matrices = {}
    all_per_class = {}

    # Evaluate on the original stratified split.
    splits = {
        "row_split": (X_train, X_test, y_train, y_test)
    }

    # Also evaluate a grouped split, when feasible.
    try:
        grouped = make_group_split(df)

        GX_train, GX_test, Gy_train, Gy_test = grouped

        g_train_mask = ~Gy_train.str.lower().isin(normal_labels)
        g_test_mask = ~Gy_test.str.lower().isin(normal_labels)

        GX_train = GX_train.loc[g_train_mask]
        Gy_train = Gy_train.loc[g_train_mask]

        GX_test = GX_test.loc[g_test_mask]
        Gy_test = Gy_test.loc[g_test_mask]

        if (
            len(GX_train) > 0
            and len(GX_test) > 0
            and Gy_train.nunique() >= 2
        ):
            splits["grouped_split"] = (
                GX_train,
                GX_test,
                Gy_train,
                Gy_test,
            )

    except Exception as exc:
        print(f"\nSkipping grouped evaluation: {exc}")

    for split_name, split_data in splits.items():
        Xtr, Xte, ytr, yte = split_data

        # Ensure each test class is present in training.
        missing_classes = set(yte.unique()) - set(ytr.unique())

        if missing_classes:
            print(
                f"\nSkipping {split_name}: test classes absent "
                f"from training: {sorted(missing_classes)}"
            )
            continue

        for model_name, model in models.items():
            try:
                metrics, report, cm, labels = evaluate_model(
                    model_name,
                    model,
                    Xtr,
                    Xte,
                    ytr,
                    yte,
                    split_name,
                )

                all_metrics.append(metrics)

                key = f"{split_name}::{model_name}"

                all_reports[key] = report
                all_matrices[key] = {
                    "labels": labels,
                    "matrix": cm.tolist(),
                }

                for label in labels:
                    if label in report:
                        class_result = report[label]

                        if isinstance(class_result, dict):
                            all_per_class[key + "::" + label] = {
                                "model": model_name,
                                "split": split_name,
                                "class": label,
                                "precision": class_result.get(
                                    "precision", 0
                                ),
                                "recall": class_result.get(
                                    "recall", 0
                                ),
                                "f1-score": class_result.get(
                                    "f1-score", 0
                                ),
                                "support": class_result.get(
                                    "support", 0
                                ),
                            }

                save_confusion_matrix(
                    model_name,
                    split_name,
                    cm,
                    labels,
                )

            except Exception as exc:
                print(
                    f"\nError evaluating {model_name} "
                    f"on {split_name}: {exc}"
                )

    # --------------------------------------------------
    # SAVE RESULTS
    # --------------------------------------------------

    if not all_metrics:
        raise RuntimeError(
            "No models completed successfully. "
            "Check the errors printed above."
        )

    metrics_df = pd.DataFrame(all_metrics)

    metrics_df.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "model_comparison_results.csv",
        ),
        index=False,
    )

    per_class_df = pd.DataFrame(
        list(all_per_class.values())
    )

    per_class_df.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "model_comparison_per_class_metrics.csv",
        ),
        index=False,
    )

    with open(
        os.path.join(
            OUTPUT_DIR,
            "model_comparison_classification_reports.json",
        ),
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(all_reports, file, indent=4)

    with open(
        os.path.join(
            OUTPUT_DIR,
            "model_comparison_confusion_matrices.json",
        ),
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(all_matrices, file, indent=4)

    # --------------------------------------------------
    # METRICS COMPARISON GRAPH
    # --------------------------------------------------

    plot_df = metrics_df.copy()

    plot_df["model_label"] = (
        plot_df["model"] + "\n(" + plot_df["split"] + ")"
    )

    ax = plot_df.set_index("model_label")[
        ["accuracy", "precision_macro", "recall_macro", "f1_macro"]
    ].plot(
        kind="bar",
        figsize=(14, 7),
    )

    ax.set_title("Model Performance Comparison")
    ax.set_xlabel("Model and Split")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1)
    ax.legend(loc="lower right")
    plt.xticks(rotation=35, ha="right")
    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_DIR,
            "model_comparison_metrics_comparison.png",
        ),
        dpi=200,
        bbox_inches="tight",
    )

    plt.close()

    print("\n" + "=" * 60)
    print("MODEL COMPARISON RESULTS")
    print("=" * 60)

    print(
        metrics_df.sort_values(
            by="f1_macro",
            ascending=False,
        ).to_string(index=False)
    )

    print("\nSaved results:")
    print(" - data/model_comparison_results.csv")
    print(" - data/model_comparison_per_class_metrics.csv")
    print(" - data/model_comparison_classification_reports.json")
    print(" - data/model_comparison_confusion_matrices.json")
    print(" - data/model_comparison_metrics_comparison.png")
    print(" - data/model_comparison_confusion_matrices/")


if __name__ == "__main__":
    main()