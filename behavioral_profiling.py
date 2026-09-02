import pandas as pd
from pathlib import Path
import joblib
import sys

from feature_engineering import engineer_features, get_feature_matrix

def main():
    file_path = Path("data/access_logs.csv")
    if not file_path.exists():
        print(f"Error: File {file_path} not found.")
        print("Please start the Flask app ('python app.py') and run the simulator ('python simulator/traffic_simulator.py --fast') first.")
        return

    # Load models
    models_dir = Path("models")
    iforest_path = models_dir / "isolation_forest.joblib"
    classifier_path = models_dir / "attack_classifier.joblib"
    scaler_path = models_dir / "scaler.joblib"

    if not iforest_path.exists() or not classifier_path.exists():
        print("Error: Persisted models not found in 'models/'. Please run 'train_models.py' first.")
        return

    # Read the dataset
    df = pd.read_csv(file_path)

    # Display total number of rows and columns
    print("--- Shape ---")
    print(f"Rows: {df.shape[0]}, Columns: {df.shape[1]}")
    print()

    # Display first 5 rows
    print("--- First 5 Rows ---")
    print(df.head())
    print()

    # Display list of column names
    print("--- Column Names ---")
    print(df.columns.tolist())
    print()

    # Display data types of each column
    print("--- Data Types ---")
    print(df.dtypes)
    print()

    # Display number of missing values in each column
    print("--- Missing Values ---")
    print(df.isnull().sum())
    print()

    # --- FEATURE ENGINEERING ---
    print("Running feature engineering...")
    df_featured = engineer_features(df)
    X = get_feature_matrix(df_featured)

    # Print the earlist and latest timestamps
    print("--- Timestamp Range ---")
    print(f"Earliest Timestamp: {df_featured['Timestamp'].min()}")
    print(f"Latest Timestamp:   {df_featured['Timestamp'].max()}")
    print()

    # Print the first 10 rows showing only these columns
    columns_to_show = [
        "Timestamp",
        "Hour",
        "DayOfWeek",
        "IsWeekend",
        "HTTP_Status",
        "IsSuccess",
        "IsFailure",
        "HTTP_Method",
        "HTTP_Method_Encoded"
    ]
    print("--- First 10 Rows (Derived Features) ---")
    print(df_featured[columns_to_show].head(10))
    print()

    # Print the value counts
    print("--- Value Counts for Hour ---")
    print(df_featured["Hour"].value_counts())
    print()

    print("--- Value Counts for DayOfWeek ---")
    print(df_featured["DayOfWeek"].value_counts())
    print()

    print("--- Value Counts for HTTP_Method_Encoded ---")
    print(df_featured["HTTP_Method_Encoded"].value_counts())
    print()

    print("--- Value Counts for IsSuccess ---")
    print(df_featured["IsSuccess"].value_counts())
    print()

    print("--- Value Counts for IsFailure ---")
    print(df_featured["IsFailure"].value_counts())
    print()

    print(df_featured["HTTP_Status"].value_counts())
    print()

    # Print the first 10 rows containing only these new behavioral features
    behavioral_cols = [
        "Requests_Per_User",
        "Requests_Per_IP",
        "Requests_Per_Session",
        "Unique_Endpoints_Per_User",
        "Failure_Rate_Per_User",
        "Average_Response_Time_User"
    ]
    print("--- First 10 Rows (New Behavioral Features) ---")
    print(df_featured[behavioral_cols].head(10).to_string(index=False))
    print()

    # Print descriptive statistics for all numeric behavioral features
    print("--- Descriptive Statistics (Behavioral Features) ---")
    print(df_featured[behavioral_cols].describe().to_string())
    print()

    # Load persisted models
    print("Loading persisted models...")
    iforest = joblib.load(iforest_path)
    classifier = joblib.load(classifier_path)
    scaler = joblib.load(scaler_path) if scaler_path.exists() else None

    # Predict anomalies using the Isolation Forest model
    df_featured["Anomaly_Label"] = iforest.predict(X)

    # Initialize all Attack_Type predictions as Normal
    df_featured["Attack_Type"] = "Normal"

    # Identify anomalies for supervised classification
    anomaly_mask = df_featured["Anomaly_Label"] == -1
    num_anomalies = anomaly_mask.sum()
    
    if num_anomalies > 0:
        print(f"Passing {num_anomalies} anomalous requests through supervised attack classifier...")
        X_anomalous = X[anomaly_mask]
        
        if scaler is not None:
            X_anomalous_scaled = scaler.transform(X_anomalous)
            attack_preds = classifier.predict(X_anomalous_scaled)
        else:
            attack_preds = classifier.predict(X_anomalous)
            
        df_featured.loc[anomaly_mask, "Attack_Type"] = attack_preds

    # Count normal (1) and anomalous (-1) requests
    total_normal = (df_featured["Anomaly_Label"] == 1).sum()
    total_anomalous = (df_featured["Anomaly_Label"] == -1).sum()
    
    print("\n--- Model Predictions ---")
    print(f"Total normal requests:    {total_normal}")
    print(f"Total anomalous requests: {total_anomalous}")
    print()
    
    print("--- Value Counts of Anomaly_Label ---")
    print(df_featured["Anomaly_Label"].value_counts().to_string())
    print()

    print("--- Value Counts of Attack_Type ---")
    print(df_featured["Attack_Type"].value_counts().to_string())
    print()
    
    # First 20 rows showing specific columns
    show_cols = [
        "Username",
        "Endpoint",
        "HTTP_Status",
        "Response_Time_ms",
        "Failure_Rate_Per_User",
        "Anomaly_Label",
        "Attack_Type"
    ]
    print("--- First 20 Rows with Anomaly & Attack Labels ---")
    print(df_featured[show_cols].head(20).to_string(index=False))
    print()

    # Filter only anomalous requests
    anomalous_df = df_featured[df_featured["Anomaly_Label"] == -1]
    
    # Columns to show for anomalous requests
    anomaly_show_cols = [
        "Username",
        "Client_IP",
        "Endpoint",
        "HTTP_Status",
        "Response_Time_ms",
        "Failure_Rate_Per_User",
        "Requests_Per_User",
        "Requests_Per_IP",
        "Anomaly_Label",
        "Attack_Type"
    ]
    
    if len(anomalous_df) > 0:
        print("--- First 20 Anomalous Requests ---")
        print(anomalous_df[anomaly_show_cols].head(20).to_string(index=False))
        print()
    else:
        print("--- No Anomalous Requests Detected ---")
        print()

    # Anomaly summary calculations
    total_requests = len(df_featured)
    percent_anomalous = (total_anomalous / total_requests) * 100
    
    print("--- Anomaly Summary ---")
    print(f"Total requests:             {total_requests}")
    print(f"Total normal requests:      {total_normal}")
    print(f"Total anomalous requests:   {total_anomalous}")
    print(f"Percentage of anomalies:    {percent_anomalous:.2f}%")
    print()

    if len(anomalous_df) > 0:
        # Top 10 users with the highest number of anomalous requests
        print("--- Top 10 Users with Highest Number of Anomalies ---")
        print(anomalous_df["Username"].value_counts().head(10).to_string())
        print()

        # Endpoints with the highest number of anomalous requests
        print("--- Endpoints with Highest Number of Anomalies ---")
        print(anomalous_df["Endpoint"].value_counts().to_string())
        print()

        print("\n--- Sample Anomalies Sorted by Response Time ---")
        print(
            anomalous_df.sort_values(
                by="Response_Time_ms",
                ascending=False
            )[[
                "Username",
                "Endpoint",
                "Response_Time_ms",
                "Failure_Rate_Per_User",
                "Anomaly_Label",
                "Attack_Type"
            ]].head(10).to_string(index=False)
        )

    # Save the complete dataframe to data/anomaly_results.csv
    output_path = Path("data/anomaly_results.csv")
    df_featured.to_csv(output_path, index=False)
    print(f"\nSuccessfully saved complete inference results to {output_path}")
    print()

if __name__ == "__main__":
    main()
