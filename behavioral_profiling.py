import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest

def main():
    file_path = Path("data/access_logs.csv")
    if not file_path.exists():
        print(f"Error: File {file_path} not found.")
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

    # Convert the Timestamp column into pandas datetime format
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])

    # Print the earliest and latest timestamps in the dataset
    print("--- Timestamp Range ---")
    print(f"Earliest Timestamp: {df['Timestamp'].min()}")
    print(f"Latest Timestamp:   {df['Timestamp'].max()}")
    print()

    # --- FEATURE ENGINEERING ---

    # 1. Time-based features
    # Hour: Represents the hour of the day (0-23) the request was made.
    # Why it's useful: Attackers or automated bots often operate at unusual hours (e.g., middle of the night)
    # compared to normal business hours of human users.
    df["Hour"] = df["Timestamp"].dt.hour

    # DayOfWeek: The day of the week name (Monday, Tuesday, etc.) of the request.
    # Why it's useful: Regular users might have patterns associated with workdays, whereas attackers
    # or automated scrapers might show activity spikes on weekends.
    df["DayOfWeek"] = df["Timestamp"].dt.day_name()

    # IsWeekend: Flag indicating weekend requests (1 for Saturday/Sunday, 0 for weekdays).
    # Why it's useful: Aggregating weekend behavior highlights off-hour system probing activity.
    df["IsWeekend"] = df["Timestamp"].dt.dayofweek.isin([5, 6]).astype(int)

    # 2. HTTP Status features
    # IsSuccess: Flag indicating successful response status codes (2xx or 3xx).
    # Why it's useful: High success rates are typical for regular users browsing the application.
    df["IsSuccess"] = df["HTTP_Status"].between(200, 399).astype(int)

    # IsFailure: Flag indicating client/server failure status codes (4xx or 5xx).
    # Why it's useful: High failure rates suggest dictionary/brute-force attacks, scanner probes,
    # or attempts to access non-existent endpoints.
    df["IsFailure"] = (df["HTTP_Status"] >= 400).astype(int)

    # 3. HTTP Method encoding
    # HTTP_Method_Encoded: Numeric representation of HTTP Method (GET=0, POST=1, Other=-1).
    # Why it's useful: Allows numeric models to identify anomalies in POST vs. GET distributions,
    # such as credential stuffing bots sending a high volume of POST requests.
    df["HTTP_Method_Encoded"] = df["HTTP_Method"].apply(lambda x: 0 if x == "GET" else (1 if x == "POST" else -1))

    # 5. Behavioral Features
    # Using pandas groupby() and transform(), create the following derived attributes:
    
    # Requests_Per_User: Total number of requests made by each Username.
    # Why it's useful: Helps identify users sending abnormally high volumes of traffic.
    df["Requests_Per_User"] = df.groupby("Username")["Username"].transform("count")

    # Requests_Per_IP: Total number of requests from each Client_IP.
    # Why it's useful: Helps detect IP-based brute-forcing or scraping where multiple sessions/users are used from one IP.
    df["Requests_Per_IP"] = df.groupby("Client_IP")["Client_IP"].transform("count")

    # Requests_Per_Session: Total number of requests within each Session_ID.
    # Why it's useful: Identifies high activity within a single session, which is common in automated bots.
    df["Requests_Per_Session"] = df.groupby("Session_ID")["Session_ID"].transform("count")

    # Unique_Endpoints_Per_User: Number of distinct endpoints accessed by each Username.
    # Why it's useful: Highlights scanning behavior (accessing many unique pages) vs. normal targeted usage.
    df["Unique_Endpoints_Per_User"] = df.groupby("Username")["Endpoint"].transform("nunique")

    # Failure_Rate_Per_User: Percentage of failed requests (HTTP status >=400) for each Username.
    # Why it's useful: Flags brute-forcing attempts or scanning tools that trigger high error rates.
    df["Failure_Rate_Per_User"] = df.groupby("Username")["IsFailure"].transform("mean") * 100

    # Average_Response_Time_User: Mean Response_Time_ms for each Username.
    # Why it's useful: Detects slow-response probes or automated behavior that shifts request timing.
    df["Average_Response_Time_User"] = df.groupby("Username")["Response_Time_ms"].transform("mean")

    # 4. Print the first 10 rows showing only these columns
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
    print(df[columns_to_show].head(10))
    print()

    # 5. Print the value counts
    print("--- Value Counts for Hour ---")
    print(df["Hour"].value_counts())
    print()

    print("--- Value Counts for DayOfWeek ---")
    print(df["DayOfWeek"].value_counts())
    print()

    print("--- Value Counts for HTTP_Method_Encoded ---")
    print(df["HTTP_Method_Encoded"].value_counts())
    print()

    print("--- Value Counts for IsSuccess ---")
    print(df["IsSuccess"].value_counts())
    print()

    print("--- Value Counts for IsFailure ---")
    print(df["IsFailure"].value_counts())
    print()

    print(df["HTTP_Status"].value_counts())
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
    print(df[behavioral_cols].head(10).to_string(index=False))
    print()

    # Print descriptive statistics (describe()) for all numeric behavioral features
    print("--- Descriptive Statistics (Behavioral Features) ---")
    print(df[behavioral_cols].describe().to_string())
    print()

    # Create a new dataframe named X containing only the specified columns
    x_columns = [
        "Hour",
        "IsWeekend",
        "HTTP_Method_Encoded",
        "HTTP_Status",
        "Response_Time_ms",
        "IsFailure",
        "Requests_Per_User",
        "Requests_Per_IP",
        "Requests_Per_Session",
        "Unique_Endpoints_Per_User",
        "Failure_Rate_Per_User",
        "Average_Response_Time_User"
    ]
    X = df[x_columns].copy()

    # Print the shape of X, the column names, and the first 10 rows of X
    print("--- Shape of X ---")
    print(X.shape)
    print()

    print("--- Column Names of X ---")
    print(X.columns.tolist())
    print()

    print("--- First 10 Rows of X ---")
    print(X.head(10).to_string(index=False))
    print()

    # Create the Isolation Forest model
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    
    # Fit the model on X
    clf.fit(X)
    
    # Generate predictions and store them in df
    df["Anomaly_Label"] = clf.predict(X)
    
    # Count normal (1) and anomalous (-1) requests
    total_normal = (df["Anomaly_Label"] == 1).sum()
    total_anomalous = (df["Anomaly_Label"] == -1).sum()
    
    print("--- Isolation Forest Predictions ---")
    print(f"Total normal requests:    {total_normal}")
    print(f"Total anomalous requests: {total_anomalous}")
    print()
    
    print("--- Value Counts of Anomaly_Label ---")
    print(df["Anomaly_Label"].value_counts().to_string())
    print()
    
    # First 20 rows showing specific columns
    show_cols = [
        "Username",
        "Endpoint",
        "HTTP_Status",
        "Response_Time_ms",
        "Failure_Rate_Per_User",
        "Anomaly_Label"
    ]
    print("--- First 20 Rows with Anomaly Labels ---")
    print(df[show_cols].head(20).to_string(index=False))
    print()

    # Filter only anomalous requests
    anomalous_df = df[df["Anomaly_Label"] == -1]
    
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
        "Anomaly_Label"
    ]
    
    print("--- First 20 Anomalous Requests ---")
    print(anomalous_df[anomaly_show_cols].head(20).to_string(index=False))
    print()

    # Anomaly summary calculations
    total_requests = len(df)
    percent_anomalous = (total_anomalous / total_requests) * 100
    
    print("--- Anomaly Summary ---")
    print(f"Total requests:             {total_requests}")
    print(f"Total normal requests:      {total_normal}")
    print(f"Total anomalous requests:   {total_anomalous}")
    print(f"Percentage of anomalies:    {percent_anomalous:.2f}%")
    print()

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
            "Anomaly_Label"
        ]].head(10).to_string(index=False)
    )
    # Save the complete dataframe to data/anomaly_results.csv
    output_path = Path("data/anomaly_results.csv")
    df.to_csv(output_path, index=False)
    print(f"Successfully saved complete results to {output_path}")
    print()

if __name__ == "__main__":
    main()
