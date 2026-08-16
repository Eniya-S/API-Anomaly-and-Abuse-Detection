import pandas as pd

FEATURE_COLUMNS = [
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

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Applies the same feature engineering logic to the raw access logs DataFrame.
    Returns the DataFrame with all engineered features added.
    """
    df = df.copy()
    
    # Fill missing values to avoid errors
    df["Username"] = df["Username"].fillna("anonymous")
    df["Client_IP"] = df["Client_IP"].fillna("127.0.0.1")
    df["Session_ID"] = df["Session_ID"].fillna("unknown")
    df["Endpoint"] = df["Endpoint"].fillna("/")
    df["HTTP_Method"] = df["HTTP_Method"].fillna("GET")
    df["HTTP_Status"] = pd.to_numeric(df["HTTP_Status"], errors="coerce").fillna(200).astype(int)
    df["Response_Time_ms"] = pd.to_numeric(df["Response_Time_ms"], errors="coerce").fillna(0.0)

    # Convert Timestamp
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    
    # 1. Time-based features
    df["Hour"] = df["Timestamp"].dt.hour
    df["DayOfWeek"] = df["Timestamp"].dt.day_name()
    df["IsWeekend"] = df["Timestamp"].dt.dayofweek.isin([5, 6]).astype(int)
    
    # 2. HTTP Status features
    df["IsSuccess"] = df["HTTP_Status"].between(200, 399).astype(int)
    df["IsFailure"] = (df["HTTP_Status"] >= 400).astype(int)
    
    # 3. HTTP Method encoding
    df["HTTP_Method_Encoded"] = df["HTTP_Method"].apply(lambda x: 0 if x == "GET" else (1 if x == "POST" else -1))
    
    # 4. Behavioral Features
    df["Requests_Per_User"] = df.groupby("Username")["Username"].transform("count")
    df["Requests_Per_IP"] = df.groupby("Client_IP")["Client_IP"].transform("count")
    df["Requests_Per_Session"] = df.groupby("Session_ID")["Session_ID"].transform("count")
    df["Unique_Endpoints_Per_User"] = df.groupby("Username")["Endpoint"].transform("nunique")
    df["Failure_Rate_Per_User"] = df.groupby("Username")["IsFailure"].transform("mean") * 100
    df["Average_Response_Time_User"] = df.groupby("Username")["Response_Time_ms"].transform("mean")
    
    return df

def get_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns the subset of columns required for modeling, in the exact expected order.
    """
    return df[FEATURE_COLUMNS].copy()
