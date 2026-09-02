import csv
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path

import requests
from flask import session as flask_session, g


# ============================================================
# PATH / FILE SETTINGS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
SRC_DATA_DIR = BASE_DIR / "data"


def _resolve_data_dir():
    """Return a writable data directory (mirrors app.py).

    On Vercel / read-only filesystems, fall back to /tmp so log writes do not
    crash the request. Storage there is ephemeral.
    """
    if os.environ.get("VERCEL") or not os.access(BASE_DIR, os.W_OK):
        tmp = Path("/tmp/data")
        try:
            if not tmp.exists():
                if SRC_DATA_DIR.exists():
                    shutil.copytree(SRC_DATA_DIR, tmp)
                else:
                    tmp.mkdir(parents=True, exist_ok=True)
        except Exception:
            tmp.mkdir(parents=True, exist_ok=True)
        return tmp
    return SRC_DATA_DIR


DATA_DIR = _resolve_data_dir()
LOG_FILE = DATA_DIR / "access_logs.csv"


# ============================================================
# GOOGLE SHEETS WEBHOOK SETTINGS
# ============================================================

WEBHOOK_URL = os.getenv("GOOGLE_WEBHOOK_URL")
WEBHOOK_TOKEN = os.getenv("GOOGLE_WEBHOOK_TOKEN")


# ============================================================
# CSV COLUMNS
# ============================================================

EXPECTED_HEADER = [
    "Timestamp",
    "Username",
    "Client_IP",
    "Endpoint",
    "HTTP_Method",
    "HTTP_Status",
    "Response_Time_ms",
    "User_Agent",
    "Session_ID",
    "Request_ID",
]


# ============================================================
# PATHS THAT SHOULD NOT BE LOGGED
# ============================================================

IGNORED_PATH_PREFIXES = (
    "/static/",
    "/favicon.ico",
    "/hybridaction/",
)

IGNORED_PATHS = {
    "/favicon.ico",
    "/hybridaction/zybTrackerStatisticsAction",
}


# ============================================================
# ALLOWED APPLICATION ENDPOINTS
# ============================================================

ALLOWED_ENDPOINTS = {
    "/",
    "/signup",
    "/login",
    "/dashboard",
    "/profile",
    "/products",
    "/change-password",
    "/api-test",
    "/logout",
}


# ============================================================
# CLIENT IP
# ============================================================

def extract_client_ip(request):
    """
    Get client IP address.

    X-Forwarded-For is trusted only when X-Persona exists,
    which is useful for controlled/simulated project traffic.
    """

    if request.headers.get("X-Persona"):
        forwarded_for = request.headers.get("X-Forwarded-For")

        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "unknown"


# ============================================================
# CHECK WHETHER REQUEST SHOULD BE LOGGED
# ============================================================

def should_log_request(path):
    if not path:
        return False

    if path in IGNORED_PATHS:
        return False

    return not any(
        path.startswith(prefix)
        for prefix in IGNORED_PATH_PREFIXES
    )


# ============================================================
# UUID VALIDATION
# ============================================================

def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except (ValueError, TypeError, AttributeError):
        return False


# ============================================================
# SESSION ID RESOLUTION
# ============================================================

def resolve_session_id(request, session_id=None, fallback=None):
    from flask import has_request_context

    # No Flask request context
    if not has_request_context():
        if fallback:
            return fallback

        return str(uuid.uuid4())

    # --------------------------------------------------------
    # 1. Authenticated Flask session
    # --------------------------------------------------------

    if flask_session.get("user") and flask_session.get("session_id"):

        sess_id = flask_session["session_id"]

        if is_valid_uuid(sess_id):
            return sess_id

    # --------------------------------------------------------
    # 2. Simulator supplied X-Session-ID
    # --------------------------------------------------------

    x_session = request.headers.get("X-Session-ID")

    if x_session:

        if is_valid_uuid(x_session):
            return x_session

        return str(
            uuid.uuid5(
                uuid.NAMESPACE_DNS,
                x_session
            )
        )

    # --------------------------------------------------------
    # 3. Generate anonymous session ID
    # --------------------------------------------------------

    if (
        "session_id" not in flask_session
        or not is_valid_uuid(flask_session.get("session_id"))
    ):
        flask_session["session_id"] = str(uuid.uuid4())

    return flask_session["session_id"]


# ============================================================
# ENSURE CSV HEADER
# ============================================================

def _ensure_log_header():

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # Create CSV if it does not exist
    if not LOG_FILE.exists():

        with LOG_FILE.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)
            writer.writerow(EXPECTED_HEADER)

        return

    # Check existing header
    with LOG_FILE.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as file:

        try:
            header = next(csv.reader(file))

        except StopIteration:
            header = []

    # Reset header if incorrect
    if header != EXPECTED_HEADER:

        with LOG_FILE.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)
            writer.writerow(EXPECTED_HEADER)


# ============================================================
# SAVE LOG TO LOCAL CSV
# ============================================================

def _append_log_row(row):

    try:

        _ensure_log_header()

        with LOG_FILE.open(
            "a",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)
            writer.writerow(row)

    except Exception:
        # Logging failure should never break the Flask application
        pass


# ============================================================
# SEND LOG TO GOOGLE SHEETS WEBHOOK
# ============================================================

def _send_to_google_sheet(log_data):

    # Webhook URL is not configured
    if not WEBHOOK_URL:
        return

    try:

        payload = dict(log_data)

        # Add secret token if configured
        if WEBHOOK_TOKEN:
            payload["webhook_token"] = WEBHOOK_TOKEN

        response = requests.post(
            WEBHOOK_URL,
            json=payload,
            timeout=5
        )

        # Optional terminal message
        if response.status_code == 200:
            print("[GOOGLE SHEET] Log sent successfully")

        else:
            print(
                f"[GOOGLE SHEET] Failed: "
                f"HTTP {response.status_code}"
            )

    except Exception as e:

        # Google Sheet failure should never break Flask
        print(
            f"[GOOGLE SHEET] Error: {e}"
        )


# ============================================================
# MAIN REQUEST LOGGER
# ============================================================

def log_request(
    request,
    status_code,
    response_time_ms=None,
    request_id=None,
    session_id=None,
    fallback_session_id=None
):

    # --------------------------------------------------------
    # Endpoint
    # --------------------------------------------------------

    endpoint = request.path or ""

    # Ignore unnecessary requests
    if not should_log_request(endpoint):
        return

    # --------------------------------------------------------
    # Prevent duplicate logging
    # --------------------------------------------------------

    if getattr(g, "logged", False):
        return

    g.logged = True

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------------
    # Username
    # --------------------------------------------------------

    if flask_session.get("user"):

        username = flask_session["user"]

    else:

        username = (
            request.headers.get("X-User")
            or "anonymous"
        )

    # --------------------------------------------------------
    # Client IP
    # --------------------------------------------------------

    client_ip = extract_client_ip(request)

    # --------------------------------------------------------
    # HTTP method
    # --------------------------------------------------------

    method = request.method

    # --------------------------------------------------------
    # Response time
    # --------------------------------------------------------

    if response_time_ms is None:
        response_time_ms = 0.0

    response_time_ms = round(
        float(response_time_ms),
        2
    )

    # --------------------------------------------------------
    # Request ID
    # --------------------------------------------------------

    req_id = (
        request_id
        or getattr(g, "request_id", None)
        or str(uuid.uuid4())
    )

    # --------------------------------------------------------
    # Session ID
    # --------------------------------------------------------

    sess_id = resolve_session_id(
        request,
        session_id=session_id,
        fallback=fallback_session_id
    )

    # ========================================================
    # CREATE LOG ROW
    # ========================================================

    row = [
        timestamp,
        username,
        client_ip,
        endpoint,
        method,
        status_code,
        response_time_ms,
        request.headers.get(
            "User-Agent",
            "unknown"
        ),
        sess_id,
        req_id,
    ]

    # ========================================================
    # 1. SAVE TO LOCAL CSV
    # ========================================================

    _append_log_row(row)

    # ========================================================
    # 2. CONVERT TO DICTIONARY
    # ========================================================

    log_data = dict(
        zip(
            EXPECTED_HEADER,
            row
        )
    )

    # ========================================================
    # 3. SEND TO GOOGLE SHEETS
    # ========================================================

    _send_to_google_sheet(log_data)

    # ========================================================
    # TERMINAL LOG
    # ========================================================

    print(
        f"[API LOG] "
        f"{method} {endpoint} | "
        f"IP={client_ip} | "
        f"User={username} | "
        f"Status={status_code} | "
        f"{response_time_ms} ms"
    )