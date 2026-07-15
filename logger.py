import csv
import uuid
from datetime import datetime
from pathlib import Path

from flask import session as flask_session, g


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_FILE = DATA_DIR / "access_logs.csv"

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

IGNORED_PATH_PREFIXES = ("/static/", "/favicon.ico", "/hybridaction/")
IGNORED_PATHS = {"/favicon.ico", "/hybridaction/zybTrackerStatisticsAction"}

ALLOWED_ENDPOINTS = {
    "/",
    "/signup",
    "/login",
    "/dashboard",
    "/profile",
    "/products",
    "/change-password",
    "/api-test",
    "/logout"
}


def extract_client_ip(request):
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def should_log_request(path):
    if not path:
        return False
    if path in IGNORED_PATHS:
        return False
    return not any(path.startswith(prefix) for prefix in IGNORED_PATH_PREFIXES)


def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False


def resolve_session_id(request, session_id=None, fallback=None):
    from flask import has_request_context
    if not has_request_context():
        if fallback:
            return fallback
        return str(uuid.uuid4())

    # 1. If a session_id exists in the authenticated Flask session, use it.
    if flask_session.get("user") and flask_session.get("session_id"):
        sess_id = flask_session["session_id"]
        if is_valid_uuid(sess_id):
            return sess_id

    # 2. Otherwise, if the request contains X-Session-ID (traffic simulator), use that value directly.
    x_session = request.headers.get("X-Session-ID")
    if x_session:
        if is_valid_uuid(x_session):
            return x_session
        else:
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, x_session))

    # 3. Otherwise, generate a new UUID, store it in the Flask session, and use it for the anonymous session.
    if "session_id" not in flask_session or not is_valid_uuid(flask_session.get("session_id")):
        flask_session["session_id"] = str(uuid.uuid4())
    return flask_session["session_id"]


def _ensure_log_header():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not LOG_FILE.exists():
        with LOG_FILE.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(EXPECTED_HEADER)
        return

    with LOG_FILE.open("r", encoding="utf-8", newline="") as file:
        try:
            header = next(csv.reader(file))
        except StopIteration:
            header = []

    if header != EXPECTED_HEADER:
        with LOG_FILE.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(EXPECTED_HEADER)


def _append_log_row(row):
    _ensure_log_header()
    with LOG_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(row)


def log_request(request, status_code, response_time_ms=None, request_id=None, session_id=None, fallback_session_id=None):
    endpoint = request.path or ""
    if not should_log_request(endpoint):
        return

    # Prevent duplicate logging for the same request
    if getattr(g, "logged", False):
        return
    g.logged = True

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Username resolution:
    # - If the user is authenticated, obtain the username from the Flask session.
    # - If no authenticated session exists, check X-User header.
    # - Otherwise, use 'anonymous'.
    if flask_session.get("user"):
        username = flask_session["user"]
    else:
        username = request.headers.get("X-User") or "anonymous"

    client_ip = extract_client_ip(request)
    endpoint = request.path or ""
    method = request.method

    if response_time_ms is None:
        response_time_ms = 0.0

    # Request ID resolution:
    # - Generate a new UUID for every HTTP request.
    # - Every request must have a unique Request_ID.
    req_id = request_id or getattr(g, "request_id", None) or str(uuid.uuid4())

    # Session ID resolution
    sess_id = resolve_session_id(request, session_id=session_id, fallback=fallback_session_id)

    row = [
        timestamp,
        username,
        client_ip,
        endpoint,
        method,
        status_code,
        round(float(response_time_ms), 2),
        request.headers.get("User-Agent", "unknown"),
        sess_id,
        req_id,
    ]
    _append_log_row(row)