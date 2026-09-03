import csv
import os
import shutil
import uuid

from datetime import datetime
from pathlib import Path

import requests

from flask import (
    session as flask_session,
    g
)


# =========================================================
# PATH
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

SRC_DATA_DIR = BASE_DIR / "data"


def _resolve_data_dir():

    # Vercel filesystem is temporary.
    # /tmp is writable.

    if (
        os.environ.get("VERCEL")
        or not os.access(BASE_DIR, os.W_OK)
    ):

        tmp = Path("/tmp/data")

        try:

            if not tmp.exists():

                if SRC_DATA_DIR.exists():

                    shutil.copytree(
                        SRC_DATA_DIR,
                        tmp
                    )

                else:

                    tmp.mkdir(
                        parents=True,
                        exist_ok=True
                    )

        except Exception:

            tmp.mkdir(
                parents=True,
                exist_ok=True
            )

        return tmp


    return SRC_DATA_DIR


DATA_DIR = _resolve_data_dir()

LOG_FILE = DATA_DIR / "access_logs.csv"


# =========================================================
# GOOGLE WEBHOOK
# =========================================================

WEBHOOK_URL = os.getenv(
    "GOOGLE_WEBHOOK_URL"
)

WEBHOOK_TOKEN = os.getenv(
    "GOOGLE_WEBHOOK_TOKEN"
)


# =========================================================
# EXACT 10 COLUMNS
# =========================================================

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

    "Request_ID"

]


# =========================================================
# IGNORED REQUESTS
# =========================================================

IGNORED_PATH_PREFIXES = (

    "/static/",

    "/hybridaction/",

)


IGNORED_PATHS = {

    "/favicon.ico",

    "/hybridaction/"
    "zybTrackerStatisticsAction"

}


# =========================================================
# IP
# =========================================================

def extract_client_ip(request):

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )


    if forwarded_for:

        return (
            forwarded_for
            .split(",")[0]
            .strip()
        )


    return (
        request.remote_addr
        or "unknown"
    )


# =========================================================
# SHOULD LOG
# =========================================================

def should_log_request(path):

    if not path:

        return False


    if path in IGNORED_PATHS:

        return False


    if any(
        path.startswith(prefix)
        for prefix in IGNORED_PATH_PREFIXES
    ):

        return False


    return True


# =========================================================
# UUID CHECK
# =========================================================

def is_valid_uuid(value):

    try:

        uuid.UUID(str(value))

        return True

    except (
        ValueError,
        TypeError,
        AttributeError
    ):

        return False


# =========================================================
# SESSION ID
# =========================================================

def resolve_session_id(
    request,
    session_id=None,
    fallback=None
):

    from flask import (
        has_request_context
    )


    if not has_request_context():

        if fallback:

            return fallback

        return str(uuid.uuid4())


    # Logged in user

    if (
        flask_session.get("user")
        and flask_session.get("session_id")
    ):

        sess_id = (
            flask_session["session_id"]
        )


        if is_valid_uuid(sess_id):

            return sess_id


    # Header session

    x_session = request.headers.get(
        "X-Session-ID"
    )


    if x_session:

        if is_valid_uuid(x_session):

            return x_session


        return str(
            uuid.uuid5(
                uuid.NAMESPACE_DNS,
                x_session
            )
        )


    # Create session

    if (
        "session_id" not in flask_session
        or not is_valid_uuid(
            flask_session.get(
                "session_id"
            )
        )
    ):

        flask_session["session_id"] = (
            str(uuid.uuid4())
        )


    return flask_session[
        "session_id"
    ]


# =========================================================
# CSV HEADER
# =========================================================

def _ensure_log_header():

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    if not LOG_FILE.exists():

        with LOG_FILE.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(
                EXPECTED_HEADER
            )

        return


    try:

        with LOG_FILE.open(
            "r",
            encoding="utf-8",
            newline=""
        ) as file:

            header = next(
                csv.reader(file),
                []
            )

    except Exception:

        header = []


    if header != EXPECTED_HEADER:

        with LOG_FILE.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(
                EXPECTED_HEADER
            )


# =========================================================
# LOCAL CSV
# =========================================================

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


    except Exception as error:

        print(
            "[CSV LOG ERROR]",
            error
        )


# =========================================================
# GOOGLE SHEET
# =========================================================

def _send_to_google_sheet(log_data):

    if not WEBHOOK_URL:

        print(
            "[GOOGLE SHEET] "
            "Webhook URL not configured"
        )

        return


    try:

        payload = dict(log_data)


        payload["action"] = "log"


        if WEBHOOK_TOKEN:

            payload[
                "webhook_token"
            ] = WEBHOOK_TOKEN


        response = requests.post(

            WEBHOOK_URL,

            json=payload,

            timeout=5

        )


        if response.status_code == 200:

            print(
                "[GOOGLE SHEET] "
                "Log sent successfully"
            )

        else:

            print(
                "[GOOGLE SHEET] "
                f"Failed: HTTP "
                f"{response.status_code}"
            )


    except Exception as error:

        print(
            "[GOOGLE SHEET] Error:",
            error
        )


# =========================================================
# MAIN LOG FUNCTION
# =========================================================

def log_request(

    request,

    status_code,

    response_time_ms=None,

    request_id=None,

    session_id=None,

    fallback_session_id=None

):

    endpoint = request.path or ""


    if not should_log_request(
        endpoint
    ):

        return


    # Prevent duplicate logging

    if getattr(
        g,
        "logged",
        False
    ):

        return


    g.logged = True


    # Timestamp

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    # Username

    if flask_session.get("user"):

        username = (
            flask_session["user"]
        )

    else:

        username = (
            request.headers.get(
                "X-User"
            )
            or "anonymous"
        )


    # IP

    client_ip = extract_client_ip(
        request
    )


    # Method

    method = request.method


    # Response time

    if response_time_ms is None:

        response_time_ms = 0.0


    response_time_ms = round(

        float(response_time_ms),

        2

    )


    # Request ID

    req_id = (

        request_id

        or getattr(
            g,
            "request_id",
            None
        )

        or str(uuid.uuid4())

    )


    # Session ID

    sess_id = resolve_session_id(

        request,

        session_id=session_id,

        fallback=fallback_session_id

    )


    # =====================================================
    # EXACT 10-COLUMN ROW
    # =====================================================

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

        req_id

    ]


    # Local CSV

    _append_log_row(row)


    # Google Sheet

    log_data = dict(
        zip(
            EXPECTED_HEADER,
            row
        )
    )


    _send_to_google_sheet(
        log_data
    )


    print(

        "[API LOG] "

        f"{method} {endpoint} | "

        f"IP={client_ip} | "

        f"User={username} | "

        f"Status={status_code} | "

        f"{response_time_ms} ms"

    )