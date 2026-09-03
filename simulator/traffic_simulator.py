import csv
import hashlib
import json
import random
import time
import uuid
from pathlib import Path
import argparse
import requests


# =========================================================
# CONFIGURATION
# =========================================================

BASE_URL = "http://127.0.0.1:3000"

BASE_DIR = Path(__file__).resolve().parent.parent

USERS_FILE = BASE_DIR / "data" / "users.json"

LABELS_FILE = BASE_DIR / "data" / "simulation_labels.csv"


# =========================================================
# ATTACKER IDENTITIES
# =========================================================

ATTACKER_USERNAMES = [
    "Aarav Sharma",
    "Aditi Rao",
    "Vikram Malhotra",
    "Neha Kapoor",
    "Rohan Joshi",
    "Deepak Gupta"
]

ATTACKER_IPS = [
    "198.51.100.200",
    "198.51.100.201",
    "198.51.100.202",
    "198.51.100.203",
    "198.51.100.204",
    "198.51.100.205"
]

ATTACKER_INDEX = 0


# =========================================================
# USER AGENTS
# =========================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "python-requests/2.32.5"
]


# =========================================================
# SIMULATION SETTINGS
# =========================================================

FAST_MODE = False

# Allows enough time for Flask + Google Sheet logging.
REQUEST_TIMEOUT = 30


# =========================================================
# LOAD USERS
# =========================================================

def load_users():

    with USERS_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        users = json.load(file)

    if not isinstance(users, list):

        raise ValueError(
            "users.json must contain a list of users."
        )

    return users


# =========================================================
# STABLE IP FOR NORMAL USERS
# =========================================================

def stable_client_ip(username):

    digest = hashlib.sha1(
        username.encode("utf-8")
    ).hexdigest()

    octet = (
        int(digest[:2], 16) % 100
    ) + 2

    return f"198.51.100.{octet}"


# =========================================================
# NEXT ATTACKER IDENTITY
# =========================================================

def next_attacker_identity():

    global ATTACKER_INDEX

    username = ATTACKER_USERNAMES[
        ATTACKER_INDEX % len(ATTACKER_USERNAMES)
    ]

    start_index = (
        ATTACKER_INDEX % len(ATTACKER_IPS)
    )

    ATTACKER_INDEX += 1

    return username, start_index


# =========================================================
# ATTACKER IP
# =========================================================

def attacker_ip(start_index, request_index):

    return ATTACKER_IPS[
        (start_index + request_index)
        % len(ATTACKER_IPS)
    ]


# =========================================================
# REQUEST HEADERS
# =========================================================

def make_headers(
    username,
    persona,
    client_ip,
    session_id
):

    return {
        "X-User": username,

        "X-Persona": persona.upper(),

        "X-Forwarded-For": client_ip,

        "X-Client-IP": client_ip,

        "X-Session-ID": session_id,

        "X-Request-ID": (
            f"sim-{session_id}-"
            f"{uuid.uuid4().hex[:8]}"
        ),

        "User-Agent": random.choice(
            USER_AGENTS
        )
    }


# =========================================================
# WRITE SIMULATION LABEL
# =========================================================

def write_label(request_id, label):

    LABELS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    write_header = (
        not LABELS_FILE.exists()
        or LABELS_FILE.stat().st_size == 0
    )

    with LABELS_FILE.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        if write_header:

            writer.writerow([
                "Request_ID",
                "Attack_Type"
            ])

        writer.writerow([
            request_id,
            label
        ])


# =========================================================
# CREATE SESSION
# =========================================================

def create_session(user, persona):

    session = requests.Session()

    session_id = str(
        uuid.uuid4()
    )

    client_ip = stable_client_ip(
        user["username"]
    )

    session.headers.update(
        make_headers(
            user["username"],
            persona,
            client_ip,
            session_id
        )
    )

    return (
        session,
        session_id,
        client_ip
    )


# =========================================================
# LOGIN USER
# =========================================================

def login_user(user, persona):

    session, session_id, client_ip = (
        create_session(
            user,
            persona
        )
    )

    password = user.get("password")

    # The simulator needs the original password.
    if password is None:

        print(
            f"[LOGIN] Skipping {user['username']} - "
            "no plaintext simulator password found."
        )

        return (
            session,
            session_id,
            client_ip
        )

    try:

        response = session.post(

            BASE_URL + "/login",

            data={
                "username": user["username"],
                "password": password
            },

            headers=make_headers(
                user["username"],
                persona,
                client_ip,
                session_id
            ),

            timeout=REQUEST_TIMEOUT
        )

        req_id = response.headers.get(
            "X-Request-ID"
        )

        if req_id:

            write_label(
                req_id,
                "Normal"
            )

        if response.status_code >= 400:

            print(
                f"[LOGIN] {user['username']} "
                f"returned HTTP {response.status_code}"
            )

        return (
            session,
            session_id,
            client_ip
        )

    except requests.RequestException as error:

        print(
            f"[LOGIN] {user['username']} failed: "
            f"{error}"
        )

        return (
            session,
            session_id,
            client_ip
        )


# =========================================================
# REQUEST WITH SESSION
# =========================================================

def request_with_session(
    session,
    method,
    path,
    data=None,
    headers=None,
    timeout=REQUEST_TIMEOUT,
    label="Normal"
):

    request_headers = dict(
        session.headers
    )

    if headers:

        request_headers.update(
            headers
        )

    request_headers["X-Request-ID"] = (
        f"sim-"
        f"{request_headers.get('X-Session-ID', 'session')}-"
        f"{uuid.uuid4().hex[:8]}"
    )

    try:

        if method.upper() == "GET":

            response = session.get(

                BASE_URL + path,

                headers=request_headers,

                timeout=timeout
            )

        else:

            response = session.post(

                BASE_URL + path,

                data=data,

                headers=request_headers,

                timeout=timeout
            )

        req_id = response.headers.get(
            "X-Request-ID"
        )

        if req_id:

            write_label(
                req_id,
                label
            )

        return response

    except requests.RequestException as error:

        print(
            f"Request failed to {path}: {error}"
        )

        return None


# =========================================================
# RANDOM NORMAL FAILURE
# =========================================================

def simulate_random_failure(
    session,
    client_ip,
    session_id,
    username,
    persona
):

    scenario = random.choice([

        "wrong_password",

        "unauthenticated_access",

        "non_existent_endpoint",

        "incomplete_form",

        "unsupported_method"

    ])

    headers = make_headers(

        username,
        persona,
        client_ip,
        session_id
    )

    try:

        if scenario == "wrong_password":

            response = session.post(

                BASE_URL + "/login",

                data={
                    "username": username,
                    "password": "incorrect_password_typo"
                },

                headers=headers,

                timeout=REQUEST_TIMEOUT
            )

            req_id = response.headers.get(
                "X-Request-ID"
            )

            if req_id:

                write_label(
                    req_id,
                    "Normal"
                )

        elif scenario == "unauthenticated_access":

            temp_session = requests.Session()

            anonymous_session_id = str(
                uuid.uuid4()
            )

            temp_headers = make_headers(

                "anonymous",

                persona,

                client_ip,

                anonymous_session_id
            )

            response = temp_session.get(

                BASE_URL + random.choice([
                    "/dashboard",
                    "/profile",
                    "/products"
                ]),

                headers=temp_headers,

                timeout=REQUEST_TIMEOUT
            )

            req_id = response.headers.get(
                "X-Request-ID"
            )

            if req_id:

                write_label(
                    req_id,
                    "Normal"
                )

        elif scenario == "non_existent_endpoint":

            response = session.get(

                BASE_URL
                + f"/non-existent-page-"
                + uuid.uuid4().hex[:6],

                headers=headers,

                timeout=REQUEST_TIMEOUT
            )

            req_id = response.headers.get(
                "X-Request-ID"
            )

            if req_id:

                write_label(
                    req_id,
                    "Normal"
                )

        elif scenario == "incomplete_form":

            response = session.post(

                BASE_URL + "/api-test",

                data={
                    "api_name": "Incomplete Data Test"
                },

                headers=headers,

                timeout=REQUEST_TIMEOUT
            )

            req_id = response.headers.get(
                "X-Request-ID"
            )

            if req_id:

                write_label(
                    req_id,
                    "Normal"
                )

        elif scenario == "unsupported_method":

            response = session.post(

                BASE_URL + random.choice([
                    "/dashboard",
                    "/profile",
                    "/products"
                ]),

                data={
                    "test": "data"
                },

                headers=headers,

                timeout=REQUEST_TIMEOUT
            )

            req_id = response.headers.get(
                "X-Request-ID"
            )

            if req_id:

                write_label(
                    req_id,
                    "Normal"
                )

    except requests.RequestException as error:

        print(
            f"Random failure simulation failed: "
            f"{error}"
        )


# =========================================================
# NORMAL USER
# =========================================================

def normal_user(user):

    session, session_id, client_ip = (
        login_user(
            user,
            "normal"
        )
    )

    pages = [
        "/dashboard",
        "/profile",
        "/products"
    ]

    random.shuffle(pages)

    for page in pages[
        :random.randint(1, 3)
    ]:

        if random.random() < 0.12:

            simulate_random_failure(

                session,
                client_ip,
                session_id,
                user["username"],
                "normal"
            )

        else:

            request_with_session(

                session,
                "GET",
                page,
                label="Normal"
            )

        if not FAST_MODE:

            time.sleep(
                random.uniform(1, 3)
            )

        else:

            time.sleep(0.01)

    if random.random() < 0.08:

        simulate_random_failure(

            session,
            client_ip,
            session_id,
            user["username"],
            "normal"
        )

    request_with_session(

        session,
        "GET",
        "/logout",
        label="Normal"
    )


# =========================================================
# EXPLORER USER
# =========================================================

def explorer_user(user):

    session, session_id, client_ip = (
        login_user(
            user,
            "explorer"
        )
    )

    pages = [
        "/dashboard",
        "/products",
        "/profile",
        "/api-test"
    ]

    selected = random.sample(
        pages,
        random.randint(2, 4)
    )

    for page in selected:

        if random.random() < 0.12:

            simulate_random_failure(

                session,
                client_ip,
                session_id,
                user["username"],
                "explorer"
            )

        else:

            if page == "/api-test":

                request_with_session(

                    session,
                    "POST",
                    page,

                    data={
                        "api_name":
                            "Monitoring API",

                        "test_type":
                            "Functional Testing",

                        "request_count":
                            random.randint(5, 20)
                    },

                    label="Normal"
                )

            else:

                request_with_session(

                    session,
                    "GET",
                    page,
                    label="Normal"
                )

        if not FAST_MODE:

            time.sleep(
                random.uniform(1, 3)
            )

        else:

            time.sleep(0.01)

    request_with_session(

        session,
        "GET",
        "/logout",
        label="Normal"
    )


# =========================================================
# ADMIN USER
# =========================================================

def admin_user(user):

    session, session_id, client_ip = (
        login_user(
            user,
            "admin"
        )
    )

    if random.random() < 0.08:

        simulate_random_failure(

            session,
            client_ip,
            session_id,
            user["username"],
            "admin"
        )

    request_with_session(

        session,
        "GET",
        "/dashboard",
        label="Normal"
    )

    request_with_session(

        session,
        "POST",
        "/api-test",

        data={
            "api_name":
                "Authentication API",

            "test_type":
                "Load Testing",

            "request_count":
                random.randint(20, 100)
        },

        label="Normal"
    )

    request_with_session(

        session,
        "GET",
        "/products",
        label="Normal"
    )

    if random.random() < 0.12:

        simulate_random_failure(

            session,
            client_ip,
            session_id,
            user["username"],
            "admin"
        )

    else:

        request_with_session(

            session,
            "GET",
            "/profile",
            label="Normal"
        )

    request_with_session(

        session,
        "GET",
        "/logout",
        label="Normal"
    )


# =========================================================
# BRUTE FORCE SIMULATION
# =========================================================

def simulate_brute_force():

    username, start_index = (
        next_attacker_identity()
    )

    session_id = str(
        uuid.uuid4()
    )

    session = requests.Session()

    num_requests = random.randint(
        10,
        30
    )

    print(
        f"  Attacker: {username}"
    )

    for index in range(
        num_requests
    ):

        client_ip = attacker_ip(
            start_index,
            index
        )

        headers = make_headers(

            username,
            "malicious",
            client_ip,
            session_id
        )

        try:

            response = session.post(

                BASE_URL + "/login",

                data={
                    "username": username,
                    "password": "wrongpassword"
                },

                headers=headers,

                timeout=REQUEST_TIMEOUT
            )

            req_id = response.headers.get(
                "X-Request-ID"
            )

            if req_id:

                write_label(
                    req_id,
                    "Brute_Force"
                )

        except requests.RequestException as error:

            print(
                f"Brute Force request failed: "
                f"{error}"
            )

        if not FAST_MODE:

            time.sleep(
                random.uniform(0.1, 0.5)
            )

        else:

            time.sleep(0.01)


# =========================================================
# ENDPOINT SCANNING SIMULATION
# =========================================================

def simulate_endpoint_scanning():

    username, start_index = (
        next_attacker_identity()
    )

    session_id = str(
        uuid.uuid4()
    )

    session = requests.Session()

    num_requests = random.randint(
        15,
        30
    )

    print(
        f"  Attacker: {username}"
    )

    scan_endpoints = [

        "/admin",
        "/wp-admin",
        "/config",
        "/backup",
        "/.git",
        "/phpinfo",
        "/secrets",
        "/api/v1/debug",
        "/env",
        "/setup",
        "/shell",
        "/phpmyadmin",
        "/db"

    ]

    for index in range(
        num_requests
    ):

        client_ip = attacker_ip(
            start_index,
            index
        )

        headers = make_headers(

            username,
            "malicious",
            client_ip,
            session_id
        )

        scan_endpoint = random.choice(
            scan_endpoints
        )

        try:

            if random.random() < 0.2:

                response = session.post(

                    BASE_URL + "/products",

                    data={
                        "scan": "post"
                    },

                    headers=headers,

                    timeout=REQUEST_TIMEOUT
                )

            else:

                response = session.get(

                    BASE_URL + scan_endpoint,

                    headers=headers,

                    timeout=REQUEST_TIMEOUT
                )

            req_id = response.headers.get(
                "X-Request-ID"
            )

            if req_id:

                write_label(
                    req_id,
                    "Endpoint_Scanning"
                )

        except requests.RequestException as error:

            print(
                f"Endpoint Scanning request failed: "
                f"{error}"
            )

        if not FAST_MODE:

            time.sleep(
                random.uniform(0.1, 0.3)
            )

        else:

            time.sleep(0.01)


# =========================================================
# REQUEST FLOODING SIMULATION
# =========================================================

def simulate_request_flooding():

    username, start_index = (
        next_attacker_identity()
    )

    session_id = str(
        uuid.uuid4()
    )

    session = requests.Session()

    num_requests = random.randint(
        40,
        80
    )

    print(
        f"  Attacker: {username}"
    )

    endpoints = [
        "/dashboard",
        "/products",
        "/profile"
    ]

    for index in range(
        num_requests
    ):

        endpoint = random.choice(
            endpoints
        )

        client_ip = attacker_ip(
            start_index,
            index
        )

        headers = make_headers(

            username,
            "malicious",
            client_ip,
            session_id
        )

        try:

            response = session.get(

                BASE_URL + endpoint,

                headers=headers,

                timeout=REQUEST_TIMEOUT
            )

            req_id = response.headers.get(
                "X-Request-ID"
            )

            if req_id:

                write_label(
                    req_id,
                    "Request_Flooding"
                )

        except requests.RequestException as error:

            print(
                f"Request Flooding request failed: "
                f"{error}"
            )

        if not FAST_MODE:

            time.sleep(
                random.uniform(0.02, 0.1)
            )

        else:

            time.sleep(0.005)


# =========================================================
# MAIN
# =========================================================

def main():

    global FAST_MODE

    parser = argparse.ArgumentParser(
        description="API traffic simulator"
    )

    parser.add_argument(
        "--fast",
        action="store_true",
        help="Run simulation in fast mode"
    )

    parser.add_argument(
        "--sessions",
        type=int,
        default=100,
        help="Number of simulation sessions"
    )

    args = parser.parse_args()

    FAST_MODE = args.fast

    num_sessions = args.sessions

    if num_sessions <= 0:

        print(
            "Sessions must be greater than 0."
        )

        return

    try:

        users = load_users()

    except Exception as error:

        print(
            f"Error loading users: {error}. "
            "Please ensure data/users.json is present."
        )

        return

    if not users:

        print(
            "No users found in data/users.json."
        )

        return

    print()

    print(
        "Traffic Simulation Started..."
    )

    print(
        f"Sessions: {num_sessions}"
    )

    print(
        f"Fast Mode: {FAST_MODE}"
    )

    print(
        f"Request Timeout: {REQUEST_TIMEOUT} seconds"
    )

    print()

    for i in range(
        num_sessions
    ):

        persona = random.choice([

            "normal",
            "normal",
            "explorer",
            "admin",
            "brute_force",
            "endpoint_scanning",
            "request_flooding"

        ])

        if persona == "brute_force":

            print(
                f"Session {i + 1}/{num_sessions}: "
                "BRUTE FORCE ATTACK"
            )

            simulate_brute_force()

        elif persona == "endpoint_scanning":

            print(
                f"Session {i + 1}/{num_sessions}: "
                "ENDPOINT SCANNING ATTACK"
            )

            simulate_endpoint_scanning()

        elif persona == "request_flooding":

            print(
                f"Session {i + 1}/{num_sessions}: "
                "REQUEST FLOODING ATTACK"
            )

            simulate_request_flooding()

        else:

            user = random.choice(
                users
            )

            print(
                f"Session {i + 1}/{num_sessions}: "
                f"{persona.upper()} - "
                f"{user['username']}"
            )

            if persona == "normal":

                normal_user(user)

            elif persona == "explorer":

                explorer_user(user)

            elif persona == "admin":

                admin_user(user)

        if not FAST_MODE:

            time.sleep(
                random.uniform(1, 3)
            )

        else:

            time.sleep(0.05)

    print()

    print(
        "Traffic Simulation Completed!"
    )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":

    main()

