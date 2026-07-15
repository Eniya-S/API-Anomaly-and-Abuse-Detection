import hashlib
import json
import random
import time
import uuid
from pathlib import Path

import requests

BASE_URL = "http://127.0.0.1:5000"
BASE_DIR = Path(__file__).resolve().parent.parent
USERS_FILE = BASE_DIR / "data" / "users.json"

ATTACKER_USERNAMES = ["Aarav Sharma", "Aditi Rao", "Vikram Malhotra", "Neha Kapoor", "Rohan Joshi", "Deepak Gupta"]
ATTACKER_IPS = ["198.51.100.200", "198.51.100.201", "198.51.100.202"]
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", "python-requests/2.32.5"]


def load_users():
    with USERS_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def stable_client_ip(username):
    digest = hashlib.sha1(username.encode("utf-8")).hexdigest()
    octet = int(digest[:2], 16) % 100 + 2
    return f"198.51.100.{octet}"


def make_headers(username, persona, client_ip, session_id):
    return {
        "X-User": username,
        "X-Persona": persona.upper(),
        "X-Forwarded-For": client_ip,
        "X-Client-IP": client_ip,
        "X-Session-ID": session_id,
        "X-Request-ID": f"sim-{session_id}-{uuid.uuid4().hex[:8]}",
        "User-Agent": random.choice(USER_AGENTS),
    }


def create_session(user, persona):
    session = requests.Session()
    session_id = str(uuid.uuid4())
    client_ip = stable_client_ip(user["username"])
    session.headers.update(make_headers(user["username"], persona, client_ip, session_id))
    return session, session_id, client_ip


def login_user(user, persona):
    session, session_id, client_ip = create_session(user, persona)
    session.post(
        BASE_URL + "/login",
        data={"username": user["username"], "password": user["password"]},
        headers=make_headers(user["username"], persona, client_ip, session_id),
        timeout=5,
    )
    return session, session_id, client_ip


def request_with_session(session, method, path, *, data=None, headers=None, timeout=5):
    request_headers = dict(session.headers)
    if headers:
        request_headers.update(headers)
    request_headers["X-Request-ID"] = f"sim-{request_headers.get('X-Session-ID', 'session')}-{uuid.uuid4().hex[:8]}"
    if method.upper() == "GET":
        return session.get(BASE_URL + path, headers=request_headers, timeout=timeout)
    return session.post(BASE_URL + path, data=data, headers=request_headers, timeout=timeout)


def simulate_random_failure(session, client_ip, session_id, username, persona):
    """
    Simulates a realistic user request failure scenario by making actual HTTP requests
    to the Flask application, resulting in authentic error status codes.
    """
    scenario = random.choice([
        "wrong_password",
        "unauthenticated_access",
        "non_existent_endpoint",
        "incomplete_form",
        "unsupported_method"
    ])
    
    headers = make_headers(username, persona, client_ip, session_id)
    
    if scenario == "wrong_password":
        # 1. Login with an incorrect password (returns 200 but renders login page with error)
        session.post(
            BASE_URL + "/login",
            data={"username": username, "password": "incorrect_password_typo"},
            headers=headers,
            timeout=5
        )
    elif scenario == "unauthenticated_access":
        # 2. Access protected pages without authentication (returns 302 redirect to login)
        temp_session = requests.Session()
        temp_headers = make_headers("anonymous", persona, client_ip, str(uuid.uuid4()))
        temp_session.get(
            BASE_URL + random.choice(["/dashboard", "/profile", "/products"]),
            headers=temp_headers,
            timeout=5
        )
    elif scenario == "non_existent_endpoint":
        # 3. Request a non-existent endpoint to generate a 404 response
        session.get(
            BASE_URL + f"/non-existent-page-{uuid.uuid4().hex[:6]}",
            headers=headers,
            timeout=5
        )
    elif scenario == "incomplete_form":
        # 4. Submit invalid/incomplete form data to generate a 400 Bad Request
        session.post(
            BASE_URL + "/api-test",
            data={"api_name": "Incomplete Data Test"},  # missing 'test_type' and 'request_count'
            headers=headers,
            timeout=5
        )
    elif scenario == "unsupported_method":
        # 5. Use an unsupported HTTP method to generate a 405 Method Not Allowed
        session.post(
            BASE_URL + random.choice(["/dashboard", "/profile", "/products"]),
            data={"test": "data"},
            headers=headers,
            timeout=5
        )


def normal_user(user):
    session, session_id, client_ip = login_user(user, "normal")
    pages = ["/dashboard", "/profile", "/products"]
    random.shuffle(pages)
    for page in pages[: random.randint(1, 3)]:
        # Introduce 12% chance of a failed request scenario
        if random.random() < 0.12:
            simulate_random_failure(session, client_ip, session_id, user["username"], "normal")
        else:
            request_with_session(session, "GET", page)
        time.sleep(random.uniform(1, 3))
    
    # Introduce small chance of failure after normal interaction or during logout
    if random.random() < 0.08:
        simulate_random_failure(session, client_ip, session_id, user["username"], "normal")
        
    request_with_session(session, "GET", "/logout")


def explorer_user(user):
    session, session_id, client_ip = login_user(user, "explorer")
    pages = ["/dashboard", "/products", "/profile", "/api-test"]
    selected = random.sample(pages, random.randint(2, 4))
    for page in selected:
        # Introduce 12% chance of a failed request scenario
        if random.random() < 0.12:
            simulate_random_failure(session, client_ip, session_id, user["username"], "explorer")
        else:
            if page == "/api-test":
                request_with_session(
                    session,
                    "POST",
                    page,
                    data={"api_name": "Monitoring API", "test_type": "Functional Testing", "request_count": random.randint(5, 20)},
                )
            else:
                request_with_session(session, "GET", page)
        time.sleep(random.uniform(1, 3))
    request_with_session(session, "GET", "/logout")


def admin_user(user):
    session, session_id, client_ip = login_user(user, "admin")
    
    # Introduce a potential failure before proceeding
    if random.random() < 0.08:
        simulate_random_failure(session, client_ip, session_id, user["username"], "admin")
        
    request_with_session(session, "GET", "/dashboard")
    request_with_session(
        session,
        "POST",
        "/api-test",
        data={"api_name": "Authentication API", "test_type": "Load Testing", "request_count": random.randint(20, 100)},
    )
    request_with_session(session, "GET", "/products")
    
    # Introduce 12% chance of a failed request scenario
    if random.random() < 0.12:
        simulate_random_failure(session, client_ip, session_id, user["username"], "admin")
    else:
        request_with_session(session, "GET", "/profile")
        
    request_with_session(session, "GET", "/logout")


def malicious_user():
    username = random.choice(ATTACKER_USERNAMES)
    ip_pool = random.choice([ATTACKER_IPS[:1], ATTACKER_IPS[:2], ATTACKER_IPS[:3]])
    session_id = str(uuid.uuid4())
    session = requests.Session()
    for index in range(random.randint(10, 30)):
        client_ip = ip_pool[index % len(ip_pool)]
        headers = make_headers(username, "malicious", client_ip, session_id)
        session.post(
            BASE_URL + "/login",
            data={"username": username, "password": "wrongpassword"},
            headers=headers,
            timeout=5,
        )
        time.sleep(random.uniform(0.1, 0.5))
        
    # Attacker scanning for hidden endpoints / vulnerability patterns (404 and 405 failures)
    for _ in range(random.randint(5, 15)):
        client_ip = ip_pool[random.randint(0, len(ip_pool) - 1)]
        headers = make_headers(username, "malicious", client_ip, session_id)
        scan_endpoint = random.choice([
            "/admin", "/wp-admin", "/config", "/backup", "/.git", "/phpinfo", "/secrets", "/api/v1/debug"
        ])
        if random.random() < 0.2:
            # Generate 405 Method Not Allowed by sending POST to a GET endpoint
            session.post(BASE_URL + "/products", data={"scan": "post"}, headers=headers, timeout=5)
        else:
            # Generate 404 Not Found
            session.get(BASE_URL + scan_endpoint, headers=headers, timeout=5)
        time.sleep(random.uniform(0.1, 0.3))

    for _ in range(random.randint(20, 60)):
        endpoint = random.choice(["/dashboard", "/products", "/profile"])
        client_ip = ip_pool[random.randint(0, len(ip_pool) - 1)]
        headers = make_headers(username, "malicious", client_ip, session_id)
        session.get(BASE_URL + endpoint, headers=headers, timeout=5)

users = load_users()
print("\nTraffic Simulation Started...\n")
for i in range(100):
    persona = random.choice(["normal", "normal", "explorer", "admin", "malicious"])
    if persona == "malicious":
        print(f"Session {i + 1}: MALICIOUS USER")
        malicious_user()
    else:
        user = random.choice(users)
        print(f"Session {i + 1}: {persona.upper()} - {user['username']}")
        if persona == "normal":
            normal_user(user)
        elif persona == "explorer":
            explorer_user(user)
        elif persona == "admin":
            admin_user(user)
    time.sleep(random.uniform(1, 3))
print("\nTraffic Simulation Completed!")