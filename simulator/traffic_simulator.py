import csv
import hashlib
import json
import random
import time
import uuid
from pathlib import Path
import argparse
import requests

BASE_URL = "http://127.0.0.1:5000"
BASE_DIR = Path(__file__).resolve().parent.parent
USERS_FILE = BASE_DIR / "data" / "users.json"
LABELS_FILE = BASE_DIR / "data" / "simulation_labels.csv"

ATTACKER_USERNAMES = ["Aarav Sharma", "Aditi Rao", "Vikram Malhotra", "Neha Kapoor", "Rohan Joshi", "Deepak Gupta"]
ATTACKER_IPS = ["198.51.100.200", "198.51.100.201", "198.51.100.202"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "python-requests/2.32.5"
]

# Fast mode flag configured via argparse
FAST_MODE = False

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

def write_label(request_id, label):
    LABELS_FILE.parent.mkdir(parents=True, exist_ok=True)
    write_header = not LABELS_FILE.exists() or LABELS_FILE.stat().st_size == 0
    with LABELS_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if write_header:
            writer.writerow(["Request_ID", "Attack_Type"])
        writer.writerow([request_id, label])

def create_session(user, persona):
    session = requests.Session()
    session_id = str(uuid.uuid4())
    client_ip = stable_client_ip(user["username"])
    session.headers.update(make_headers(user["username"], persona, client_ip, session_id))
    return session, session_id, client_ip

def login_user(user, persona):
    session, session_id, client_ip = create_session(user, persona)
    response = session.post(
        BASE_URL + "/login",
        data={"username": user["username"], "password": user["password"]},
        headers=make_headers(user["username"], persona, client_ip, session_id),
        timeout=5,
    )
    req_id = response.headers.get("X-Request-ID")
    if req_id:
        write_label(req_id, "Normal")
    return session, session_id, client_ip

def request_with_session(session, method, path, *, data=None, headers=None, timeout=5, label="Normal"):
    request_headers = dict(session.headers)
    if headers:
        request_headers.update(headers)
    request_headers["X-Request-ID"] = f"sim-{request_headers.get('X-Session-ID', 'session')}-{uuid.uuid4().hex[:8]}"
    
    try:
        if method.upper() == "GET":
            response = session.get(BASE_URL + path, headers=request_headers, timeout=timeout)
        else:
            response = session.post(BASE_URL + path, data=data, headers=request_headers, timeout=timeout)
        
        req_id = response.headers.get("X-Request-ID")
        if req_id:
            write_label(req_id, label)
        return response
    except Exception as e:
        print(f"Request failed to {path}: {e}")
        return None

def simulate_random_failure(session, client_ip, session_id, username, persona):
    scenario = random.choice([
        "wrong_password",
        "unauthenticated_access",
        "non_existent_endpoint",
        "incomplete_form",
        "unsupported_method"
    ])
    
    headers = make_headers(username, persona, client_ip, session_id)
    
    try:
        if scenario == "wrong_password":
            response = session.post(
                BASE_URL + "/login",
                data={"username": username, "password": "incorrect_password_typo"},
                headers=headers,
                timeout=5
            )
            req_id = response.headers.get("X-Request-ID")
            if req_id:
                write_label(req_id, "Normal")
        elif scenario == "unauthenticated_access":
            temp_session = requests.Session()
            temp_headers = make_headers("anonymous", persona, client_ip, str(uuid.uuid4()))
            response = temp_session.get(
                BASE_URL + random.choice(["/dashboard", "/profile", "/products"]),
                headers=temp_headers,
                timeout=5
            )
            req_id = response.headers.get("X-Request-ID")
            if req_id:
                write_label(req_id, "Normal")
        elif scenario == "non_existent_endpoint":
            response = session.get(
                BASE_URL + f"/non-existent-page-{uuid.uuid4().hex[:6]}",
                headers=headers,
                timeout=5
            )
            req_id = response.headers.get("X-Request-ID")
            if req_id:
                write_label(req_id, "Normal")
        elif scenario == "incomplete_form":
            response = session.post(
                BASE_URL + "/api-test",
                data={"api_name": "Incomplete Data Test"},
                headers=headers,
                timeout=5
            )
            req_id = response.headers.get("X-Request-ID")
            if req_id:
                write_label(req_id, "Normal")
        elif scenario == "unsupported_method":
            response = session.post(
                BASE_URL + random.choice(["/dashboard", "/profile", "/products"]),
                data={"test": "data"},
                headers=headers,
                timeout=5
            )
            req_id = response.headers.get("X-Request-ID")
            if req_id:
                write_label(req_id, "Normal")
    except Exception as e:
        print(f"Random failure simulation request failed: {e}")

def normal_user(user):
    session, session_id, client_ip = login_user(user, "normal")
    pages = ["/dashboard", "/profile", "/products"]
    random.shuffle(pages)
    for page in pages[: random.randint(1, 3)]:
        if random.random() < 0.12:
            simulate_random_failure(session, client_ip, session_id, user["username"], "normal")
        else:
            request_with_session(session, "GET", page, label="Normal")
        
        if not FAST_MODE:
            time.sleep(random.uniform(1, 3))
        else:
            time.sleep(0.01)
    
    if random.random() < 0.08:
        simulate_random_failure(session, client_ip, session_id, user["username"], "normal")
        
    request_with_session(session, "GET", "/logout", label="Normal")

def explorer_user(user):
    session, session_id, client_ip = login_user(user, "explorer")
    pages = ["/dashboard", "/products", "/profile", "/api-test"]
    selected = random.sample(pages, random.randint(2, 4))
    for page in selected:
        if random.random() < 0.12:
            simulate_random_failure(session, client_ip, session_id, user["username"], "explorer")
        else:
            if page == "/api-test":
                request_with_session(
                    session,
                    "POST",
                    page,
                    data={"api_name": "Monitoring API", "test_type": "Functional Testing", "request_count": random.randint(5, 20)},
                    label="Normal"
                )
            else:
                request_with_session(session, "GET", page, label="Normal")
        
        if not FAST_MODE:
            time.sleep(random.uniform(1, 3))
        else:
            time.sleep(0.01)
            
    request_with_session(session, "GET", "/logout", label="Normal")

def admin_user(user):
    session, session_id, client_ip = login_user(user, "admin")
    
    if random.random() < 0.08:
        simulate_random_failure(session, client_ip, session_id, user["username"], "admin")
        
    request_with_session(session, "GET", "/dashboard", label="Normal")
    request_with_session(
        session,
        "POST",
        "/api-test",
        data={"api_name": "Authentication API", "test_type": "Load Testing", "request_count": random.randint(20, 100)},
        label="Normal"
    )
    request_with_session(session, "GET", "/products", label="Normal")
    
    if random.random() < 0.12:
        simulate_random_failure(session, client_ip, session_id, user["username"], "admin")
    else:
        request_with_session(session, "GET", "/profile", label="Normal")
        
    request_with_session(session, "GET", "/logout", label="Normal")

def simulate_brute_force():
    username = random.choice(ATTACKER_USERNAMES)
    ip_pool = random.choice([ATTACKER_IPS[:1], ATTACKER_IPS[:2], ATTACKER_IPS[:3]])
    session_id = str(uuid.uuid4())
    session = requests.Session()
    
    num_requests = random.randint(10, 30)
    for index in range(num_requests):
        client_ip = ip_pool[index % len(ip_pool)]
        headers = make_headers(username, "malicious", client_ip, session_id)
        try:
            response = session.post(
                BASE_URL + "/login",
                data={"username": username, "password": "wrongpassword"},
                headers=headers,
                timeout=5,
            )
            req_id = response.headers.get("X-Request-ID")
            if req_id:
                write_label(req_id, "Brute_Force")
        except Exception as e:
            print(f"Brute Force request failed: {e}")
        
        if not FAST_MODE:
            time.sleep(random.uniform(0.1, 0.5))
        else:
            time.sleep(0.01)

def simulate_endpoint_scanning():
    username = random.choice(ATTACKER_USERNAMES)
    ip_pool = random.choice([ATTACKER_IPS[:1], ATTACKER_IPS[:2], ATTACKER_IPS[:3]])
    session_id = str(uuid.uuid4())
    session = requests.Session()
    
    num_requests = random.randint(15, 30)
    for index in range(num_requests):
        client_ip = ip_pool[index % len(ip_pool)]
        headers = make_headers(username, "malicious", client_ip, session_id)
        scan_endpoint = random.choice([
            "/admin", "/wp-admin", "/config", "/backup", "/.git", "/phpinfo", "/secrets", "/api/v1/debug",
            "/env", "/setup", "/shell", "/phpmyadmin", "/db"
        ])
        try:
            if random.random() < 0.2:
                response = session.post(BASE_URL + "/products", data={"scan": "post"}, headers=headers, timeout=5)
            else:
                response = session.get(BASE_URL + scan_endpoint, headers=headers, timeout=5)
            
            req_id = response.headers.get("X-Request-ID")
            if req_id:
                write_label(req_id, "Endpoint_Scanning")
        except Exception as e:
            print(f"Endpoint Scanning request failed: {e}")
            
        if not FAST_MODE:
            time.sleep(random.uniform(0.1, 0.3))
        else:
            time.sleep(0.01)

def simulate_request_flooding():
    username = random.choice(ATTACKER_USERNAMES)
    ip_pool = random.choice([ATTACKER_IPS[:1], ATTACKER_IPS[:2], ATTACKER_IPS[:3]])
    session_id = str(uuid.uuid4())
    session = requests.Session()
    
    num_requests = random.randint(40, 80)
    for index in range(num_requests):
        endpoint = random.choice(["/dashboard", "/products", "/profile"])
        client_ip = ip_pool[index % len(ip_pool)]
        headers = make_headers(username, "malicious", client_ip, session_id)
        try:
            response = session.get(BASE_URL + endpoint, headers=headers, timeout=5)
            req_id = response.headers.get("X-Request-ID")
            if req_id:
                write_label(req_id, "Request_Flooding")
        except Exception as e:
            print(f"Request Flooding request failed: {e}")
            
        if not FAST_MODE:
            time.sleep(random.uniform(0.02, 0.1))
        else:
            time.sleep(0.005)

def main():
    global FAST_MODE
    parser = argparse.ArgumentParser(description="API traffic simulator")
    parser.add_argument("--fast", action="store_true", help="Run simulation in fast mode with minimal delays")
    parser.add_argument("--sessions", type=int, default=100, help="Number of simulation sessions (default: 100)")
    args = parser.parse_args()
    
    FAST_MODE = args.fast
    num_sessions = args.sessions
    
    try:
        users = load_users()
    except Exception as e:
        print(f"Error loading users: {e}. Please ensure data/users.json is present.")
        return

    print(f"\nTraffic Simulation Started... (Sessions: {num_sessions}, Fast Mode: {FAST_MODE})\n")
    
    for i in range(num_sessions):
        persona = random.choice([
            "normal", "normal", "explorer", "admin",
            "brute_force", "endpoint_scanning", "request_flooding"
        ])
        
        if persona == "brute_force":
            print(f"Session {i + 1}/{num_sessions}: BRUTE FORCE ATTACK")
            simulate_brute_force()
        elif persona == "endpoint_scanning":
            print(f"Session {i + 1}/{num_sessions}: ENDPOINT SCANNING ATTACK")
            simulate_endpoint_scanning()
        elif persona == "request_flooding":
            print(f"Session {i + 1}/{num_sessions}: REQUEST FLOODING ATTACK")
            simulate_request_flooding()
        else:
            user = random.choice(users)
            print(f"Session {i + 1}/{num_sessions}: {persona.upper()} - {user['username']}")
            if persona == "normal":
                normal_user(user)
            elif persona == "explorer":
                explorer_user(user)
            elif persona == "admin":
                admin_user(user)
                
        if not FAST_MODE:
            time.sleep(random.uniform(1, 3))
        else:
            time.sleep(0.05)
            
    print("\nTraffic Simulation Completed!")

if __name__ == "__main__":
    main()