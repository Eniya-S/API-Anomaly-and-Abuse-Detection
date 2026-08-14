from flask import Flask, g, redirect, render_template, request, session, url_for
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from logger import log_request

app = Flask(__name__)
app.secret_key = "api_anomaly_project"

BASE_DIR = Path(__file__).resolve().parent
SRC_DATA_DIR = BASE_DIR / "data"


def _resolve_data_dir():
    """Return a writable data directory.

    On Vercel (and any read-only filesystem) the project directory cannot be
    written to, so we fall back to /tmp, seeding it with the repo's data files
    on cold start. Note: /tmp is ephemeral, so writes do not persist between
    deployments or across cold starts.
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
USERS_FILE = DATA_DIR / "users.json"
API_TEST_FILE = DATA_DIR / "api_tests.json"

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)

if not os.path.exists(API_TEST_FILE):
    with open(API_TEST_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)


@app.before_request
def before_request():
    g.request_start_time = time.perf_counter()
    g.request_id = str(uuid.uuid4())


@app.after_request
def after_request(response):
    start_time = getattr(g, "request_start_time", None)
    if start_time is not None:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
    else:
        elapsed_ms = 0.0
    try:
        log_request(request, response.status_code, response_time_ms=elapsed_ms)
    except Exception:
        # Logging must never break a response (e.g. read-only filesystem).
        pass
    req_id = getattr(g, "request_id", None)
    if req_id:
        response.headers["X-Request-ID"] = req_id
    return response


@app.errorhandler(Exception)
def handle_exception(error):
    from werkzeug.exceptions import HTTPException
    if isinstance(error, HTTPException):
        return error

    start_time = getattr(g, "request_start_time", None)
    if start_time is not None:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
    else:
        elapsed_ms = 0.0
    try:
        log_request(request, 500, response_time_ms=elapsed_ms)
    except Exception:
        pass
    return "Internal Server Error", 500


# ---------------- LOAD USERS ----------------
def load_users():
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if content == "":
                return []
            return json.loads(content)
    except Exception:
        return []


# ---------------- SAVE USERS ----------------
def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)


# ---------------- API TEST FILE ----------------
def load_api_tests():
    try:
        with open(API_TEST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_api_tests(tests):
    with open(API_TEST_FILE, "w", encoding="utf-8") as f:
        json.dump(tests, f, indent=4)


# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("home.html")


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        users = load_users()

        for user in users:
            if user["username"] == username:
                return "Username already exists!"

        users.append({
            "username": username,
            "email": email,
            "password": password
        })

        save_users(users)
        return redirect(url_for("login"))

    return render_template("signup.html")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        users = load_users()

        for user in users:
            if user["username"] == username and user["password"] == password:
                session["user"] = username
                session["session_id"] = str(uuid.uuid4())
                next_page = session.pop("next_page", "dashboard")
                return redirect(url_for(next_page))

        error = "Invalid Username or Password"

    return render_template("login.html", error=error)


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        session["next_page"] = "dashboard"
        return redirect(url_for("login"))

    total_tests = len(load_api_tests())

    return render_template(
        "dashboard.html",
        username=session["user"],
        total_apis=8,
        active_users=len(load_users()),
        total_tests=total_tests,
    )

# ---------------- PROFILE ----------------
@app.route("/profile")
def profile():
    if "user" not in session:
        session["next_page"] = "profile"
        return redirect(url_for("login"))

    return render_template("profile.html", username=session["user"])


# ---------------- API SERVICES ----------------
@app.route("/products")
def products():
    if "user" not in session:
        session["next_page"] = "products"
        return redirect(url_for("login"))

    services = [
        {"name": "User Management API", "description": "Create and Manage Users"},
        {"name": "Authentication API", "description": "Signup Login Logout"},
        {"name": "Dashboard API", "description": "Shows API Statistics"},
        {"name": "API Monitoring", "description": "Monitors API Requests"},
        {"name": "Anomaly Detection", "description": "Detect Suspicious Behaviour"},
        {"name": "Access Log Service", "description": "Stores API Logs"},
    ]

    return render_template("products.html", services=services)


# ---------------- CHANGE PASSWORD ----------------
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    message = None

    if request.method == "POST":
        username = request.form["username"]
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]

        users = load_users()

        for user in users:
            if user["username"] == username:
                if user["password"] == old_password:
                    user["password"] = new_password
                    save_users(users)
                    message = "Password Updated Successfully!"
                    return render_template("change_password.html", message=message)

                message = "Old Password is Incorrect!"
                return render_template("change_password.html", message=message)

        message = "Username Not Found!"

    return render_template("change_password.html", message=message)


# ---------------- API TEST SERVICE ----------------
@app.route("/api-test", methods=["GET", "POST"])
def api_test():
    if "user" not in session:
        session["next_page"] = "api_test"
        return redirect(url_for("login"))

    if request.method == "POST":
        api_name = request.form["api_name"]
        test_type = request.form["test_type"]
        request_count = int(request.form["request_count"])

        tests = load_api_tests()
        tests.append({
            "username": session["user"],
            "api_name": api_name,
            "test_type": test_type,
            "request_count": request_count,
        })
        save_api_tests(tests)

        return render_template(
            "api_test.html",
            message=f"{request_count} API Requests Generated Successfully",
        )

    return render_template("api_test.html")


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("session_id", None)
    return redirect(url_for("home"))


# ---------------- RUN APP ----------------
if __name__ == "__main__":
    print("API Shield AI Server Started...")
    app.run(debug=True)
