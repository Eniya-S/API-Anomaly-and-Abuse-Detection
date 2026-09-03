from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for
)

import json
import os
import time
import uuid
import shutil

from pathlib import Path

import requests

from dotenv import load_dotenv

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from logger import log_request


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# FLASK
# =========================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "api_anomaly_project"
)


BASE_DIR = Path(__file__).resolve().parent


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
# ORIGINAL PROJECT DATA FILES
# =========================================================

LOCAL_USERS_FILE = (
    BASE_DIR
    / "data"
    / "users.json"
)

LOCAL_API_TEST_FILE = (
    BASE_DIR
    / "data"
    / "api_tests.json"
)


# =========================================================
# VERCEL / LOCAL FILE PATHS
# =========================================================

if os.getenv("VERCEL"):

    # Vercel filesystem is read-only except /tmp
    USERS_FILE = Path(
        "/tmp/users.json"
    )

    API_TEST_FILE = Path(
        "/tmp/api_tests.json"
    )

    # -----------------------------------------------------
    # Copy existing project users to /tmp
    # -----------------------------------------------------

    if (
        not USERS_FILE.exists()
        and LOCAL_USERS_FILE.exists()
    ):

        try:

            shutil.copy2(
                LOCAL_USERS_FILE,
                USERS_FILE
            )

            print(
                "[USERS] Existing users copied to Vercel /tmp"
            )

        except Exception as error:

            print(
                "[USERS] Copy error:",
                error
            )

else:

    USERS_FILE = LOCAL_USERS_FILE

    API_TEST_FILE = LOCAL_API_TEST_FILE


# =========================================================
# CREATE DIRECTORIES
# =========================================================

USERS_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

API_TEST_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)


# =========================================================
# CREATE LOCAL FILES IF NOT EXISTS
# =========================================================

if not USERS_FILE.exists():

    with open(
        USERS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            [],
            file,
            indent=4
        )


if not API_TEST_FILE.exists():

    with open(
        API_TEST_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            [],
            file,
            indent=4
        )


# =========================================================
# BEFORE REQUEST
# =========================================================

@app.before_request
def before_request():

    g.request_start_time = (
        time.perf_counter()
    )

    g.request_id = str(
        uuid.uuid4()
    )


# =========================================================
# AFTER REQUEST
# =========================================================

@app.after_request
def after_request(response):

    start_time = getattr(
        g,
        "request_start_time",
        None
    )

    if start_time is not None:

        elapsed_ms = round(

            (
                time.perf_counter()
                - start_time
            ) * 1000,

            2

        )

    else:

        elapsed_ms = 0.0


    # -----------------------------------------------------
    # Log every API request
    # -----------------------------------------------------

    try:

        log_request(

            request,

            response.status_code,

            response_time_ms=elapsed_ms

        )

    except Exception as error:

        print(
            "[LOGGER ERROR]",
            error
        )


    # -----------------------------------------------------
    # Add Request ID
    # -----------------------------------------------------

    request_id = getattr(
        g,
        "request_id",
        None
    )


    if request_id:

        response.headers[
            "X-Request-ID"
        ] = request_id


    return response


# =========================================================
# ERROR HANDLER
# =========================================================

@app.errorhandler(Exception)
def handle_exception(error):

    from werkzeug.exceptions import (
        HTTPException
    )


    # Let Flask handle normal HTTP errors
    if isinstance(
        error,
        HTTPException
    ):

        return error


    start_time = getattr(
        g,
        "request_start_time",
        None
    )


    if start_time is not None:

        elapsed_ms = round(

            (
                time.perf_counter()
                - start_time
            ) * 1000,

            2

        )

    else:

        elapsed_ms = 0.0


    # -----------------------------------------------------
    # Log unexpected errors
    # -----------------------------------------------------

    try:

        log_request(

            request,

            500,

            response_time_ms=elapsed_ms

        )

    except Exception as log_error:

        print(
            "[LOGGER ERROR]",
            log_error
        )


    return (
        "Internal Server Error",
        500
    )


# =========================================================
# GOOGLE SHEET REQUEST
# =========================================================
#
# IMPORTANT:
# Google Sheet is used ONLY for API LOGGING.
# It is NOT used for user authentication.
#
# =========================================================

def google_sheet_request(payload):

    if not WEBHOOK_URL:

        print(
            "[GOOGLE] "
            "GOOGLE_WEBHOOK_URL missing"
        )

        return None


    try:

        data = dict(
            payload
        )


        data[
            "webhook_token"
        ] = WEBHOOK_TOKEN or ""


        response = requests.post(

            WEBHOOK_URL,

            json=data,

            timeout=10

        )


        print(
            "[GOOGLE] Response:",
            response.status_code
        )


        if response.status_code != 200:

            print(
                "[GOOGLE] HTTP error:",
                response.status_code
            )

            return None


        try:

            return response.json()

        except ValueError:

            print(
                "[GOOGLE] Invalid JSON response"
            )

            return None


    except requests.RequestException as error:

        print(
            "[GOOGLE] Connection error:",
            error
        )

        return None


    except Exception as error:

        print(
            "[GOOGLE] Error:",
            error
        )

        return None


# =========================================================
# LOCAL USERS
# =========================================================

def load_users():

    try:

        with open(
            USERS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            content = (
                file.read().strip()
            )


            if not content:

                return []


            users = json.loads(
                content
            )


            if not isinstance(
                users,
                list
            ):

                return []


            return users


    except Exception as error:

        print(
            "[LOCAL USERS] Error:",
            error
        )

        return []


# =========================================================
# SAVE LOCAL USERS
# =========================================================

def save_users(users):

    try:

        with open(
            USERS_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                users,
                file,
                indent=4
            )

        return True


    except Exception as error:

        print(
            "[LOCAL USERS] Save error:",
            error
        )

        return False


# =========================================================
# FIND USER
# =========================================================

def find_user(username):

    users = load_users()


    for user in users:

        stored_username = str(
            user.get(
                "username",
                ""
            )
        ).strip()


        if (
            stored_username.lower()
            == username.strip().lower()
        ):

            return user


    return None


# =========================================================
# API TESTS
# =========================================================

def load_api_tests():

    try:

        with open(
            API_TEST_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            content = (
                file.read().strip()
            )


            if not content:

                return []


            return json.loads(
                content
            )


    except Exception as error:

        print(
            "[API TEST] Load error:",
            error
        )

        return []


# =========================================================
# SAVE API TESTS
# =========================================================

def save_api_tests(tests):

    try:

        with open(
            API_TEST_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                tests,
                file,
                indent=4
            )

        return True


    except Exception as error:

        print(
            "[API TEST] Save error:",
            error
        )

        return False


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return render_template(
        "home.html"
    )


# =========================================================
# SIGNUP
# =========================================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if request.method == "POST":

        username = (
            request.form.get(
                "username",
                ""
            )
            .strip()
        )


        email = (
            request.form.get(
                "email",
                ""
            )
            .strip()
        )


        password = request.form.get(
            "password",
            ""
        )


        # -------------------------------------------------
        # BASIC VALIDATION
        # -------------------------------------------------

        if not username:

            return (
                "Username is required.",
                400
            )


        if not email:

            return (
                "Email is required.",
                400
            )


        if not password:

            return (
                "Password is required.",
                400
            )


        # -------------------------------------------------
        # CHECK EXISTING USER
        # -------------------------------------------------

        users = load_users()


        for user in users:

            existing_username = str(
                user.get(
                    "username",
                    ""
                )
            ).strip().lower()


            if (
                existing_username
                == username.lower()
            ):

                return (
                    "Username already exists!",
                    400
                )


        # -------------------------------------------------
        # CREATE PASSWORD HASH
        # -------------------------------------------------

        password_hash = (
            generate_password_hash(
                password
            )
        )


        # -------------------------------------------------
        # SAVE USER LOCALLY
        # -------------------------------------------------

        users.append({

            "username":
                username,

            "email":
                email,

            "password_hash":
                password_hash

        })


        saved = save_users(
            users
        )


        if not saved:

            return (
                "Unable to create user.",
                500
            )


        print(
            "[SIGNUP] "
            "User saved:",
            username
        )


        return redirect(
            url_for("login")
        )


    return render_template(
        "signup.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    error = None


    if request.method == "POST":

        username = (
            request.form.get(
                "username",
                ""
            )
            .strip()
        )


        password = request.form.get(
            "password",
            ""
        )


        # -------------------------------------------------
        # BASIC VALIDATION
        # -------------------------------------------------

        if not username or not password:

            error = (
                "Please enter "
                "username and password."
            )


            return render_template(

                "login.html",

                error=error

            )


        # -------------------------------------------------
        # FIND EXISTING USER
        # -------------------------------------------------

        user = find_user(
            username
        )


        if user is None:

            print(
                "[LOGIN] "
                "User not found:",
                username
            )


            error = (
                "Invalid Username "
                "or Password"
            )


            return render_template(

                "login.html",

                error=error

            )


        stored_username = str(
            user.get(
                "username",
                username
            )
        ).strip()


        # -------------------------------------------------
        # HASHED PASSWORD
        # -------------------------------------------------

        stored_hash = user.get(
            "password_hash"
        )


        if stored_hash:

            try:

                password_valid = (
                    check_password_hash(

                        stored_hash,

                        password

                    )
                )


            except Exception as password_error:

                print(
                    "[LOGIN] "
                    "Password check error:",
                    password_error
                )

                password_valid = False


            if password_valid:

                session[
                    "user"
                ] = stored_username


                session[
                    "session_id"
                ] = str(
                    uuid.uuid4()
                )


                next_page = session.pop(

                    "next_page",

                    "dashboard"

                )


                print(
                    "[LOGIN] "
                    "Login successful:",
                    stored_username
                )


                return redirect(
                    url_for(next_page)
                )


        # -------------------------------------------------
        # OLD PLAINTEXT PASSWORD SUPPORT
        #
        # This supports old users.json files that still
        # contain:
        #
        # "password": "password"
        #
        # After successful login it is automatically
        # converted into password_hash.
        # -------------------------------------------------

        old_password = user.get(
            "password"
        )


        if (
            old_password is not None
            and old_password == password
        ):

            user[
                "password_hash"
            ] = (
                generate_password_hash(
                    password
                )
            )


            user.pop(
                "password",
                None
            )


            users = load_users()


            for index, existing_user in enumerate(users):

                if (
                    str(
                        existing_user.get(
                            "username",
                            ""
                        )
                    )
                    .strip()
                    .lower()
                    == stored_username.lower()
                ):

                    users[index] = user

                    break


            save_users(
                users
            )


            session[
                "user"
            ] = stored_username


            session[
                "session_id"
            ] = str(
                uuid.uuid4()
            )


            next_page = session.pop(

                "next_page",

                "dashboard"

            )


            print(
                "[LOGIN] "
                "Old password migrated:",
                stored_username
            )


            return redirect(
                url_for(next_page)
            )


        # -------------------------------------------------
        # INVALID PASSWORD
        # -------------------------------------------------

        print(
            "[LOGIN] "
            "Invalid password:",
            stored_username
        )


        error = (
            "Invalid Username "
            "or Password"
        )


    return render_template(

        "login.html",

        error=error

    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:

        session[
            "next_page"
        ] = "dashboard"


        return redirect(
            url_for("login")
        )


    total_tests = len(
        load_api_tests()
    )


    users = load_users()


    return render_template(

        "dashboard.html",

        username=session["user"],

        total_apis=8,

        active_users=len(
            users
        ),

        total_tests=total_tests

    )


# =========================================================
# PROFILE
# =========================================================

@app.route("/profile")
def profile():

    if "user" not in session:

        session[
            "next_page"
        ] = "profile"


        return redirect(
            url_for("login")
        )


    return render_template(

        "profile.html",

        username=session["user"]

    )


# =========================================================
# PRODUCTS
# =========================================================

@app.route("/products")
def products():

    if "user" not in session:

        session[
            "next_page"
        ] = "products"


        return redirect(
            url_for("login")
        )


    services = [

        {
            "name":
                "User Management API",

            "description":
                "Create and Manage Users"
        },

        {
            "name":
                "Authentication API",

            "description":
                "Signup Login Logout"
        },

        {
            "name":
                "Dashboard API",

            "description":
                "Shows API Statistics"
        },

        {
            "name":
                "API Monitoring",

            "description":
                "Monitors API Requests"
        },

        {
            "name":
                "Anomaly Detection",

            "description":
                "Detect Suspicious Behaviour"
        },

        {
            "name":
                "Access Log Service",

            "description":
                "Stores API Logs"
        }

    ]


    return render_template(

        "products.html",

        services=services

    )


# =========================================================
# CHANGE PASSWORD
# =========================================================

@app.route(
    "/change-password",
    methods=["GET", "POST"]
)
def change_password():

    message = None


    if request.method == "POST":

        username = (
            request.form.get(
                "username",
                ""
            )
            .strip()
        )


        old_password = request.form.get(
            "old_password",
            ""
        )


        new_password = request.form.get(
            "new_password",
            ""
        )


        users = load_users()


        for user in users:

            stored_username = str(
                user.get(
                    "username",
                    ""
                )
            ).strip()


            if (
                stored_username.lower()
                == username.lower()
            ):

                stored_hash = user.get(
                    "password_hash"
                )


                if stored_hash:

                    try:

                        valid = (
                            check_password_hash(

                                stored_hash,

                                old_password

                            )
                        )

                    except Exception:

                        valid = False


                else:

                    valid = (
                        user.get(
                            "password"
                        )
                        == old_password
                    )


                if valid:

                    user[
                        "password_hash"
                    ] = (
                        generate_password_hash(
                            new_password
                        )
                    )


                    user.pop(
                        "password",
                        None
                    )


                    save_users(
                        users
                    )


                    message = (
                        "Password Updated "
                        "Successfully!"
                    )


                    return render_template(

                        "change_password.html",

                        message=message

                    )


                message = (
                    "Old Password "
                    "is Incorrect!"
                )


                return render_template(

                    "change_password.html",

                    message=message

                )


        message = (
            "Username Not Found!"
        )


    return render_template(

        "change_password.html",

        message=message

    )


# =========================================================
# API TEST
# =========================================================

@app.route(
    "/api-test",
    methods=["GET", "POST"]
)
def api_test():

    if "user" not in session:

        session[
            "next_page"
        ] = "api_test"


        return redirect(
            url_for("login")
        )


    if request.method == "POST":

        api_name = request.form.get(
            "api_name",
            ""
        )


        test_type = request.form.get(
            "test_type",
            ""
        )


        try:

            request_count = int(

                request.form.get(
                    "request_count",
                    "0"
                )

            )

        except ValueError:

            request_count = 0


        tests = load_api_tests()


        tests.append({

            "username":
                session["user"],

            "api_name":
                api_name,

            "test_type":
                test_type,

            "request_count":
                request_count

        })


        save_api_tests(
            tests
        )


        return render_template(

            "api_test.html",

            message=(

                f"{request_count} "

                "API Requests Generated "

                "Successfully"

            )

        )


    return render_template(
        "api_test.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.pop(
        "user",
        None
    )


    session.pop(
        "session_id",
        None
    )


    return redirect(
        url_for("home")
    )


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    print(
        "API Shield AI Server Started..."
    )


    print(
        "[GOOGLE] Webhook:",
        "Configured"
        if WEBHOOK_URL
        else "NOT CONFIGURED"
    )


    print(
        "[AUTH] User Database:",
        str(USERS_FILE)
    )


    app.run(

        debug=True,

        host="0.0.0.0",

        port=3000

    )