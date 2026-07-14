from flask import Flask, render_template, request, redirect, url_for, session
import json
import os
from logger import log_request

app = Flask(__name__)
app.secret_key = "api_anomaly_project"

USERS_FILE = "data/users.json"

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump([], f)


# ---------------- LOAD USERS ----------------

def load_users():
    try:
        with open(USERS_FILE, "r") as f:
            content = f.read().strip()

            if content == "":
                return []

            return json.loads(content)

    except:
        return []
    

    def load_users():

        try:

            with open(USERS_FILE,"r") as f:

                content = f.read().strip()


            if content == "":
                return []


            return json.loads(content)


        except:

            return []
# ---------------- SAVE USERS ----------------

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)




        # ---------------- API TEST FILE ----------------

# ---------------- API TEST FILE ----------------

API_TEST_FILE = "data/api_tests.json"


if not os.path.exists(API_TEST_FILE):

    with open(API_TEST_FILE, "w") as f:
        json.dump([], f)



def load_api_tests():

    try:

        with open(API_TEST_FILE, "r") as f:

            return json.load(f)

    except:

        return []



def save_api_tests(tests):

    with open(API_TEST_FILE,"w") as f:

        json.dump(
            tests,
            f,
            indent=4
        )
# ---------------- HOME ----------------

@app.route("/")
def home():

    log_request(request, 200)

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

        log_request(request, 200)

        return redirect(url_for("login"))

    return render_template("signup.html")


# ---------------- LOGIN ----------------

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

                log_request(request, 200)

                next_page = session.pop("next_page", "dashboard")

                return redirect(url_for(next_page))

        log_request(request, 401)

        error = "Invalid Username or Password"

    return render_template("login.html", error=error)
# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    if "user" not in session:

        session["next_page"] = "dashboard"

        return redirect(url_for("login"))


    log_request(request,200)


    total_tests = len(load_api_tests())


    return render_template(

        "dashboard.html",

        username=session["user"],

        total_apis=8,

        active_users=len(load_users()),

        total_tests=total_tests

    )
# ---------------- PROFILE ----------------

@app.route("/profile")
def profile():

    if "user" not in session:
        session["next_page"] = "profile"
        return redirect(url_for("login"))

    log_request(request, 200)

    return render_template(
        "profile.html",
        username=session["user"]
    )


# ---------------- API SERVICES ----------------

@app.route("/products")
def products():

    if "user" not in session:
        session["next_page"] = "products"
        return redirect(url_for("login"))

    log_request(request, 200)

    services = [

        {
            "name":"User Management API",
            "description":"Create and Manage Users"
        },

        {
            "name":"Authentication API",
            "description":"Signup Login Logout"
        },

        {
            "name":"Dashboard API",
            "description":"Shows API Statistics"
        },

        {
            "name":"API Monitoring",
            "description":"Monitors API Requests"
        },

        {
            "name":"Anomaly Detection",
            "description":"Detect Suspicious Behaviour"
        },

        {
            "name":"Access Log Service",
            "description":"Stores API Logs"
        }

    ]

    return render_template(
        "products.html",
        services=services
    )


# ---------------- CHANGE PASSWORD ----------------

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

                    log_request(request, 200)

                    message = "Password Updated Successfully!"

                    return render_template(
                        "change_password.html",
                        message=message
                    )

                else:

                    message = "Old Password is Incorrect!"

                    return render_template(
                        "change_password.html",
                        message=message
                    )

        message = "Username Not Found!"

    return render_template(
        "change_password.html",
        message=message
    )


# ---------------- API TEST SERVICE ----------------

# ---------------- API TEST SERVICE ----------------

# ---------------- API TEST SERVICE ----------------

@app.route("/api-test", methods=["GET","POST"])
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

            "username":session["user"],

            "api_name":api_name,

            "test_type":test_type,

            "request_count":request_count

        })



        save_api_tests(tests)



        # Generate logs based on request count

        for i in range(request_count):

            log_request(request,200)



        return render_template(

            "api_test.html",

            message=f"{request_count} API Requests Generated Successfully"

        )



    return render_template("api_test.html")
# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    session.pop("user", None)

    log_request(request, 200)

    return redirect(url_for("home"))


# ---------------- RUN APP ----------------

if __name__ == "__main__":

    print("API Shield AI Server Started...")

    app.run(debug=True)