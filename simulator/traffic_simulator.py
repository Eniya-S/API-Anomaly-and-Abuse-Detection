import requests
import random
import time
import json


BASE_URL = "http://127.0.0.1:5000"

USERS_FILE = "../data/users.json"


# ---------------- LOAD USERS ----------------

def load_users():

    with open(USERS_FILE, "r") as file:
        return json.load(file)



# ---------------- LOGIN USER ----------------

def login_user(user, persona):

    session = requests.Session()

    # Send user information for logging
    session.headers.update({

        "X-User": user["username"],
        "X-Persona": persona.upper()

    })


    session.post(

        BASE_URL + "/login",

        data={

            "username": user["username"],
            "password": user["password"]

        }

    )


    return session




# ---------------- NORMAL USER ----------------

def normal_user(user):

    session = login_user(
        user,
        "normal"
    )


    pages = [

        "/dashboard",
        "/profile",
        "/products"

    ]


    random.shuffle(pages)


    for page in pages[:random.randint(1,3)]:

        session.get(
            BASE_URL + page
        )

        time.sleep(
            random.uniform(1,3)
        )


    session.get(
        BASE_URL+"/logout"
    )





# ---------------- EXPLORER USER ----------------

def explorer_user(user):

    session = login_user(
        user,
        "explorer"
    )


    pages = [

        "/dashboard",
        "/products",
        "/profile",
        "/api-test"

    ]


    selected = random.sample(

        pages,

        random.randint(2,4)

    )


    for page in selected:


        if page == "/api-test":


            session.post(

                BASE_URL+"/api-test",

                data={

                    "api_name":"Monitoring API",

                    "test_type":"Functional Testing",

                    "request_count":random.randint(5,20)

                }

            )


        else:


            session.get(

                BASE_URL+page

            )


        time.sleep(
            random.uniform(1,3)
        )



    session.get(
        BASE_URL+"/logout"
    )





# ---------------- ADMIN USER ----------------

def admin_user(user):

    session = login_user(
        user,
        "admin"
    )


    session.get(
        BASE_URL+"/dashboard"
    )


    session.post(

        BASE_URL+"/api-test",

        data={

            "api_name":"Authentication API",

            "test_type":"Load Testing",

            "request_count":random.randint(20,100)

        }

    )


    session.get(
        BASE_URL+"/products"
    )


    session.get(
        BASE_URL+"/profile"
    )


    session.get(
        BASE_URL+"/logout"
    )





# ---------------- MALICIOUS USER ----------------

def malicious_user():


    session = requests.Session()


    session.headers.update({

        "X-User":"Unknown Attacker",

        "X-Persona":"MALICIOUS"

    })



    # Brute Force Attack

    for i in range(
        random.randint(10,30)
    ):


        session.post(

            BASE_URL+"/login",

            data={

                "username":"hacker",

                "password":"wrongpassword"

            }

        )


        time.sleep(
            random.uniform(0.1,0.5)
        )




    # API Abuse

    for i in range(
        random.randint(20,60)
    ):


        endpoint=random.choice([

            "/dashboard",
            "/products",
            "/profile"

        ])


        session.get(

            BASE_URL+endpoint

        )






# ---------------- MAIN ----------------


users = load_users()


print("\nTraffic Simulation Started...\n")



for i in range(100):


    persona=random.choice([

        "normal",
        "normal",
        "explorer",
        "admin",
        "malicious"

    ])



    if persona=="malicious":


        print(
            f"Session {i+1}: MALICIOUS USER"
        )


        malicious_user()



    else:


        user=random.choice(users)



        print(

            f"Session {i+1}: {persona.upper()} - {user['username']}"

        )



        if persona=="normal":

            normal_user(user)



        elif persona=="explorer":

            explorer_user(user)



        elif persona=="admin":

            admin_user(user)



    time.sleep(
        random.uniform(1,3)
    )



print("\nTraffic Simulation Completed!")