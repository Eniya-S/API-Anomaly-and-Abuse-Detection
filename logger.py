import csv
import os
import time
from datetime import datetime


LOG_FILE = "data/access_logs.csv"



def log_request(request, status_code):


    # Create CSV Header

    if not os.path.exists(LOG_FILE):

        with open(LOG_FILE,"w",newline="") as file:

            writer = csv.writer(file)

            writer.writerow([

                "Timestamp",
                "Username",
                "Persona",
                "IP_Address",
                "Endpoint",
                "Method",
                "Status_Code",
                "Response_Time(ms)",
                "User_Agent"

            ])




    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    username = request.headers.get(

        "X-User",

        "Unknown"

    )


    persona = request.headers.get(

        "X-Persona",

        "Unknown"

    )


    ip = request.remote_addr


    endpoint = request.path


    method = request.method



    response_time = round(

        time.time()*1000 % 500,

        2

    )



    user_agent = request.headers.get(

        "User-Agent",

        "Simulator"

    )




    with open(LOG_FILE,"a",newline="") as file:


        writer = csv.writer(file)


        writer.writerow([

            timestamp,

            username,

            persona,

            ip,

            endpoint,

            method,

            status_code,

            response_time,

            user_agent

        ])