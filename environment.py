#!/usr/bin/env python


from crayons import blue, green, red
from inspect import currentframe
import requests
import json

# Constants

SECURE_ENDPOINT = {"host": "localhost:4000"}

malware_analytics = {"host": "localhost:4000"}

UMBRELLA = {"en_url": "localhost:4000",
            "inv_url": "localhost:4000", }

THREATRESPONSE = {"host": "localhost:4000"}

XDR = {"host": "localhost:4000"}

VALIDATOR = {"host": "api.firejumpermission.rocks"}

# Fire Jumper Security Programmability Mission TEST Room
WEBEX_TEAMS_ROOM_ID = "Y2lzY29zcGFyazovL3VzLxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# User Input

# Webex Teams
WEBEX_TEAMS_ACCESS_TOKEN = "OGEzYjNmM2YtMjBlZS00NWM1LWIwYTAtMGYxN2E4MGQyODExxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Cisco Umbrella
UMBRELLA_ENFORCEMENT_KEY = "12345678-b9a1-4ad3-82d9-dfe2c93ffffz"
UMBRELLA_INVESTIGATE_KEY = "31801821-b9a1-4ad3-82d9-dfe2c93ffake"

UMBRELLA_ORGANIZATION_ID="123456789"
UMBRELLA_CLIENT_ID="7c46bbf9e629475086e8fad219f9999a"
UMBRELLA_CLIENT_SECRET="1d579c19ed8c474596103239305b418f"
#UMBRELLA_HOST_FOR_TOKEN="api.umbrella.com" # for calls to real umbrella backend
UMBRELLA_HOST_FOR_TOKEN="localhost:4000"  # for call to simulator
#UMBRELLA_REPORT_HOST="reports.api.umbrella.com"
UMBRELLA_REPORT_HOST="localhost:4000" # for call to simulator 
# Cisco SECURE_ENDPOINT
SECURE_ENDPOINT_CLIENT_ID = "defg26458064a05f1faz"
SECURE_ENDPOINT_API_KEY = "12345678-4f95-43d5-908d-7a7d41ad385z"

# Cisco Threat Grid
malware_analytics_API_KEY = "Zjttqveo7g1doaszbc0n6qfzzz"

# Cisco Threat Response
CTR_CLIENT_ID = "client-bbaad7e2-e5ff-413f-1234-0e21bc871zzz"
CTR_API_KEY = "ZezA_VszEcMTCzzzU0Wr5mQypXoxbjFNKDnLa0Mkw_O_ZZ4TND9mZZ"

ARBITRARY_TEXT="""The Young Brown Fox Jumped {replace_me_by_sha256} over the Lazy dog
some text stuff here to showcase the XDR inspect API capability 
Some additional text here after that can be very long
"""

# End User Input

# Helper functions


def print_missing_mission_warn(lineerror):
    print(blue(f"\nPlease replace this function (print_missing_mission_warn(...)) with correct required mission statements!\n"))
    print(green(f"At a hosted event, if you are not making progress, please ask for help from proctor or your neighbour attendee.\n"))
    print(red(f"Check and complete the #TODO at Line number --->  {lineerror}"))
    return exit()

def get_line():
    currentfram=currentframe()
    return currentfram.f_back.f_lineno