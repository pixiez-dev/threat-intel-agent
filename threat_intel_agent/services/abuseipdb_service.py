# abuseipdb_service.py

import os
import requests
from dotenv import load_dotenv  # 1. Import the library

# 2. Find and load the .env file
load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def check_ip(ip_address: str):

    if not ABUSEIPDB_API_KEY:
        raise ValueError(
            "ABUSEIPDB_API_KEY is not set. Add it to .env to enable live IP reputation checks."
        )

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=30
    )

    response.raise_for_status()

    return response.json()