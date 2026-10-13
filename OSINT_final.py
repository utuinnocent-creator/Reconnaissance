"""
OSINT_final.py

This script performs basic Open-Source Intelligence (OSINT) reconnaissance
on a target domain. It gathers:
    1. WHOIS registration data (via the 'whois' library)
    2. Open port / host data from Shodan (via the Shodan REST API)
    3. Basic domain information (IP resolution)

Results are saved to a timestamped JSON file for later analysis, and a
custom User-Agent header is used on all outbound HTTP requests to reduce
the chance of being blocked by basic web security / bot filtering.

Usage:
    python OSINT_final.py
    (then enter a domain name, e.g. microsoft.com, when prompted)

Note: A valid Shodan API key is required to actually retrieve Shodan data.
Register for a free key at https://shodan.io.
"""

import requests
import json
import socket
import whois
from datetime import datetime

# Shodan API key - replace with your own key from https://shodan.io
SHODAN_API_KEY = "your_shodan_api_key_here"

# Custom User-Agent header used on all outbound requests to help avoid
# being blocked by basic web/browser security filtering (Task 6).
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}


def get_whois_info(domain):
    """Fetches WHOIS information for a given domain."""
    try:
        w = whois.whois(domain)
        return w.text
    except Exception as e:
        return f"Error retrieving WHOIS data: {e}"


def get_shodan_info(domain):
    """Fetches Shodan information (open ports/host data) for a given domain."""
    try:
        url = f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={SHODAN_API_KEY}"
        response = requests.get(url, headers=HEADERS)
        ip = response.json().get(domain)

        if ip:
            shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
            shodan_response = requests.get(shodan_url, headers=HEADERS)
            return json.dumps(shodan_response.json(), indent=4)
        else:
            return "No IP found for this domain."
    except Exception as e:
        return f"Error retrieving Shodan data: {e}"


def get_basic_domain_info(domain):
    """Fetches basic domain information, such as the resolved IP address."""
    try:
        ip_address = socket.gethostbyname(domain)
        return {"domain": domain, "resolved_ip": ip_address}
    except Exception as e:
        return f"Error retrieving basic domain info: {e}"


def save_to_json(data, domain):
    """Saves the collected OSINT data to a timestamped JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"osint_results_{domain}_{timestamp}.json"
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"OSINT data successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving data to JSON: {e}")


def main():
    """Main entry point: prompts for a domain, runs all OSINT checks,
    prints the results, and saves them to a JSON file."""
    domain = input("Enter the domain name to investigate: ")

    print("\nGathering WHOIS information...")
    whois_data = get_whois_info(domain)
    print(whois_data)

    print("\nGathering basic domain information...")
    domain_info = get_basic_domain_info(domain)
    print(domain_info)

    print("\nGathering Shodan information...")
    shodan_data = get_shodan_info(domain)
    print(shodan_data)

    results = {
        "domain": domain,
        "whois_info": whois_data,
        "basic_domain_info": domain_info,
        "shodan_info": shodan_data,
    }

    save_to_json(results, domain)

    print("\nOSINT data collection complete.")


if __name__ == "__main__":
    main()
