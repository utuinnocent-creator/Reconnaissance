# OSINT Exposure Assessment Tool

##  Disclaimer & Ethics
**This tool is intended for authorized security assessments and educational purposes only.**  
Always ensure you have explicit permission from the organization owner before running OSINT gathering tools against their infrastructure. While OSINT uses publicly available data, aggressive scanning or misuse of API terms of service can lead to IP bans or legal issues. The user assumes all responsibility for compliance with local laws and regulations.

## Overview
This Python script is an Open-Source Intelligence (OSINT) gathering tool designed for cybersecurity analysts, penetration testers, and security researchers. It automates the collection of publicly available information to help organizations understand their digital footprint and potential exposure to attackers.

The tool aggregates data from multiple sources:
- **WHOIS Records:** Retrieves domain registration details, owner information, and administrative contacts.
- **Domain Information:** Performs DNS lookups to identify IP addresses, mail servers (MX), and name servers (NS).
- **Shodan API Integration:** Queries the Shodan database to identify open ports, running services, and known vulnerabilities associated with the target's IP address.

## Features
- **WHOIS Lookup:** Extracts registration data to identify potential social engineering targets or expired domain risks.
- **DNS Reconnaissance:** Maps out domain infrastructure including A, MX, and NS records.
- **Shodan Integration:** Leverages the Shodan API to find exposed devices, open ports, and critical vulnerabilities without sending direct packets to the target.
- **Data Formatting:** Outputs collected data in a structured JSON format for easy analysis and reporting.
- **Error Handling:** Robust handling of API errors, network timeouts, and invalid domains.
- **Security Conscious:** Does not perform active scanning against the target infrastructure (Shodan queries are passive regarding the target).

## Requirements
- **OS:** Linux (Kali, Parrot, Ubuntu), macOS, or Windows.
- **Python:** Python 3.6+
- **Dependencies:**
  - `requests` (For API interactions)
  - `python-whois` (For WHOIS lookups)
  - `dnspython` (For DNS queries)

### Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-name>
