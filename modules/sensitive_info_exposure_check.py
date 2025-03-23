import requests

def sensitive_info_exposure_check(url):
    sensitive_endpoints = [
        "/ftp/legal.md",  # Legal Docs
        "/encryptionkeys/tokens",  # Exposed tokens
        "/.git/config",  # Git history leak
        "/.env",  # Environment variables
        "/logs/error.log"  # Logs with sensitive data
    ]

    found_vulnerabilities = []

    for endpoint in sensitive_endpoints:
        test_url = url + endpoint
        response = requests.get(test_url)

        if response.status_code == 200 and len(response.text) > 10:
            found_vulnerabilities.append(f"Sensitive info found at {test_url}")

    return found_vulnerabilities if found_vulnerabilities else None
