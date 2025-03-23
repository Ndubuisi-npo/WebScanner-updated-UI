import requests

def security_misconfiguration_check(url):
    print("\n[+] Checking for Security Misconfigurations...")
    sensitive_paths = ["/admin", "/config", "/backup"]

    for path in sensitive_paths:
        test_url = url + path
        try:
            response = requests.get(test_url, timeout=50)
            if response.status_code == 200:
                print(f"[!] Sensitive path accessible: {test_url}")
            else:
                print(f"[-] No issue found with {test_url}")
        except requests.exceptions.RequestException as e:
            print(f"[Error] Could not connect to {test_url}: {e}")
