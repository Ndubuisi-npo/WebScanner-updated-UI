import requests

def subdomain_enumeration(domain):
    print("\n[+] Checking for Subdomains...")
    subdomains_found = []

    common_subdomains = ["www", "mail", "about", "goals", "ftp", "blog", "dev", "test", "api", "staging"]

    for sub in common_subdomains:
        subdomain = f"http://{sub}.{domain}"
        try:
            response = requests.get(subdomain, timeout=20)
            if response.status_code == 200:
                print(f"[+] Active subdomain found: {subdomain}")
                subdomains_found.append(subdomain)
            else:
                print(f"[-] No response from {subdomain}")
        except requests.ConnectionError:
            print(f"[-] Subdomain not found: {subdomain}")

    return subdomains_found
