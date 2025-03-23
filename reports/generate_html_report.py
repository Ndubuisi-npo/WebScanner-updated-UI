import os
from datetime import datetime
from modules.sql_injection_check import sql_injection_check
from modules.xss_check import xss_check
from modules.security_misconfiguration_check import security_misconfiguration_check
from modules.subdomain_enumeration import subdomain_enumeration
from modules.sensitive_info_exposure_check import sensitive_info_exposure_check


def generate_html_report(title, subdomains, vulnerabilities):
    """Generates an HTML report with the given title, subdomains, and vulnerabilities."""
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f4f4f9;
                color: #333;
            }}
            h1 {{
                color: #444;
            }}
            .section {{
                margin-bottom: 20px;
            }}
            .section h2 {{
                color: #555;
            }}
            .content {{
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                background: #fff;
            }}
            li {{
                margin-bottom: 5px;
            }}
        </style>
    </head>
    <body>
        <h1>{title}</h1>
        <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <div class="section">
            <h2>Subdomains Found</h2>
            <div class="content">
                {generate_list_html(subdomains, "No subdomains found.")}
            </div>
        </div>

        <div class="section">
            <h2>Vulnerabilities Detected</h2>
            <div class="content">
                {generate_list_html(vulnerabilities, "No vulnerabilities detected.")}
            </div>
        </div>
    </body>
    </html>
    """
    report_path = "report.html"
    with open(report_path, "w") as report_file:
        report_file.write(html_template)
    print(f"Report generated successfully: {os.path.abspath(report_path)}")


def generate_list_html(items, empty_message):
    """Helper function to generate an HTML list."""
    if items:
        return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"
    else:
        return f"<p>{empty_message}</p>"


def main():
    # Get user input
    url = input("Enter the target URL (e.g., http://example.com): ").strip()
    domain = url.replace("http://", "").replace("https://", "").split('/')[0]

    # Perform subdomain enumeration
    print("Enumerating subdomains...")
    subdomains = subdomain_enumeration(domain)
    print(f"Subdomains Found: {', '.join(subdomains) if subdomains else 'No subdomains found.'}")

    # Perform vulnerability checks
    vulnerabilities = []

    print("Running SQL Injection check...")
    sql_results = sql_injection_check(url)
    if sql_results:
        vulnerabilities.append(f"SQL Injection detected: {sql_results}")

    print("Running XSS check...")
    xss_results = xss_check(url)
    if xss_results:
        vulnerabilities.append(f"XSS detected: {xss_results}")

    print("Running Security Misconfiguration check...")
    security_results = security_misconfiguration_check(url)
    if security_results:
        vulnerabilities.append(f"Security misconfiguration detected: {security_results}")

    print("Running Sensitive Information Exposure check...")
    sensitive_info_results = sensitive_info_exposure_check(url)
    if sensitive_info_results:
        vulnerabilities.append(f"Sensitive information exposed: {sensitive_info_results}")

    # Generate the HTML report
    generate_html_report("Web Scanner Report", subdomains, vulnerabilities)


if __name__ == "__main__":
    main()
