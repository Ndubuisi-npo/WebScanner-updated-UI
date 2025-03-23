from flask import Flask, redirect, render_template, request, jsonify, session, url_for, send_file
import requests
from modules.sql_injection_check import sql_injection_check
from modules.xss_check import xss_check
from modules.security_misconfiguration_check import security_misconfiguration_check
from modules.subdomain_enumeration import subdomain_enumeration
from modules.sensitive_info_exposure_check import sensitive_info_exposure_check
import mysql.connector
import ast  # Import the module to safely convert string to dictionary
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
import io


def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",  # Default XAMPP user
        password="paul",  # Default is empty in XAMPP
        database="scanner_db"
    )

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Required for session management

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/test_juice_shop")
def test_juice_shop():
    JUICE_SHOP_URL = "http://localhost:3000"  # Ensure the correct target is used

    scan_payload = {
        "url": JUICE_SHOP_URL,
        "checks": ["sql_injection", "xss", "sensitive_info"]
    }
    response = requests.post("http://localhost:5000/scan", json=scan_payload)
    return response.json()



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user:
            session["logged_in"] = True
            session["username"] = user["username"]  # Store username in session
            return redirect(url_for("home"))  # Redirect to home page
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("home"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", 
                           (username, email, password))
            conn.commit()
            session["logged_in"] = True
            session["username"] = username  # Store username in session
            return redirect(url_for("home"))
        except mysql.connector.IntegrityError:
            return render_template("signup.html", error="Email already exists")

        cursor.close()
        conn.close()

    return render_template("signup.html")



@app.route("/results")
def results():
    if "logged_in" not in session:
        return render_template("no_access.html")  # Show access restriction message

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, scan_date, scan_types FROM scans 
        WHERE user_id = (SELECT id FROM users WHERE username = %s)
        ORDER BY scan_date DESC
    """, (session["username"],))
    
    scans = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("results.html", scans=scans)

@app.route("/scan_report/<int:scan_id>")
def scan_report(scan_id):
    if "logged_in" not in session:
        return render_template("no_access.html")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
    scan = cursor.fetchone()

    cursor.close()
    conn.close()

    if not scan:
        return "Scan report not found.", 404

    # Convert string back to dictionary
    try:
        scan["scan_results"] = ast.literal_eval(scan["scan_results"])  # Convert string to dict
    except (ValueError, SyntaxError):
        scan["scan_results"] = {"Error": "Could not parse scan results"}

    return render_template("scan_report.html", scan=scan)


@app.route("/download_report/<int:scan_id>")
def download_report(scan_id):
    if "logged_in" not in session:
        return render_template("no_access.html")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
    scan = cursor.fetchone()

    cursor.close()
    conn.close()

    if not scan:
        return "Scan report not found.", 404

    # Convert scan results string to dictionary
    try:
        scan["scan_results"] = ast.literal_eval(scan["scan_results"])
    except (ValueError, SyntaxError):
        scan["scan_results"] = {"Error": "Could not parse scan results"}

    # Create a PDF in memory
    pdf_buffer = io.BytesIO()
    pdf = canvas.Canvas(pdf_buffer, pagesize=letter)
    pdf.setFont("Helvetica", 12)

    # Add Report Header
    pdf.drawString(200, 750, "🛡️ Security Scan Report")
    pdf.drawString(50, 730, f"Date: {scan['scan_date']}")
    pdf.drawString(50, 710, f"Scans Performed: {scan['scan_types']}")

    # Add Scan Results with Word Wrapping
    y_position = 690
    max_width = 500  # Adjust width for wrapping

    for key, value in scan["scan_results"].items():
        pdf.drawString(50, y_position, f"{key}:")
        y_position -= 20  # Move text down

        # Wrap long text properly
        wrapped_text = simpleSplit(str(value), "Helvetica", 12, max_width)
        for line in wrapped_text:
            pdf.drawString(70, y_position, line)  # Indent result
            y_position -= 20  # Move to next line

        y_position -= 10  # Extra spacing between results

        # Prevent text from going off the page
        if y_position < 50:
            pdf.showPage()
            pdf.setFont("Helvetica", 12)
            y_position = 750  # Reset position for new page

    pdf.showPage()
    pdf.save()
    pdf_buffer.seek(0)

    return send_file(pdf_buffer, as_attachment=True, download_name="Scan_Report.pdf", mimetype="application/pdf")



@app.route("/scan", methods=["POST"])
def scan():
    if "logged_in" not in session:
        return jsonify({"error": "You must be logged in to perform a scan."})

    data = request.json
    url = data.get("url")
    checks = data.get("checks", [])

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the user ID from the database
    cursor.execute("SELECT id FROM users WHERE username = %s", (session["username"],))
    user = cursor.fetchone()
    if not user:
        return jsonify({"error": "User not found."})
    
    user_id = user[0]  # Get user ID

    results = {}

    if "sql_injection" in checks:
        result = sql_injection_check(url)
        results["SQL Injection"] = result if result else "No SQL Injection vulnerability found."

    if "xss" in checks:
        result = xss_check(url)
        results["XSS"] = result if result else "No XSS vulnerability found."

    if "security_misconfiguration" in checks:
        result = security_misconfiguration_check(url)
        results["Security Misconfigurations"] = result if result else "No Security Misconfigurations found."

    if "sensitive_info" in checks:
        result = sensitive_info_exposure_check(url)
        results["Sensitive Information Exposure"] = result if result else "No Sensitive Information Exposure found."

    if "subdomain_enum" in checks:
        domain = url.replace("http://", "").replace("https://", "").split('/')[0]
        subdomains = subdomain_enumeration(domain)
        results["Subdomain Enumeration"] = "<br>".join(subdomains) if subdomains else "No Active Subdomains found."

    # Convert results to string format for database storage
    scan_types = ", ".join(checks)
    scan_results = str(results)

    # Insert the scan into the database
    cursor.execute("INSERT INTO scans (user_id, scan_types, scan_results) VALUES (%s, %s, %s)", 
                   (user_id, scan_types, scan_results))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=True)
