from flask import Flask, render_template, request, redirect, session
from database.db_connection import get_db_connection
from utils.password_checker import check_password_strength
from utils.phishing_detector import detect_phishing
from utils.vulnerability_scanner import scan_vulnerabilities
from werkzeug.security import generate_password_hash, check_password_hash
from utils.validators import is_valid_password, is_valid_url
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from flask import send_file
import io
import os

app = Flask(__name__)
app.secret_key = "secret123"

# HOME
@app.route('/')
def home():
    return redirect('/dashboard')

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)  # ✅ correct

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password)  # ✅ FIXED
        )
        conn.commit()

        return redirect('/login')

    return render_template('register.html')


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # ✅ get user first
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        # ✅ check hash
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect('/dashboard')
        else:
            return "Invalid login ❌"

    return render_template('login.html')


# DASHBOARD
@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ Guest user
    if not user_id:
        username = "Guest"
        total_scans = session.get('guest_count', 0)

        recent_scans = []  # ❌ no history for guest

    else:
        # ✅ Logged in user
        cursor.execute("SELECT username FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()

        username = user['username']

        cursor.execute("SELECT COUNT(*) as total FROM scans WHERE user_id=%s", (user_id,))
        total_scans = cursor.fetchone()['total']

        cursor.execute(
            "SELECT tool_type, result, created_at FROM scans WHERE user_id=%s ORDER BY created_at DESC LIMIT 5",
            (user_id,)
        )
        recent_scans = cursor.fetchall()

    return render_template(
        'dashboard.html',
        username=username,
        total_scans=total_scans,
        recent_scans=recent_scans,
        is_guest=(user_id is None)
    )

# LOGOUT
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/?message=logged_out')


# PASSWORD CHECKER
@app.route('/password-checker', methods=['GET', 'POST'])
def password_checker():
    result = None
    why = None
    score = 0
    error = None
    color = None
    password = ""

    user_id = session.get('user_id')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        password = request.form['password']

        # ✅ EMPTY CHECK
        if not password.strip():
            error = "Please enter a password"

        else:
            # ✅ GUEST USER (session-based limit)
            if not user_id:
                if 'guest_password_count' not in session:
                    session['guest_password_count'] = 0

                if session['guest_password_count'] >= 5:
                    error = "Guest scan limit reached (5). Please register."
                else:
                    session['guest_password_count'] += 1

                    data = check_password_strength(password)

                    result = data['level']
                    why = data['why']
                    score = data['score']

            # ✅ LOGGED-IN USER (database save)
            else:
                data = check_password_strength(password)

                result = data['level']
                why = data['why']
                score = data['score']

                cursor.execute(
                    "INSERT INTO scans (user_id, tool_type, result) VALUES (%s, %s, %s)",
                    (user_id, "password_checker", result)
                )
                conn.commit()

    # ✅ COLOR LOGIC
    if result == "Weak ❌":
        color = "red"
    elif result == "Medium ⚠️":
        color = "orange"
    elif result == "Strong ✅":
        color = "green"

    return render_template(
        'password_checker.html',
        result=result,
        why=why,
        score=score,
        error=error,
        color=color,
        is_guest=(user_id is None),
        last_input=password
    )

# HISTORY
@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM scans WHERE user_id=%s ORDER BY created_at DESC", (user_id,))
    scans = cursor.fetchall()

    return render_template('history.html', scans=scans)


# PHISHING
@app.route('/phishing-detector', methods=['GET', 'POST'])
def phishing_detector():
    result = None
    why = None
    error = None

    user_id = session.get('user_id')

    if request.method == 'POST':
        url = request.form['url']

        if not url.strip():
            error = "Please enter a URL"

        elif not is_valid_url(url):
            error = "Invalid URL format"

        else:
            if not user_id:
                if 'guest_phishing_count' not in session:
                    session['guest_phishing_count'] = 0

                if session['guest_phishing_count'] >= 5:
                    error = "Guest limit reached (5). Please register."
                else:
                    session['guest_phishing_count'] += 1

                    data = detect_phishing(url)
                    result = data['result']
                    why = data['why']

            else:
                data = detect_phishing(url)
                result = data['result']
                why = data['why']

                conn = get_db_connection()
                cursor = conn.cursor()

                cursor.execute(
                    "INSERT INTO scans (user_id, tool_type, result) VALUES (%s, %s, %s)",
                    (user_id, "phishing_detector", result)
                )
                conn.commit()

    return render_template(
        'phishing_detector.html',
        result=result,
        why=why,
        error=error,
        is_guest=(user_id is None),
        last_input=url if request.method == 'POST' else ""
    )

# VULNERABILITY
@app.route('/vulnerability-scanner', methods=['GET', 'POST'])
def vulnerability_scanner():
    result = None
    why = None
    error = None

    user_id = session.get('user_id')

    if request.method == 'POST':
        url = request.form['url']

        if not url.strip():
            error = "Please enter a URL"

        elif not is_valid_url(url):
            error = "Invalid URL format"

        else:
            if not user_id:
                if 'guest_vuln_count' not in session:
                    session['guest_vuln_count'] = 0

                if session['guest_vuln_count'] >= 5:
                    error = "Guest limit reached (5). Please register."
                else:
                    session['guest_vuln_count'] += 1

                    data = scan_vulnerabilities(url)
                    result = data['result']
                    why = data['why']

            else:
                data = scan_vulnerabilities(url)
                result = data['result']
                why = data['why']

                conn = get_db_connection()
                cursor = conn.cursor()

                cursor.execute(
                    "INSERT INTO scans (user_id, tool_type, result) VALUES (%s, %s, %s)",
                    (user_id, "vulnerability_scanner", result)
                )
                conn.commit()

    return render_template(
        'vulnerability_scanner.html',
        result=result,
        why=why,
        error=error,
        is_guest=(user_id is None),
        last_input=url if request.method == 'POST' else ""
    )

# 404 ERROR (page not found)
@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', message="Page not found"), 404


# 500 ERROR (server error)
@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', message="Internal server error"), 500

# REPORT Download
@app.route('/download-report')
def download_report():

    # ✅ BLOCK guest
    if 'user_id' not in session:
        return "Please login to download report ❌"

    tool = request.args.get('tool')
    input_data = request.args.get('input')
    result = request.args.get('result')
    explanation = request.args.get('why')

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()

    content = []

    content.append(Paragraph("SecureScan Report", styles['Title']))
    content.append(Spacer(1, 10))

    content.append(Paragraph(f"Tool Used: {tool}", styles['Normal']))
    content.append(Paragraph(f"Input: {input_data}", styles['Normal']))
    content.append(Paragraph(f"Result: {result}", styles['Normal']))
    content.append(Spacer(1, 10))

    if explanation:
        content.append(Paragraph("Why This Matters:", styles['Heading3']))
        content.append(Paragraph(explanation, styles['Normal']))

    doc.build(content)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name="report.pdf")

# HISTORY Download
@app.route('/download-history')
def download_history():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT tool_type, result, created_at FROM scans WHERE user_id=%s", (user_id,))
    scans = cursor.fetchall()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()

    content = []
    content.append(Paragraph("SecureScan Full History Report", styles['Title']))

    for scan in scans:
        content.append(Spacer(1, 10))
        content.append(Paragraph(f"Tool: {scan['tool_type']}", styles['Normal']))
        content.append(Paragraph(f"Result: {scan['result']}", styles['Normal']))
        content.append(Paragraph(f"Time: {scan['created_at']}", styles['Normal']))

    doc.build(content)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name="history.pdf")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)