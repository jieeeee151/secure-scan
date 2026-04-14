from flask import Flask, render_template, request, redirect, session
from database.db_connection import get_db_connection
from utils.password_checker import check_password_strength
from utils.phishing_detector import detect_phishing
from utils.vulnerability_scanner import scan_vulnerabilities
from werkzeug.security import generate_password_hash, check_password_hash
from utils.validators import is_valid_password, is_valid_url
from flask import send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.units import mm
import datetime
import io
import os

app = Flask(__name__, static_folder='static')
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
            session['username'] = user['username']
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
    session.pop('username', None)
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
                    return render_template(
                        'password_checker.html',
                        error="LIMIT_REACHED",
                        is_guest=True
                    )
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

@app.route('/about')
def about():
    return render_template('about.html')

# HISTORY
@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    page = request.args.get('page', 1, type=int)
    per_page = 15
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # total count
    cursor.execute(
        "SELECT COUNT(*) AS total FROM scans WHERE user_id = %s",
        (user_id,)
    )
    total_scans = cursor.fetchone()['total']

    # 🔥 FIX HERE → ADD id
    cursor.execute("""
        SELECT id, tool_type, result, created_at
        FROM scans
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
    """, (user_id, per_page, offset))

    scans = cursor.fetchall()

    total_pages = (total_scans + per_page - 1) // per_page
    start = offset + 1 if total_scans > 0 else 0
    end = min(offset + per_page, total_scans)

    cursor.close()
    conn.close()

    return render_template(
        'history.html',
        scans=scans,
        page=page,
        total_pages=total_pages,
        total=total_scans,
        start=start,
        end=end
    )

# PHISHING
@app.route('/phishing-detector', methods=['GET', 'POST'])
def phishing_detector():
    result = None
    why = None
    error = None
    color = None
    url = ""

    user_id = session.get('user_id')

    if request.method == 'POST':
        url = request.form['url']

        if not url.strip():
            error = "Please enter a URL"

        elif not is_valid_url(url):
            result = "Invalid URL ❌"
            why = "The URL format is incorrect. Please enter a valid website address."

        else:
            # ✅ GUEST LIMIT
            if not user_id:
                if 'guest_phishing_count' not in session:
                    session['guest_phishing_count'] = 0

                if session['guest_password_count'] >= 5:
                    return render_template(
                        'password_checker.html',
                        error="LIMIT_REACHED",
                        is_guest=True
                    )
                else:
                    session['guest_phishing_count'] += 1

                    data = detect_phishing(url)
                    result = data['result']
                    why = data['why']

            # ✅ LOGGED USER
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
                cursor.close()
                conn.close()

    # ✅ COLOR LOGIC
    if result:
        if "Safe" in result:
            color = "strong"
        elif "Suspicious" in result:
            color = "medium"
        elif "Invalid" in result:
            color = "weak"
        else:
            color = "red"

    return render_template(
        'phishing_detector.html',
        result=result,
        why=why,
        error=error,
        color=color,
        is_guest=(user_id is None),
        last_input=url
    )

# VULNERABILITY
@app.route('/vulnerability-scanner', methods=['GET', 'POST'])
def vulnerability_scanner():
    result = None
    why = None
    error = None
    color = None
    url = ""

    user_id = session.get('user_id')

    if request.method == 'POST':
        url = request.form['url']

        if not url.strip():
            error = "Please enter a URL"

        elif not is_valid_url(url):
            result = "Invalid URL ❌"
            why = "The URL format is incorrect. Please enter a valid website address."

        else:
            # ✅ GUEST LIMIT
            if not user_id:
                if 'guest_vuln_count' not in session:
                    session['guest_vuln_count'] = 0

                if session['guest_password_count'] >= 5:
                    return render_template(
                        'password_checker.html',
                        error="LIMIT_REACHED",
                        is_guest=True
                    )
                else:
                    session['guest_vuln_count'] += 1

                    data = scan_vulnerabilities(url)
                    result = data['result']
                    why = data['why']

            # ✅ LOGGED USER
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
                cursor.close()
                conn.close()

    # ✅ COLOR LOGIC
    if result:
        if "Low" in result:
            color = "green"
        elif "Medium" in result:
            color = "orange"
        elif "Invalid" in result:
            color = "red"
        else:
            color = "red"

    return render_template(
        'vulnerability_scanner.html',
        result=result,
        why=why,
        error=error,
        color=color,
        is_guest=(user_id is None),
        last_input=url
    )

# 404 ERROR
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error_code=404), 404


# 500 ERROR
@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", error_code=500), 500

def add_page_number(canvas, doc):
    page_num = canvas.getPageNumber()
    text = f"Page {page_num}"
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(200 * mm, 15, text)

# REPORT Download
@app.route('/download-report')
def download_report():

    if 'user_id' not in session:
        return "Please login to download report ❌"

    tool = request.args.get('tool', 'N/A')
    input_data = request.args.get('input', 'N/A')
    result = request.args.get('result', 'N/A')
    explanation = request.args.get('why', '')

    username = session.get('username', 'User')
    now = datetime.datetime.now().strftime("%d %b %Y, %H:%M")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()

    content = []

    # LOGO
    logo_path = os.path.join("static", "images", "logo.png")
    if os.path.exists(logo_path):
        content.append(Image(logo_path, width=120, height=50))

    content.append(Spacer(1, 10))

    # TITLE
    content.append(Paragraph("<b>SecureScan Report</b>", styles['Title']))
    content.append(Spacer(1, 10))

    # USER INFO
    content.append(Paragraph(f"<b>User:</b> {username}", styles['Normal']))
    content.append(Paragraph(f"<b>Date:</b> {now}", styles['Normal']))
    content.append(Spacer(1, 15))

    # RESULT STYLE
    if "Safe" in result or "Strong" in result:
        color = "green"
        icon = "✔"
    elif "Medium" in result:
        color = "orange"
        icon = "⚠"
    else:
        color = "red"
        icon = "✖"

    # CONTENT
    content.append(Paragraph(f"<b>Tool:</b> {tool}", styles['Normal']))
    content.append(Paragraph(f"<b>Input:</b> {input_data}", styles['Normal']))
    content.append(
        Paragraph(f"<b>Result:</b> <font color='{color}'>{icon} {result}</font>", styles['Normal'])
    )

    content.append(Spacer(1, 15))

    if explanation:
        content.append(Paragraph("<b>Why This Matters</b>", styles['Heading3']))
        content.append(Paragraph(explanation, styles['Normal']))

    content.append(Spacer(1, 30))
    content.append(Paragraph("<font size=9 color='grey'>Generated by SecureScan</font>", styles['Normal']))

    doc.build(content, onFirstPage=add_page_number, onLaterPages=add_page_number)

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="report.pdf")

# HISTORY Download
@app.route('/download-history')
def download_history():

    if 'user_id' not in session:
        return "Please login ❌"

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    user_id = session.get('user_id')
    username = session.get('username', 'User')

    cursor.execute("SELECT * FROM scans WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    scans = cursor.fetchall()

    conn.close()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()

    content = []

    now = datetime.datetime.now().strftime("%d %b %Y, %H:%M")

    # LOGO
    logo_path = os.path.join("static", "images", "logo.png")
    if os.path.exists(logo_path):
        content.append(Image(logo_path, width=120, height=50))

    content.append(Spacer(1, 10))

    # TITLE
    content.append(Paragraph("<b>SecureScan Full History Report</b>", styles['Title']))
    content.append(Spacer(1, 10))

    # USER INFO
    content.append(Paragraph(f"<b>User:</b> {username}", styles['Normal']))
    content.append(Paragraph(f"<b>Date:</b> {now}", styles['Normal']))
    content.append(Spacer(1, 15))

    # 🔥 SUMMARY
    total = len(scans)
    safe = sum(1 for s in scans if "Safe" in s['result'] or "Strong" in s['result'])
    medium = sum(1 for s in scans if "Medium" in s['result'])
    risk = total - safe - medium

    content.append(Paragraph("<b>Summary</b>", styles['Heading3']))
    content.append(Paragraph(f"Total Scans: {total}", styles['Normal']))
    content.append(Paragraph(f"Safe/Strong: {safe}", styles['Normal']))
    content.append(Paragraph(f"Medium: {medium}", styles['Normal']))
    content.append(Paragraph(f"Risky: {risk}", styles['Normal']))
    content.append(Spacer(1, 20))

    # 🔥 TABLE DATA
    table_data = [["No", "Tool", "Result", "Date"]]

    for i, scan in enumerate(scans, start=1):

        tool = scan['tool_type'].replace("_", " ").title()
        result = scan['result']
        date = str(scan['created_at'])

        # icon + color
        if "Safe" in result or "Strong" in result:
            result_text = f"✔ {result}"
        elif "Medium" in result:
            result_text = f"⚠ {result}"
        else:
            result_text = f"✖ {result}"

        table_data.append([i, tool, result_text, date])

    table = Table(table_data, repeatRows=1)

    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))

    content.append(table)

    content.append(Spacer(1, 30))
    content.append(Paragraph("<font size=9 color='grey'>Generated by SecureScan</font>", styles['Normal']))

    doc.build(content, onFirstPage=add_page_number, onLaterPages=add_page_number)

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="history.pdf")

#DELETE HISTORY
@app.route('/delete-history/<int:id>', methods=['POST'])
def delete_history(id):
    # 🔒 Check login
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔐 SECURE DELETE (only delete own data)
    cursor.execute(
        "DELETE FROM scans WHERE id = %s AND user_id = %s",
        (id, user_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/history')

@app.route('/delete-all-history', methods=['POST'])
def delete_all_history():
    # 🔒 Check login
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔐 Delete ONLY current user's history
    cursor.execute(
        "DELETE FROM scans WHERE user_id = %s",
        (user_id,)
    )

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/history')

@app.context_processor
def inject_user():
    return {
        'is_guest': ('user_id' not in session),
        'username': session.get('username', 'Guest')
    }

@app.context_processor
def inject_user():
    user_id = session.get('user_id')

    total_scans = 0

    if user_id:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) as total FROM scans WHERE user_id=%s", (user_id,))
        result = cursor.fetchone()

        total_scans = result['total'] if result else 0

    return {
        'is_guest': (user_id is None),
        'username': session.get('username', 'Guest'),
        'total_scans': total_scans
    }

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)