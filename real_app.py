from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, jsonify
import os
import json
from datetime import datetime
from functools import wraps
import csv
import io
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import random
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS") 
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD") 
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY","fallback_secret") 

# -----------------------------
# DATA CONFIGURATION
# -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

USERS_FILE = os.path.join(DATA_DIR, "users.json")
VERIFICATION_FILE = os.path.join(DATA_DIR, "verification_records.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_logs.json")

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)


# -----------------------------
# HELPER FUNCTIONS
# -----------------------------

def load_json(file, default):
    if not os.path.exists(file):
        return default
    with open(file, "r") as f:
        try:
            return json.load(f)
        except:
            return default


def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=2)


def log_action(action, email):
    logs = load_json(AUDIT_FILE, [])
    logs.append({
        "TIMESTAMP": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ACTION_TYPE": action,
        "USER_EMAIL": email
    })
    save_json(AUDIT_FILE, logs)


def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_email" not in session:
                flash("Please login first", "error")
                return redirect(url_for("login"))

            if role:
                users = load_json(USERS_FILE, {})
                user = users.get(session["user_email"])
                if not user or user.get("role") != role:
                    flash("Unauthorized access", "error")
                    return redirect(url_for("login"))

            return f(*args, **kwargs)
        return decorated
    return decorator


# -----------------------------
# ROUTES
# -----------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------- REGISTER ---------------- #
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    users = load_json(USERS_FILE, {})

    email = request.form["email"]
    phone = request.form["phone"]

    # Email check
    if email in users:
        return render_template("register.html", error="Email already exists")

    # Phone check
    for user in users.values():
        if user.get("phone") == phone:
            return render_template("register.html", error="Phone number already registered")

    # Generate OTP
    otp = str(random.randint(100000, 999999))

    # Store form data temporarily in session
    session["register_data"] = request.form.to_dict()
    session["register_otp"] = otp
    session["register_otp_expiry"] = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    send_otp_email(email, otp)

    return render_template("verify_otp.html", mode="register")

def send_otp_email(receiver_email, otp):
    try:
        subject = "SurakshaID OTP Verification"
        body = f"""
Hello,

Your OTP is: {otp}

This OTP is valid for 5 minutes.
"""

        message = MIMEMultipart()
        message["From"] = EMAIL_ADDRESS
        message["To"] = receiver_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(message)
        server.quit()

        print("OTP Email sent successfully")

    except Exception as e:
        print("EMAIL ERROR:", str(e))

@app.route('/resend_otp', methods=['POST'])
def resend_otp():

    if 'register_data' not in session:
        return jsonify({"success": False})

    email = session["register_data"]["email"]

    # Generate new OTP
    new_otp = str(random.randint(100000, 999999))

    # Update session
    session["register_otp"] = new_otp
    session["register_otp_expiry"] = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    # Send email
    send_otp_email(email, new_otp)

    return jsonify({"success": True})
# ---------------- LOGIN ---------------- #
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    users = load_json(USERS_FILE, {})
    email = request.form["email"]
    password = request.form["password"]

    user = users.get(email)

    # 🔐 Step 1: Verify password
    if user and check_password_hash(user["password"], password):

        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))

        session["temp_email"] = email
        session["temp_role"] = user["role"]
        session["otp"] = otp
        session["otp_expiry"] = (
            datetime.now() + timedelta(minutes=5)
        ).strftime("%Y-%m-%d %H:%M:%S")

        # Send OTP to email
        send_otp_email(email, otp)

        return render_template("verify_otp.html")

    return render_template("login.html", error="Invalid credentials")

@app.route("/verify_otp", methods=["POST"])
def verify_otp():

    entered_otp = request.form["otp"]

    # 🔹 LOGIN OTP CHECK
    if session.get("otp"):

        if entered_otp == session.get("otp"):

            email = session.get("temp_email")
            role = session.get("temp_role")

            session.clear()

            session["user_email"] = email
            session["role"] = role

            log_action("LOGIN_WITH_OTP", email)

            if role == "USER":
                return redirect(url_for("user_dashboard"))
            elif role == "AUTHORIZED":
                return redirect(url_for("authorized_dashboard"))
            elif role == "COMPANY":
                return redirect(url_for("company_dashboard"))
            elif role == "ADMIN":
                return redirect(url_for("admin_dashboard"))

        return render_template("verify_otp.html", error="Invalid OTP")


    # 🔹 REGISTER OTP CHECK
    if session.get("register_otp"):

        expiry_time = datetime.strptime(session["register_otp_expiry"], "%Y-%m-%d %H:%M:%S")

        if datetime.now() > expiry_time:
            session.clear()
            return render_template("register.html", error="OTP expired. Please register again.")

        if entered_otp == session.get("register_otp"):

            form_data = session.get("register_data")

            users = load_json(USERS_FILE, {})
            verification_records = load_json(VERIFICATION_FILE, {})

            email = form_data["email"]
            phone = form_data["phone"]
            vid = f"VID-{phone}"

            # Save user finally
            users[email] = {
    "email": email,
    "phone": phone,
    "password": generate_password_hash(form_data["password"]),
    "role": "USER",
    "name": form_data["name"],
    "age": form_data["age"],

    # 🔥 NEW JOB FIELDS
    "is_job_holder": form_data.get("is_job_holder"),
    "company_name": form_data.get("company_name"),
    "emp_id": form_data.get("emp_id"),
    "job_role": form_data.get("job_role"),

    "house_no": form_data.get("house_no"),
    "locality": form_data.get("locality"),
    "village": form_data.get("village"),
    "district": form_data.get("district"),
    "govt_id_type": form_data["govt_id_type"],
    "govt_id_number": form_data["govt_id_number"],
    "created_date": datetime.now().strftime("%Y-%m-%d")
}
            verification_records[email] = {
			    "VERIFICATION_ID": vid,
				"NAME": form_data["name"],
				"EMAIL": email,
				"PHONE_NUMBER": phone,
				"AGE": form_data["age"],
				"GOVT_ID_TYPE": form_data["govt_id_type"],
				"MASKED_GOVT_ID": "XXXX-XXXX",
				# 🔥 ADD COMPANY DETAILS HERE
				"COMPANY_NAME": form_data.get("company_name"),
				"EMP_ID": form_data.get("emp_id"),
				"JOB_ROLE": form_data.get("job_role"),
				"POLICE_VERIFICATION_STATUS": "PENDING",
				"ADDRESS_VERIFICATION_STATUS": "PENDING",
				"CRIMINAL_VERIFICATION_STATUS": "PENDING",
				"ELIGIBILITY_STATUS": "RESTRICTED",
				"VERIFICATION_DATE": datetime.now().strftime("%Y-%m-%d"),
				"HOUSE_NO": form_data.get("house_no"),
				"LOCALITY": form_data.get("locality"),
				"VILLAGE": form_data.get("village"),
				"DISTRICT": form_data.get("district")
            }

            save_json(USERS_FILE, users)
            save_json(VERIFICATION_FILE, verification_records)

            session.clear()

            return render_template("login.html", success="Registration successful. Please login.")

        return render_template("verify_otp.html", error="Invalid OTP")

    return redirect(url_for("login"))

# ---------------- LOGOUT ---------------- #

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
#-----------------CREATE COMPANY-----------#

@app.route("/admin/create_company", methods=["POST"])
@login_required(role="ADMIN")
def create_company():

    users = load_json(USERS_FILE, {})

    email = request.form["email"]
    password = request.form["password"]
    company_name = request.form["company_name"]

    if email in users:
        flash("Company already exists", "error")
        return redirect(url_for("admin_dashboard"))

    users[email] = {
        "email": email,
        "password": generate_password_hash(password),
        "role": "COMPANY",
        "company_name": company_name,
        "created_date": datetime.now().strftime("%Y-%m-%d")
    }

    save_json(USERS_FILE, users)

    flash("Company created successfully", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/company/dashboard")
@login_required(role="COMPANY")
def company_dashboard():

    verification = load_json(VERIFICATION_FILE, {})
    users = load_json(USERS_FILE, {})

    company_email = session["user_email"]
    company_user = users.get(company_email)
    company_name = company_user.get("company_name")

    search = request.args.get("search", "").lower()
    police_filter = request.args.get("police_status")
    address_filter = request.args.get("address_status")
    criminal_filter = request.args.get("criminal_status")
    eligibility_filter = request.args.get("eligibility_status")
    filter_type = request.args.get("filter_type")

    records = []

    for record in verification.values():

        # 🔥 Company filter
        if record.get("COMPANY_NAME") != company_name:
            continue

        match = True

        # 🔎 Search
        if search:
            if search not in record.get("NAME", "").lower() and \
               search not in record.get("VERIFICATION_ID", "").lower():
                match = False

        # 🚓 Police filter
        if police_filter and record.get("POLICE_VERIFICATION_STATUS") != police_filter:
            match = False

        # 🏠 Address filter
        if address_filter and record.get("ADDRESS_VERIFICATION_STATUS") != address_filter:
            match = False

        # ⚖ Criminal filter
        if criminal_filter and record.get("CRIMINAL_VERIFICATION_STATUS") != criminal_filter:
            match = False

        # 🛡 Eligibility filter
        if eligibility_filter and record.get("ELIGIBILITY_STATUS") != eligibility_filter:
            match = False

        # 📊 Card filters
        if filter_type == "pending":
            if not (
                record["POLICE_VERIFICATION_STATUS"] == "PENDING" or
                record["ADDRESS_VERIFICATION_STATUS"] == "PENDING" or
                record["CRIMINAL_VERIFICATION_STATUS"] == "PENDING"
            ):
                match = False

        elif filter_type == "safe":
            if record["ELIGIBILITY_STATUS"] != "SAFE":
                match = False

        elif filter_type == "restricted":
            if record["ELIGIBILITY_STATUS"] != "RESTRICTED":
                match = False

        if match:
            records.append(record)

    return render_template(
        "company_dashboard.html",
        employees=records,
        total_users=len([
            r for r in verification.values()
            if r.get("COMPANY_NAME") == company_name
        ]),
        pending_users=len([
            r for r in verification.values()
            if r.get("COMPANY_NAME") == company_name and
               (
                   r["POLICE_VERIFICATION_STATUS"] == "PENDING" or
                   r["ADDRESS_VERIFICATION_STATUS"] == "PENDING" or
                   r["CRIMINAL_VERIFICATION_STATUS"] == "PENDING"
               )
        ]),
        safe_users=len([
            r for r in verification.values()
            if r.get("COMPANY_NAME") == company_name and
               r["ELIGIBILITY_STATUS"] == "SAFE"
        ]),
        restricted_users=len([
            r for r in verification.values()
            if r.get("COMPANY_NAME") == company_name and
               r["ELIGIBILITY_STATUS"] == "RESTRICTED"
        ])
    )

@app.route("/company/view/<vid>")
@login_required(role="COMPANY")
def company_view_user(vid):
    verification = load_json(VERIFICATION_FILE, {})
    users = load_json(USERS_FILE, {})
    
    company_email = session["user_email"]
    company_user = users.get(company_email)
    company_name = company_user.get("company_name")

    for email, record in verification.items():
        if record["VERIFICATION_ID"] == vid and record.get("COMPANY_NAME") == company_name:
            user = users.get(email)
            return render_template("company_view_user.html",
                                   user=user,
                                   record=record)

    flash("Employee not found", "error")
    return redirect(url_for("company_dashboard"))

@app.route("/company/export/csv")
@login_required(role="COMPANY")
def company_export_csv():
    verification = load_json(VERIFICATION_FILE, {})
    users = load_json(USERS_FILE, {})
    
    company_email = session["user_email"]
    company_user = users.get(company_email)
    company_name = company_user.get("company_name")
    
    # Filter company records
    company_records = []
    for record in verification.values():
        if record.get("COMPANY_NAME") == company_name:
            company_records.append(record)
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    header = ['Verification ID', 'Name', 'Phone', 'Email', 'Police Status', 'Address Status', 'Eligibility']
    writer.writerow(header)
    
    for record in company_records:
        writer.writerow([
            record.get('VERIFICATION_ID', ''),
            record.get('NAME', ''),
            record.get('PHONE_NUMBER', ''),
            record.get('EMAIL', ''),
            record.get('POLICE_VERIFICATION_STATUS', ''),
            record.get('ADDRESS_VERIFICATION_STATUS', ''),
            record.get('ELIGIBILITY_STATUS', '')
        ])
    
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename={company_name}_employees.csv'
    return response

# ---------------- USER DASHBOARD ---------------- #
@app.route("/user/dashboard")
@login_required(role="USER")
def user_dashboard():
    users = load_json(USERS_FILE, {})
    verification = load_json(VERIFICATION_FILE, {})

    email = session["user_email"]
    user = users.get(email)
    record = verification.get(email)

    if not record:
        return redirect(url_for("login"))

    # ✅ Always ensure masked ID exists
    if "MASKED_GOVT_ID" not in record:
        record["MASKED_GOVT_ID"] = "XXXX-XXXX"

    # ✅ If address missing in verification, take from user
    record["HOUSE_NO"] = record.get("HOUSE_NO") or user.get("house_no") or "N/A"
    record["LOCALITY"] = record.get("LOCALITY") or user.get("locality") or "N/A"
    record["VILLAGE"] = record.get("VILLAGE") or user.get("village") or "N/A"
    record["DISTRICT"] = record.get("DISTRICT") or user.get("district") or "N/A"

    save_json(VERIFICATION_FILE, verification)

    return render_template(
        "user_dashboard.html",
        user=user,
        verification_record=record
    )

# ---------------- AUTHORIZED DASHBOARD ---------------- #
@app.route("/authorized/dashboard")
@login_required(role="AUTHORIZED")
def authorized_dashboard():

    verification = load_json(VERIFICATION_FILE, {})
    users = load_json(USERS_FILE, {})

    current_user = users.get(session["user_email"])
    verifier_type = current_user.get("verifier_type")

    records = list(verification.values())

    # -------------------------
    # FILTERS (Same as Admin)
    # -------------------------

    search = request.args.get("search", "").lower()
    police_filter = request.args.get("police_status")
    address_filter = request.args.get("address_status")
    criminal_filter = request.args.get("criminal_status")
    eligibility_filter = request.args.get("eligibility_status")
    filter_type = request.args.get("filter_type")

    filtered = []

    for user in records:

        match = True

        # 🔎 Search
        if search:
            if search not in user.get("NAME", "").lower() and \
               search not in user.get("VERIFICATION_ID", "").lower():
                match = False

        # 🚓 Police Filter
        if police_filter and user.get("POLICE_VERIFICATION_STATUS") != police_filter:
            match = False

        # 🏠 Address Filter
        if address_filter and user.get("ADDRESS_VERIFICATION_STATUS") != address_filter:
            match = False

        # ⚖ Criminal Filter
        if criminal_filter and user.get("CRIMINAL_VERIFICATION_STATUS") != criminal_filter:
            match = False

        # 🛡 Eligibility Filter
        if eligibility_filter and user.get("ELIGIBILITY_STATUS") != eligibility_filter:
            match = False

        # 📊 Dashboard Cards
        if filter_type == "pending":
            if not (
                user["POLICE_VERIFICATION_STATUS"] == "PENDING"
                or user["ADDRESS_VERIFICATION_STATUS"] == "PENDING"
                or user["CRIMINAL_VERIFICATION_STATUS"] == "PENDING"
            ):
                match = False

        elif filter_type == "safe":
            if user["ELIGIBILITY_STATUS"] != "SAFE":
                match = False

        elif filter_type == "restricted":
            if user["ELIGIBILITY_STATUS"] != "RESTRICTED":
                match = False

        if match:
            filtered.append(user)

    return render_template(
        "authorized_dashboard.html",
        search_results=filtered,
        total_users=len(verification),
        pending_users=len([
            r for r in verification.values()
            if r["POLICE_VERIFICATION_STATUS"] == "PENDING"
            or r["ADDRESS_VERIFICATION_STATUS"] == "PENDING"
            or r["CRIMINAL_VERIFICATION_STATUS"] == "PENDING"
        ]),
        safe_users=len([
            r for r in verification.values()
            if r["ELIGIBILITY_STATUS"] == "SAFE"
        ]),
        restricted_users=len([
            r for r in verification.values()
            if r["ELIGIBILITY_STATUS"] == "RESTRICTED"
        ]),
        verifier_type=verifier_type
    )

@app.route("/authorized/search", methods=["POST"])
@login_required(role="AUTHORIZED")
def authorized_search():

    verification = load_json(VERIFICATION_FILE, {})
    users = load_json(USERS_FILE, {})

    current_user = users.get(session["user_email"])
    verifier_type = current_user.get("verifier_type")

    search_term = request.form.get("search_term", "").lower()

    results = []

    # 🔍 SEARCH LOGIC
    for record in verification.values():

        if "CRIMINAL_VERIFICATION_STATUS" not in record:
            record["CRIMINAL_VERIFICATION_STATUS"] = "PENDING"

        if (
            search_term in record.get("VERIFICATION_ID", "").lower()
            or search_term in record.get("NAME", "").lower()
            or search_term in record.get("PHONE_NUMBER", "").lower()
        ):
            results.append(record)

    return render_template(
        "authorized_dashboard.html",
        search_results=results,
        search_term=search_term,
        total_users=len(verification),
        pending_users=len([
            r for r in verification.values()
            if r["POLICE_VERIFICATION_STATUS"] == "PENDING"
            or r["ADDRESS_VERIFICATION_STATUS"] == "PENDING"
            or r["CRIMINAL_VERIFICATION_STATUS"] == "PENDING"
        ]),
        safe_users=len([
            r for r in verification.values()
            if r["ELIGIBILITY_STATUS"] == "SAFE"
        ]),
        restricted_users=len([
            r for r in verification.values()
            if r["ELIGIBILITY_STATUS"] == "RESTRICTED"
        ]),
        verifier_type=verifier_type
    )

@app.route("/admin/users")
@login_required(role="ADMIN")
def admin_users():

    verification = load_json(VERIFICATION_FILE, {})

    # Fix missing fields
    for email, record in verification.items():

        if "NAME" not in record or not record["NAME"]:
            record["NAME"] = email.split("@")[0]

        if "CRIMINAL_VERIFICATION_STATUS" not in record:
            record["CRIMINAL_VERIFICATION_STATUS"] = "PENDING"

    save_json(VERIFICATION_FILE, verification)

    users_list = list(verification.values())

    # --------------------------------
    # DASHBOARD CARD FILTER (NEW)
    # --------------------------------
    filter_type = request.args.get("filter_type")

    if filter_type == "pending":
        users_list = [
            r for r in users_list
            if r["POLICE_VERIFICATION_STATUS"] == "PENDING"
            or r["ADDRESS_VERIFICATION_STATUS"] == "PENDING"
            or r["CRIMINAL_VERIFICATION_STATUS"] == "PENDING"
        ]

    elif filter_type == "safe":
        users_list = [
            r for r in users_list
            if r["ELIGIBILITY_STATUS"] == "SAFE"
        ]

    elif filter_type == "restricted":
        users_list = [
            r for r in users_list
            if r["ELIGIBILITY_STATUS"] == "RESTRICTED"
        ]

    # --------------------------------
    # NORMAL SEARCH & FILTER SECTION
    # --------------------------------
    search = request.args.get("search", "").lower()
    police_filter = request.args.get("police_status")
    address_filter = request.args.get("address_status")
    criminal_filter = request.args.get("criminal_status")
    eligibility_filter = request.args.get("eligibility_status")

    filtered = []

    for user in users_list:

        match = True

        # 🔍 Search
        if search:
            if search not in user.get("NAME", "").lower() and \
               search not in user.get("VERIFICATION_ID", "").lower():
                match = False

        # 🚓 Police filter
        if police_filter and user.get("POLICE_VERIFICATION_STATUS") != police_filter:
            match = False

        # 🏠 Address filter
        if address_filter and user.get("ADDRESS_VERIFICATION_STATUS") != address_filter:
            match = False

        # ⚖ Criminal filter
        if criminal_filter and user.get("CRIMINAL_VERIFICATION_STATUS") != criminal_filter:
            match = False

        # 🛡 Eligibility filter
        if eligibility_filter and user.get("ELIGIBILITY_STATUS") != eligibility_filter:
            match = False

        if match:
            filtered.append(user)

    return render_template("admin_users.html", users=filtered)

@app.route("/admin/view/<vid>")
@login_required(role="ADMIN")
def admin_view_user(vid):

    verification = load_json(VERIFICATION_FILE, {})
    users = load_json(USERS_FILE, {})

    for email, record in verification.items():
        if record["VERIFICATION_ID"] == vid:
            user = users.get(email)

            return render_template(
                "authorized_view_user.html",   # reuse same template
                user=user,
                record=record
            )

    flash("User not found", "error")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/update_verification", methods=["POST"])
@login_required(role="ADMIN")
def admin_update_verification():

    verification = load_json(VERIFICATION_FILE, {})

    vid = request.form.get("verification_id")
    field = request.form.get("field")
    status = request.form.get("status")

    for email, record in verification.items():
        if record["VERIFICATION_ID"] == vid:

            if field == "POLICE":
                record["POLICE_VERIFICATION_STATUS"] = status

            elif field == "ADDRESS":
                record["ADDRESS_VERIFICATION_STATUS"] = status

            elif field == "CRIMINAL":
                record["CRIMINAL_VERIFICATION_STATUS"] = status

            # 🔥 Auto eligibility logic
            if (
                record["POLICE_VERIFICATION_STATUS"] == "CLEAR" and
                record["ADDRESS_VERIFICATION_STATUS"] == "CLEAR" and
                record["CRIMINAL_VERIFICATION_STATUS"] == "CLEAR"
            ):
                record["ELIGIBILITY_STATUS"] = "SAFE"
            else:
                record["ELIGIBILITY_STATUS"] = "RESTRICTED"

            save_json(VERIFICATION_FILE, verification)
            return jsonify({"success": True})

    return jsonify({"success": False, "message": "User not found"})

# ---------------- ADMIN EXPORT ---------------- #

@app.route("/admin/export/<format>")
@login_required(role="ADMIN")
def admin_export(format):
    verification = load_json(VERIFICATION_FILE, {})

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["Verification ID", "Age", "Eligibility Status"])

        for r in verification.values():
            writer.writerow([
                r.get("VERIFICATION_ID"),
                r.get("AGE"),
                r.get("ELIGIBILITY_STATUS")
            ])

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=verification.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

    elif format == "json":
        response = make_response(json.dumps(verification, indent=2))
        response.headers["Content-Disposition"] = "attachment; filename=verification.json"
        response.headers["Content-Type"] = "application/json"
        return response

    else:
        flash("Invalid export format", "error")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/dashboard")
@login_required(role="ADMIN")
def admin_dashboard():

    verification = load_json(VERIFICATION_FILE, {})

    filter_type = request.args.get("filter_type")

    records = list(verification.values())

    # 🔹 Same filtering logic like AUTH
    if filter_type == "pending":
        records = [
            r for r in records
            if r["POLICE_VERIFICATION_STATUS"] == "PENDING"
            or r["ADDRESS_VERIFICATION_STATUS"] == "PENDING"
            or r["CRIMINAL_VERIFICATION_STATUS"] == "PENDING"
        ]

    elif filter_type == "safe":
        records = [r for r in records if r["ELIGIBILITY_STATUS"] == "SAFE"]

    elif filter_type == "restricted":
        records = [r for r in records if r["ELIGIBILITY_STATUS"] == "RESTRICTED"]

    stats = {
        "total_users": len(verification),
        "safe_users": len([r for r in verification.values() if r["ELIGIBILITY_STATUS"] == "SAFE"]),
        "restricted_users": len([r for r in verification.values() if r["ELIGIBILITY_STATUS"] == "RESTRICTED"]),
        "pending_verifications": len([
            r for r in verification.values()
            if r["POLICE_VERIFICATION_STATUS"] == "PENDING"
            or r["ADDRESS_VERIFICATION_STATUS"] == "PENDING"
            or r["CRIMINAL_VERIFICATION_STATUS"] == "PENDING"
        ]),
        "today_registrations": 0
    }

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        users=records   # 🔥 IMPORTANT
    )

@app.route("/admin/audit_logs")
@login_required(role="ADMIN")
def admin_audit_logs():
    logs = load_json(AUDIT_FILE, [])

    # Optional filtering
    user_email = request.args.get("user_email")
    action_type = request.args.get("action_type")
    date = request.args.get("date")

    if user_email:
        logs = [l for l in logs if user_email.lower() in l.get("USER_EMAIL", "").lower()]

    if action_type:
        logs = [l for l in logs if l.get("ACTION_TYPE") == action_type]

    if date:
        logs = [l for l in logs if l.get("TIMESTAMP", "").startswith(date)]

    return render_template("admin_audit_logs.html", logs=logs)

@app.route("/authorized/export/csv")
@login_required(role="AUTHORIZED")
def authorized_export_csv():
    verification = load_json(VERIFICATION_FILE, {})
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    header = ['Verification ID', 'Name', 'Phone', 'Email', 'Police Status', 'Address Status', 'Eligibility']
    writer.writerow(header)
    
    for record in verification.values():
        writer.writerow([
            record.get('VERIFICATION_ID', ''),
            record.get('NAME', ''),
            record.get('PHONE_NUMBER', ''),
            record.get('EMAIL', ''),
            record.get('POLICE_VERIFICATION_STATUS', ''),
            record.get('ADDRESS_VERIFICATION_STATUS', ''),
            record.get('ELIGIBILITY_STATUS', '')
        ])
    
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=authorized_verification_records.csv'
    return response

@app.route("/authorized/view/<vid>")
@login_required(role="AUTHORIZED")
def authorized_view_user(vid):
    verification = load_json(VERIFICATION_FILE, {})
    users = load_json(USERS_FILE, {})

    for email, record in verification.items():
        if record["VERIFICATION_ID"] == vid:
            user = users.get(email)
            return render_template("authorized_view_user.html",
                                   user=user,
                                   record=record)

    flash("User not found", "error")
    return redirect(url_for("authorized_dashboard"))

@app.route("/authorized/update_verification", methods=["POST"])
@login_required(role="AUTHORIZED")
def authorized_update_verification():

    users = load_json(USERS_FILE, {})
    verification = load_json(VERIFICATION_FILE, {})

    current_user = users.get(session["user_email"])
    verifier_type = current_user.get("verifier_type")

    vid = request.form.get("verification_id")
    new_status = request.form.get("status")

    for email, record in verification.items():
        if record["VERIFICATION_ID"] == vid:

            if verifier_type == "POLICE":
                record["POLICE_VERIFICATION_STATUS"] = new_status

            elif verifier_type == "ADDRESS":
                record["ADDRESS_VERIFICATION_STATUS"] = new_status

            elif verifier_type == "CRIMINAL":
                record["CRIMINAL_VERIFICATION_STATUS"] = new_status

            # 🔥 Auto eligibility logic
            if (
                record["POLICE_VERIFICATION_STATUS"] == "CLEAR" and
                record["ADDRESS_VERIFICATION_STATUS"] == "CLEAR" and
                record["CRIMINAL_VERIFICATION_STATUS"] == "CLEAR"
            ):
                record["ELIGIBILITY_STATUS"] = "SAFE"
            else:
                record["ELIGIBILITY_STATUS"] = "RESTRICTED"

            save_json(VERIFICATION_FILE, verification)
            log_action("AUTHORIZED_UPDATE", session["user_email"])

            return jsonify({"success": True})

    return jsonify({"success": False})

# ---------------- ADMIN CREATE AUTHORIZED ---------------- #
@app.route("/admin/create_authorized", methods=["POST"])
@login_required(role="ADMIN")
def create_authorized():

    users = load_json(USERS_FILE, {})

    email = request.form["email"]
    password = request.form["password"]
    role_type = request.form["role_type"]

    if email in users:
        flash("User already exists", "error")
        return redirect(url_for("admin_dashboard"))

    # 🔥 IF AUTHORIZED
    if role_type == "AUTHORIZED":

        verifier_type = request.form["verifier_type"]

        users[email] = {
            "email": email,
            "password": generate_password_hash(password),
            "role": "AUTHORIZED",
            "verifier_type": verifier_type,
            "created_date": datetime.now().strftime("%Y-%m-%d")
        }

    # 🔥 IF COMPANY
    elif role_type == "COMPANY":

        company_name = request.form["company_name"]

        users[email] = {
            "email": email,
            "password": generate_password_hash(password),
            "role": "COMPANY",
            "company_name": company_name,
            "created_date": datetime.now().strftime("%Y-%m-%d")
        }

    save_json(USERS_FILE, users)

    flash(f"{role_type} account created successfully", "success")
    return redirect(url_for("admin_dashboard"))
# ---------------- ADMIN DELETE USER ---------------- #

@app.route("/admin/delete_user/<vid>")
@login_required(role="ADMIN")
def delete_user(vid):

    users = load_json(USERS_FILE, {})
    verification = load_json(VERIFICATION_FILE, {})

    user_email_to_delete = None

    # 🔍 Find user email using VERIFICATION_ID
    for email, record in verification.items():
        if record.get("VERIFICATION_ID") == vid:
            user_email_to_delete = email
            break

    if user_email_to_delete:
        # Delete from both files
        users.pop(user_email_to_delete, None)
        verification.pop(user_email_to_delete, None)

        save_json(USERS_FILE, users)
        save_json(VERIFICATION_FILE, verification)

        flash("User deleted successfully", "success")
    else:
        flash("User not found", "danger")

    return redirect(url_for("admin_dashboard"))

# ---------------- RUN ---------------- #

