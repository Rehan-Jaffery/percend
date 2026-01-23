from flask import Flask, render_template, request, redirect, url_for, g, session, flash
from datetime import datetime, timedelta
import sqlite3
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib
from email.mime.text import MIMEText
import functools


DATABASE = "database.db"
app = Flask(__name__)
app.secret_key = "CHANGE_THIS_TO_A_STRONG_RANDOM_SECRET"


# ---------- EMAIL SMTP CONFIG ----------
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "rehanjaffery.02@gmail.com"      # sender email (app account)
SMTP_PASS = "kphzbujukbvzmclj"               # Gmail App Password (no spaces)


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Create/alter all tables, including semester columns."""
    with app.app_context():
        db = get_db()
        cur = db.cursor()

        # subjects now has 'semester'
        cur.execute("""
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                semester INTEGER DEFAULT 1
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS lectures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_id INTEGER NOT NULL,
                day_of_week TEXT NOT NULL,
                number_per_day INTEGER NOT NULL,
                FOREIGN KEY (subject_id) REFERENCES subjects(id)
            )
        """)

        # attendance now has 'semester'
        cur.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                subject_id INTEGER NOT NULL,
                lecture_number INTEGER NOT NULL,
                status TEXT NOT NULL,
                semester INTEGER DEFAULT 1,
                FOREIGN KEY (subject_id) REFERENCES subjects(id)
            )
        """)

        # try to add semester columns if DB already existed
        try:
            cur.execute("ALTER TABLE subjects ADD COLUMN semester INTEGER DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("ALTER TABLE attendance ADD COLUMN semester INTEGER DEFAULT 1")
        except sqlite3.OperationalError:
            pass

        # ---- users + otps tables for auth ----
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                otp TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        db.commit()


init_db()


# ----------------- AUTH HELPERS -----------------


def send_otp_email(to_email, otp):
    body = f"Your Percend verification OTP is: {otp}\n\nIt is valid for 10 minutes."
    msg = MIMEText(body)
    msg["Subject"] = "Percend Email Verification OTP"
    msg["From"] = SMTP_USER
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


def login_required(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        # set a default current semester if not set
        if "current_semester" not in session:
            session["current_semester"] = 1
        return view_func(*args, **kwargs)

    return wrapper


# ---------- REGISTER (STEP 1: email + password, send OTP) ----------


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not email or not password:
            flash("Email and password are required.")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cur.fetchone()
        if existing:
            flash("Email already registered. Please login.")
            return redirect(url_for("login"))

        otp = str(random.randint(100000, 999999))
        expires_at = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        cur.execute("DELETE FROM otps WHERE email = ?", (email,))
        cur.execute(
            "INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)",
            (email, otp, expires_at),
        )
        db.commit()

        session["pending_email"] = email
        session["pending_password_hash"] = generate_password_hash(password)

        try:
            send_otp_email(email, otp)
            flash("OTP sent to your email. Please verify.")
        except Exception as e:
            print("Error sending email:", e)
            flash("Failed to send OTP email. Please check SMTP config.")
            return redirect(url_for("register"))

        return redirect(url_for("verify_otp"))

    return render_template("register.html")


# ---------- REGISTER (STEP 2: verify OTP, create user) ----------


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    pending_email = session.get("pending_email")
    pending_hash = session.get("pending_password_hash")

    if not pending_email or not pending_hash:
        flash("No pending registration. Please register again.")
        return redirect(url_for("register"))

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT otp, expires_at FROM otps WHERE email = ?", (pending_email,))
        row = cur.fetchone()
        if not row:
            flash("No OTP found or it has expired. Please register again.")
            return redirect(url_for("register"))

        db_otp = row["otp"]
        expires_at = datetime.fromisoformat(row["expires_at"])
        now = datetime.utcnow()

        if now > expires_at:
            cur.execute("DELETE FROM otps WHERE email = ?", (pending_email,))
            db.commit()
            flash("OTP expired. Please register again.")
            return redirect(url_for("register"))

        if entered_otp != db_otp:
            flash("Invalid OTP. Please try again.")
            return redirect(url_for("verify_otp"))

        # OTP valid: create user
        cur.execute(
            "INSERT INTO users (email, password_hash, is_verified) VALUES (?, ?, 1)",
            (pending_email, pending_hash),
        )
        db.commit()
        user_id = cur.lastrowid
        cur.execute("DELETE FROM otps WHERE email = ?", (pending_email,))
        db.commit()

        session.pop("pending_email", None)
        session.pop("pending_password_hash", None)

        session["user_id"] = user_id
        session["user_email"] = pending_email
        session["current_semester"] = 1
        flash("Registration successful and email verified.")
        return redirect(url_for("dashboard"))

    return render_template("verify_otp.html", email=pending_email)


# ---------- LOGIN / LOGOUT ----------


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT id, email, password_hash, is_verified FROM users WHERE email = ?",
            (email,),
        )
        user = cur.fetchone()

        if not user:
            flash("Invalid email or password.")
            return redirect(url_for("login"))

        if user["is_verified"] != 1:
            flash("Email not verified. Please register again.")
            return redirect(url_for("register"))

        if not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        session["current_semester"] = 1
        flash("Logged in successfully.")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))


# ---------- EXISTING HELPERS ----------


def get_subjects():
    db = get_db()
    return db.execute("SELECT * FROM subjects").fetchall()


def get_lecture_schedule():
    db = get_db()
    return db.execute(
        """
        SELECT lectures.id, subjects.name as subject, lectures.day_of_week, lectures.number_per_day
        FROM lectures JOIN subjects ON lectures.subject_id = subjects.id
        ORDER BY subjects.name ASC, lectures.day_of_week ASC
        """
    ).fetchall()


def get_today_lectures():
    today_name = datetime.today().strftime("%A")
    today_date = datetime.today().strftime("%Y-%m-%d")
    current_sem = session.get("current_semester", 1)

    db = get_db()
    lectures = db.execute(
        """
        SELECT subjects.id as subject_id, subjects.name, lectures.id as lecture_id, lectures.number_per_day
        FROM lectures JOIN subjects ON lectures.subject_id = subjects.id
        WHERE lectures.day_of_week = ? AND subjects.semester = ?
        """,
        (today_name, current_sem),
    ).fetchall()

    lecture_list = []
    for row in lectures:
        for lec_num in range(1, row["number_per_day"] + 1):
            att = db.execute(
                """
                SELECT status FROM attendance
                WHERE date = ? AND subject_id = ? AND lecture_number = ? AND semester = ?
                """,
                (today_date, row["subject_id"], lec_num, current_sem),
            ).fetchone()
            lecture_list.append(
                {
                    "subject_id": row["subject_id"],
                    "subject": row["name"],
                    "lecture_number": lec_num,
                    "lecture_id": row["lecture_id"],
                    "status": att["status"] if att else "Blank",
                }
            )
    return lecture_list


def get_attendance_stats():
    """Subject‑wise totals for current semester."""
    db = get_db()
    current_sem = session.get("current_semester", 1)

    result = defaultdict(
        lambda: {"Attended": 0, "Not Attended": 0, "Cancelled": 0, "Total": 0}
    )
    rows = db.execute(
        """
        SELECT subjects.name as subject, attendance.status
        FROM attendance
        JOIN subjects ON attendance.subject_id = subjects.id
        WHERE attendance.semester = ?
        """,
        (current_sem,),
    ).fetchall()

    for row in rows:
        subj = row["subject"]
        status = row["status"]
        result[subj]["Total"] += 1
        if status in result[subj]:
            result[subj][status] += 1

    pie_stats = {"Attended": 0, "Not Attended": 0}
    pie_rows = db.execute(
        """
        SELECT status, COUNT(*) as cnt
        FROM attendance
        WHERE semester = ?
        GROUP BY status
        """,
        (current_sem,),
    ).fetchall()
    for row in pie_rows:
        if row["status"] in pie_stats:
            pie_stats[row["status"]] += row["cnt"]

    total_for_pie = sum(pie_stats.values())
    has_data = total_for_pie > 0
    return dict(result), pie_stats, has_data


def get_monthly_stats():
    """Monthly stats for current semester (for charts)."""
    db = get_db()
    current_sem = session.get("current_semester", 1)

    months = []
    percentages = []
    bar_labels = []
    conducted_counts = []
    attended_counts = []

    month_stat = defaultdict(lambda: {"attended": 0, "conducted": 0, "cancelled": 0})
    # bar_data[subject] = [conducted, attended]
    bar_data = defaultdict(lambda: [0, 0])

    rows = db.execute(
        """
        SELECT s.name, a.date, a.status
        FROM attendance a
        JOIN subjects s ON a.subject_id = s.id
        WHERE a.semester = ?
        ORDER BY a.date
        """,
        (current_sem,),
    ).fetchall()

    for row in rows:
        subj = row["name"]
        date = row["date"]
        status = row["status"]

        # ---- SUBJECT-WISE BAR DATA ----
        # Conducted: only non-cancelled (Attended or Not Attended)
        if status != "Cancelled":
            bar_data[subj][0] += 1

        # Attended: only Attended
        if status == "Attended":
            bar_data[subj][1] += 1

        # ---- MONTHLY / PIE DATA ----
        dt = datetime.strptime(date, "%Y-%m-%d")
        key = dt.strftime("%Y-%m")

        if status != "Cancelled":
            month_stat[key]["conducted"] += 1
        if status == "Attended":
            month_stat[key]["attended"] += 1
        elif status == "Cancelled":
            month_stat[key]["cancelled"] += 1

    # Build arrays for bar chart
    for subj in sorted(bar_data.keys()):
        bar_labels.append(subj)
        conducted_counts.append(bar_data[subj][0])
        attended_counts.append(bar_data[subj][1])

    # Build arrays for line chart
    for key in sorted(month_stat.keys()):
        months.append(key)
        conducted = month_stat[key]["conducted"]
        attended = month_stat[key]["attended"]
        if conducted > 0:
            pct = int(round(100 * attended / conducted))
        else:
            pct = 0
        percentages.append(pct)

    this_month = datetime.now().strftime("%Y-%m")
    pie_conducted = month_stat[this_month].get("conducted", 0)
    pie_attended = month_stat[this_month].get("attended", 0)
    pie_cancelled = month_stat[this_month].get("cancelled", 0)
    pie_has = pie_conducted > 0

    # Fallbacks so charts always have something to draw and data is JSON safe
    if not bar_labels:
        bar_labels = ["No data"]
        conducted_counts = [0]
        attended_counts = [0]

    if not months:
        months = [this_month]
        percentages = [0]

    return {
        "bar_labels": list(bar_labels),
        "conducted_counts": list(conducted_counts),
        "attended_counts": list(attended_counts),
        "months": list(months),
        "percentages": list(percentages),
        "pie_conducted": int(pie_conducted),
        "pie_attended": int(pie_attended),
        "pie_cancelled": int(pie_cancelled),
        "pie_has": bool(pie_has),
    }


# ---------- ROUTES ----------


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    subject_stats, pie_stats, has_attendance_data = get_attendance_stats()
    monthly_stats = get_monthly_stats()
    has_data = has_attendance_data or monthly_stats["pie_has"]

    db = get_db()
    current_sem = session.get("current_semester", 1)

    # totals for current semester (all months) for the top cards
    result = db.execute(
        """
        SELECT
            COUNT(CASE WHEN status != 'Cancelled' THEN 1 END) as conducted,
            SUM(CASE WHEN status='Attended' THEN 1 ELSE 0 END) as attended
        FROM attendance
        WHERE semester = ?
        """,
        (current_sem,),
    ).fetchone()

    conducted = result["conducted"] if result["conducted"] else 0
    attended = result["attended"] if result["attended"] else 0
    missed = max(conducted - attended, 0)

    if conducted == 0:
        prediction_percent = 100
    else:
        prediction_percent = int(round((attended / conducted) * 100))

    summary = {
        "conducted": conducted,
        "attended": attended,
        "missed": missed,
        "prediction": prediction_percent,
    }

    return render_template(
        "dashboard.html",
        subject_stats=subject_stats,
        pie_stats=pie_stats,
        has_attendance_data=has_attendance_data,
        has_data=has_data,
        prediction_percent=prediction_percent,
        summary=summary,
        current_semester=current_sem,
        active_page="dashboard",
        **monthly_stats,
    )


@app.route("/mark_attendance", methods=["GET", "POST"])
@login_required
def mark_attendance():
    db = get_db()
    today_schedule = get_today_lectures()
    message = ""
    current_sem = session.get("current_semester", 1)

    if request.method == "POST" and not request.form.get("add_subject"):
        today_date = datetime.today().strftime("%Y-%m-%d")
        for lec in today_schedule:
            key = f"{lec['subject']}_{lec['lecture_number']}"
            status = request.form.get(key, "Blank")
            att_exists = db.execute(
                """
                SELECT id FROM attendance
                WHERE date = ? AND subject_id = ? AND lecture_number = ? AND semester = ?
                """,
                (today_date, lec["subject_id"], lec["lecture_number"], current_sem),
            ).fetchone()
            if att_exists:
                db.execute(
                    "UPDATE attendance SET status = ? WHERE id = ?",
                    (status, att_exists["id"]),
                )
            else:
                db.execute(
                    "INSERT INTO attendance (date, subject_id, lecture_number, status, semester) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (today_date, lec["subject_id"], lec["lecture_number"], status, current_sem),
                )
        db.commit()
        return redirect(url_for("mark_attendance"))

    return render_template(
        "mark_attendance.html",
        today_schedule=today_schedule,
        message=message,
        current_semester=current_sem,
        active_page="mark",
    )


@app.route("/subjects", methods=["GET", "POST"])
@login_required
def subjects():
    db = get_db()
    message = ""
    current_sem = session.get("current_semester", 1)

    if request.method == "POST":
        if request.form.get("add_subject"):
            name = request.form.get("subject_name")
            sem = int(request.form.get("semester", current_sem))
            if name:
                session["current_semester"] = sem
                db.execute(
                    "INSERT OR IGNORE INTO subjects (name, semester) VALUES (?, ?)",
                    (name, sem),
                )
                subject_id = db.execute(
                    "SELECT id FROM subjects WHERE name = ?", (name,)
                ).fetchone()["id"]
                for day in [
                    "Monday",
                    "Tuesday",
                    "Wednesday",
                    "Thursday",
                    "Friday",
                    "Saturday",
                    "Sunday",
                ]:
                    num = int(request.form.get(f"num_{day}", 0))
                    if num > 0:
                        db.execute(
                            "INSERT INTO lectures (subject_id, day_of_week, number_per_day) "
                            "VALUES (?, ?, ?)",
                            (subject_id, day, num),
                        )
                db.commit()
                message = f"Subject '{name}' and lectures added!"
        elif request.form.get("delete_lecture"):
            lid = request.form.get("delete_lecture")
            if lid:
                db.execute("DELETE FROM lectures WHERE id = ?", (lid,))
                db.commit()
                message = "Lecture deleted."

    subjects_data = get_subjects()
    schedule = get_lecture_schedule()
    return render_template(
        "subjects.html",
        subjects=subjects_data,
        schedule=schedule,
        message=message,
        current_semester=current_sem,
        active_page="subjects",
    )


@app.route("/delete_lecture/<int:lecture_id>", methods=["POST"])
@login_required
def delete_lecture(lecture_id):
    db = get_db()
    db.execute("DELETE FROM lectures WHERE id = ?", (lecture_id,))
    db.commit()
    return redirect(url_for("subjects"))


# ---------- SEMESTERS & SEMESTER REPORT ----------


@app.route("/semesters")
@login_required
def semesters():
    """List distinct semesters that have any attendance."""
    db = get_db()
    rows = db.execute(
        "SELECT DISTINCT semester FROM attendance ORDER BY semester"
    ).fetchall()
    semesters = [r["semester"] for r in rows] or [1]
    return render_template(
        "semesters.html",
        semesters=semesters,
        current_semester=session.get("current_semester", 1),
        active_page="semesters",
    )


@app.route("/set_semester/<int:sem>")
@login_required
def set_semester(sem):
    """Change current semester (used when clicking from semesters list)."""
    session["current_semester"] = sem
    return redirect(url_for("dashboard"))


@app.route("/semester_report/<int:sem>")
@login_required
def semester_report(sem):
    db = get_db()
    user_sem = sem

    rows = db.execute(
        """
        SELECT s.name,
               COUNT(CASE WHEN a.status != 'Cancelled' THEN 1 END) AS conducted,
               SUM(CASE WHEN a.status='Attended' THEN 1 ELSE 0 END) AS attended
        FROM attendance a
        JOIN subjects s ON a.subject_id = s.id
        WHERE a.semester = ?
        GROUP BY s.id
        """,
        (user_sem,),
    ).fetchall()

    subjects = []
    total_conducted = 0
    total_attended = 0
    for row in rows:
        conducted = row["conducted"] or 0
        attended = row["attended"] or 0
        perc = 0 if conducted == 0 else round(attended * 100 / conducted, 2)
        subjects.append(
            {
                "name": row["name"],
                "conducted": conducted,
                "attended": attended,
                "perc": perc,
            }
        )
        total_conducted += conducted
        total_attended += attended

    overall_perc = 0 if total_conducted == 0 else round(
        total_attended * 100 / total_conducted, 2
    )

    return render_template(
        "semester_report.html",
        sem=user_sem,
        subjects=subjects,
        overall_perc=overall_perc,
        current_semester=session.get("current_semester", 1),
        active_page="report",
    )


if __name__ == "__main__":
    app.run(debug=True)
