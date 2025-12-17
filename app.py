from flask import Flask, render_template, request, redirect, url_for, g
from datetime import datetime
import sqlite3
from collections import defaultdict

DATABASE = "database.db"
app = Flask(__name__)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS lectures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_id INTEGER NOT NULL,
                day_of_week TEXT NOT NULL,
                number_per_day INTEGER NOT NULL,
                FOREIGN KEY (subject_id) REFERENCES subjects(id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                subject_id INTEGER NOT NULL,
                lecture_number INTEGER NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY (subject_id) REFERENCES subjects(id)
            )
        ''')
        db.commit()
init_db()

def get_subjects():
    db = get_db()
    return db.execute("SELECT * FROM subjects").fetchall()

def get_lecture_schedule():
    db = get_db()
    return db.execute('''
        SELECT lectures.id, subjects.name as subject, lectures.day_of_week, lectures.number_per_day
        FROM lectures JOIN subjects ON lectures.subject_id = subjects.id
        ORDER BY subjects.name ASC, lectures.day_of_week ASC
    ''').fetchall()

def get_today_lectures():
    today_name = datetime.today().strftime('%A')
    today_date = datetime.today().strftime('%Y-%m-%d')
    db = get_db()
    lectures = db.execute('''
        SELECT subjects.id as subject_id, subjects.name, lectures.id as lecture_id, lectures.number_per_day
        FROM lectures JOIN subjects ON lectures.subject_id = subjects.id
        WHERE lectures.day_of_week = ?
    ''', (today_name,)).fetchall()
    lecture_list = []
    for row in lectures:
        for lec_num in range(1, row["number_per_day"] + 1):
            att = db.execute('''
                SELECT status FROM attendance
                WHERE date = ? AND subject_id = ? AND lecture_number = ?
            ''', (today_date, row["subject_id"], lec_num)).fetchone()
            lecture_list.append({
                'subject_id': row["subject_id"],
                'subject': row["name"],
                'lecture_number': lec_num,
                'lecture_id': row["lecture_id"],
                'status': att["status"] if att else "Blank"
            })
    return lecture_list

def get_attendance_stats():
    db = get_db()
    result = defaultdict(lambda: {'Attended': 0, 'Not Attended': 0, 'Cancelled': 0, 'Total': 0})
    rows = db.execute('''
        SELECT subjects.name as subject, attendance.status FROM attendance
        JOIN subjects ON attendance.subject_id = subjects.id
    ''').fetchall()
    for row in rows:
        subj = row['subject']
        status = row['status']
        result[subj]['Total'] += 1
        if status in result[subj]:
            result[subj][status] += 1

    # Recalculate pie_stats excluding 'Cancelled' from total
    pie_stats = {'Attended': 0, 'Not Attended': 0}
    cancelled_count = 0
    pie_rows = db.execute('SELECT status, COUNT(*) as cnt FROM attendance GROUP BY status').fetchall()
    for row in pie_rows:
        if row['status'] == 'Cancelled':
            cancelled_count += row['cnt']
        elif row['status'] in pie_stats:
            pie_stats[row['status']] += row['cnt']

    total_for_pie = sum(pie_stats.values())
    has_data = total_for_pie > 0
    return dict(result), pie_stats, has_data

def get_monthly_stats():
    db = get_db()
    months = []
    percentages = []
    bar_labels = []
    conducted_counts = []
    attended_counts = []
    month_stat = defaultdict(lambda: {'attended': 0, 'conducted': 0, 'cancelled': 0})
    bar_data = defaultdict(lambda: [0, 0])
    rows = db.execute('''
        SELECT s.name, a.date, a.status FROM attendance a
        JOIN subjects s ON a.subject_id = s.id
        ORDER BY a.date
    ''').fetchall()
    for row in rows:
        subj = row['name']
        date = row['date']
        status = row['status']
        bar_data[subj][0] += 1
        if status == "Attended":
            bar_data[subj][1] += 1
        dt = datetime.strptime(date, "%Y-%m-%d")
        key = dt.strftime("%Y-%m")
        if status != "Cancelled":
            month_stat[key]['conducted'] += 1
        if status == "Attended":
            month_stat[key]['attended'] += 1
        elif status == "Cancelled":
            month_stat[key]['cancelled'] += 1
    for subj in sorted(bar_data.keys()):
        bar_labels.append(subj)
        conducted_counts.append(bar_data[subj][0])
        attended_counts.append(bar_data[subj][1])
    for key in sorted(month_stat.keys()):
        months.append(key)
        conducted = month_stat[key]['conducted']
        attended = month_stat[key]['attended']
        if conducted > 0:
            pct = int(round(100 * attended / conducted))
        else:
            pct = 0
        percentages.append(pct)
    this_month = datetime.now().strftime("%Y-%m")
    pie_conducted = month_stat[this_month].get('conducted', 0)
    pie_attended = month_stat[this_month].get('attended', 0)
    pie_cancelled = month_stat[this_month].get('cancelled', 0)
    pie_has = pie_conducted > 0
    return {
        'bar_labels': bar_labels,
        'conducted_counts': conducted_counts,
        'attended_counts': attended_counts,
        'months': months,
        'percentages': percentages,
        'pie_conducted': pie_conducted,
        'pie_attended': pie_attended,
        'pie_cancelled': pie_cancelled,
        'pie_has': pie_has
    }

@app.route('/')
def dashboard():
    subject_stats, pie_stats, has_attendance_data = get_attendance_stats()
    monthly_stats = get_monthly_stats()
    has_data = has_attendance_data or monthly_stats['pie_has']

    # AI prediction excluding cancelled classes
    db = get_db()
    this_month = datetime.now().strftime("%Y-%m")
    result = db.execute("""
        SELECT
            COUNT(CASE WHEN status != 'Cancelled' THEN 1 END) as conducted,
            SUM(CASE WHEN status='Attended' THEN 1 ELSE 0 END) as attended
        FROM attendance
        WHERE strftime('%Y-%m', date) = ?
    """, (this_month,)).fetchone()
    conducted = result['conducted'] if result['conducted'] else 0
    attended = result['attended'] if result['attended'] else 0
    if conducted == 0:
        prediction_percent = 100
    else:
        prediction_percent = int(round((attended / conducted) * 100))

    return render_template("dashboard.html",
        subject_stats=subject_stats,
        pie_stats=pie_stats,
        has_attendance_data=has_attendance_data,
        has_data=has_data,
        prediction_percent=prediction_percent,
        **monthly_stats
    )

@app.route('/mark_attendance', methods=['GET', 'POST'])
def mark_attendance():
    db = get_db()
    today_schedule = get_today_lectures()
    message = ""
    if request.method == 'POST' and not request.form.get('add_subject'):
        today_date = datetime.today().strftime('%Y-%m-%d')
        for lec in today_schedule:
            key = f"{lec['subject']}_{lec['lecture_number']}"
            status = request.form.get(key, 'Blank')
            att_exists = db.execute('''
                SELECT id FROM attendance
                WHERE date = ? AND subject_id = ? AND lecture_number = ?
            ''', (today_date, lec['subject_id'], lec['lecture_number'])).fetchone()
            if att_exists:
                db.execute('UPDATE attendance SET status = ? WHERE id = ?', (status, att_exists["id"]))
            else:
                db.execute(
                    'INSERT INTO attendance (date, subject_id, lecture_number, status) VALUES (?, ?, ?, ?)',
                    (today_date, lec['subject_id'], lec['lecture_number'], status)
                )
        db.commit()
        return redirect(url_for('mark_attendance'))
    return render_template('mark_attendance.html',
        today_schedule=today_schedule,
        message=message)

@app.route('/subjects', methods=['GET', 'POST'])
def subjects():
    db = get_db()
    message = ""
    if request.method == 'POST':
        if request.form.get('add_subject'):
            name = request.form.get('subject_name')
            if name:
                db.execute("INSERT OR IGNORE INTO subjects (name) VALUES (?)", (name,))
                subject_id = db.execute("SELECT id FROM subjects WHERE name = ?", (name,)).fetchone()["id"]
                for day in ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday']:
                    num = int(request.form.get(f'num_{day}', 0))
                    if num > 0:
                        db.execute("INSERT INTO lectures (subject_id, day_of_week, number_per_day) VALUES (?, ?, ?)",
                            (subject_id, day, num))
                db.commit()
                message = f"Subject '{name}' and lectures added!"
        elif request.form.get('delete_lecture'):
            lid = request.form.get('delete_lecture')
            if lid:
                db.execute("DELETE FROM lectures WHERE id = ?", (lid,))
                db.commit()
                message = "Lecture deleted."
    subjects = get_subjects()
    schedule = get_lecture_schedule()
    return render_template("subjects.html", subjects=subjects, schedule=schedule, message=message)

@app.route('/delete_lecture/<int:lecture_id>', methods=['POST'])
def delete_lecture(lecture_id):
    db = get_db()
    db.execute("DELETE FROM lectures WHERE id = ?", (lecture_id,))
    db.commit()
    return redirect(url_for('subjects'))

@app.route('/semesters')
def semesters():
    return render_template("semesters.html")

if __name__ == "__main__":
    app.run(debug=True)
