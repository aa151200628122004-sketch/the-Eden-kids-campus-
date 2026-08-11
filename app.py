import os, sqlite3, secrets, hashlib, hmac
from functools import wraps
from datetime import date
from flask import Flask, request, redirect, session, render_template, flash, jsonify
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, 'eden_school.db')
UPLOAD = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD, exist_ok=True)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('EDEN_SECRET_KEY', 'CHANGE-ME-IN-PRODUCTION')
app.config.update(
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '0') == '1',
)


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c


def hpw(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000)
    return salt.hex() + ':' + digest.hex()


def cpw(password, stored):
    try:
        salt, digest = stored.split(':', 1)
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 310000)
        return hmac.compare_digest(actual.hex(), digest)
    except Exception:
        return False


def init_db():
    c = db()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
      full_name TEXT NOT NULL,
      email TEXT DEFAULT '', phone TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS classes(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, section TEXT DEFAULT '',
      teacher_id INTEGER, UNIQUE(name,section), FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS student_profiles(
      user_id INTEGER PRIMARY KEY, roll_no TEXT DEFAULT '', class_id INTEGER,
      guardian_name TEXT DEFAULT '', guardian_phone TEXT DEFAULT '', address TEXT DEFAULT '',
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS teacher_profiles(
      user_id INTEGER PRIMARY KEY, designation TEXT DEFAULT 'Teacher', subject TEXT DEFAULT '',
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS attendance(
      id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, class_id INTEGER,
      attendance_date TEXT NOT NULL, status TEXT NOT NULL, marked_by INTEGER,
      UNIQUE(student_id,attendance_date), FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS results(
      id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, subject TEXT NOT NULL,
      exam TEXT NOT NULL, obtained REAL NOT NULL, total REAL NOT NULL, term TEXT DEFAULT '',
      entered_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(student_id,subject,exam), FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS homework(
      id INTEGER PRIMARY KEY AUTOINCREMENT, class_id INTEGER, subject TEXT NOT NULL, title TEXT NOT NULL,
      details TEXT NOT NULL, due_date TEXT, teacher_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS notices(
      id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL,
      created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, details TEXT DEFAULT '',
      event_date TEXT, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS gallery(
      id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, filename TEXT NOT NULL,
      created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS admissions(
      id INTEGER PRIMARY KEY AUTOINCREMENT, student_name TEXT NOT NULL, guardian_name TEXT NOT NULL,
      phone TEXT NOT NULL, class_name TEXT NOT NULL, message TEXT DEFAULT '',
      status TEXT DEFAULT 'New', created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    ''')
    seeds = [
        ('admin', os.environ.get('EDEN_ADMIN_PASSWORD', 'EdenAdmin#2026'), 'admin', 'School Administrator'),
        ('teacher01', os.environ.get('EDEN_TEACHER_PASSWORD', 'Teacher#2026'), 'teacher', 'Demo Teacher'),
        ('student01', os.environ.get('EDEN_STUDENT_PASSWORD', 'Student#2026'), 'student', 'Demo Student'),
    ]
    for username, password, role_name, full_name in seeds:
        if not c.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone():
            c.execute('INSERT INTO users(username,password_hash,role,full_name) VALUES(?,?,?,?)',
                      (username, hpw(password), role_name, full_name))
    teacher = c.execute("SELECT id FROM users WHERE username='teacher01'").fetchone()
    cls = c.execute('SELECT * FROM classes ORDER BY id LIMIT 1').fetchone()
    if not cls:
        c.execute("INSERT INTO classes(name,section,teacher_id) VALUES('Grade 10','A',?)", (teacher['id'],))
        cls = c.execute('SELECT * FROM classes ORDER BY id LIMIT 1').fetchone()
    student = c.execute("SELECT id FROM users WHERE username='student01'").fetchone()
    if student and not c.execute('SELECT 1 FROM student_profiles WHERE user_id=?', (student['id'],)).fetchone():
        c.execute('''INSERT INTO student_profiles(user_id,roll_no,class_id,guardian_name,guardian_phone)
                     VALUES(?,?,?,?,?)''', (student['id'], '001', cls['id'], 'Demo Guardian', '03000000000'))
    if teacher and not c.execute('SELECT 1 FROM teacher_profiles WHERE user_id=?', (teacher['id'],)).fetchone():
        c.execute('INSERT INTO teacher_profiles(user_id,designation,subject) VALUES(?,?,?)',
                  (teacher['id'], 'Teacher', 'Science'))
    c.commit(); c.close()


init_db()


def current():
    return session.get('user')


def role_required(role_name):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current():
                return redirect('/login')
            if current().get('role') != role_name:
                return redirect('/portal')
            return fn(*args, **kwargs)
        return wrapper
    return deco


@app.before_request
def access_guard():
    path = request.path
    protected = {
        'admin': path.startswith('/admin/'),
        'teacher': path.startswith('/teacher/'),
        'student': path.startswith('/student/'),
    }
    for needed, matched in protected.items():
        if matched:
            if not current():
                return redirect('/login')
            if current().get('role') != needed:
                return redirect('/portal')
            break


def rows_html(rows, cols):
    out = '<div style="overflow:auto"><table><thead><tr>' + ''.join(f'<th>{label}</th>' for _, label in cols) + '</tr></thead><tbody>'
    for r in rows:
        out += '<tr>' + ''.join(f'<td>{r[key] if r[key] is not None else ""}</td>' for key, _ in cols) + '</tr>'
    return out + '</tbody></table></div>'


def layout(title, body):
    u = current()
    nav = '<a href="/portal">Dashboard</a>' if u else '<a href="/">Website</a>'
    if u and u['role'] == 'admin':
        nav += '<a href="/admin/users">Users</a><a href="/admin/classes">Classes</a><a href="/admin/notices">Notices</a><a href="/admin/events">Events</a><a href="/admin/gallery">Gallery</a><a href="/admin/admissions">Admissions</a>'
    elif u and u['role'] == 'teacher':
        nav += '<a href="/teacher/students">Students</a><a href="/teacher/attendance">Attendance</a><a href="/teacher/results">Results</a><a href="/teacher/homework">Homework</a>'
    elif u and u['role'] == 'student':
        nav += '<a href="/student/profile">Profile</a><a href="/student/attendance">Attendance</a><a href="/student/results">Results</a><a href="/student/homework">Homework</a><a href="/student/notices">Notices</a>'
    if u:
        nav += '<a href="/logout">Logout</a>'
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} | The Eden</title>
<style>*{{box-sizing:border-box}}body{{margin:0;font-family:Arial,sans-serif;background:#f4f7fb;color:#172033}}header{{background:linear-gradient(135deg,#10186f,#2436a5);color:#fff;padding:15px 20px;position:sticky;top:0;z-index:5}}.bar{{max-width:1200px;margin:auto;display:flex;align-items:center;justify-content:space-between;gap:12px}}.brand{{font-weight:900}}nav{{display:flex;flex-wrap:wrap;gap:5px}}nav a{{color:#fff;text-decoration:none;padding:8px 10px;border-radius:9px}}nav a:hover{{background:#ffffff22}}main{{max-width:1200px;margin:25px auto;padding:0 16px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}}.card{{background:#fff;border:1px solid #e5e9f2;border-radius:18px;padding:18px;box-shadow:0 7px 25px #16205c12}}.stat{{font-size:30px;font-weight:900;color:#b5122b}}label{{display:block;font-weight:700;margin:9px 0 5px}}input,select,textarea{{width:100%;padding:11px;border:1px solid #d5dbea;border-radius:10px;font:inherit}}textarea{{min-height:100px}}button,.btn{{background:#b5122b;color:#fff;border:0;border-radius:10px;padding:10px 14px;font-weight:800;cursor:pointer;text-decoration:none;display:inline-block}}.blue{{background:#16227f}}table{{width:100%;border-collapse:collapse;background:#fff}}th,td{{padding:10px;border-bottom:1px solid #edf0f6;text-align:left}}.muted{{color:#68758d}}.flash{{background:#fff2f2;color:#9b1528;padding:10px 14px;border-radius:10px;margin-bottom:12px}}@media(max-width:700px){{.bar{{align-items:flex-start;flex-direction:column}}nav{{width:100%}}}}</style></head><body><header><div class="bar"><div class="brand">🏫 The Eden Kids Campus & Girls College</div><nav>{nav}</nav></div></header><main>{body}</main></body></html>'''


@app.route('/')
def home():
    return render_template('public.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        selected = request.form.get('role', '').lower()
        c = db(); u = c.execute('SELECT * FROM users WHERE username=? AND active=1', (username,)).fetchone(); c.close()
        if not u or not cpw(password, u['password_hash']) or (selected and selected != u['role']):
            return layout('Login', '<div class="card" style="max-width:520px;margin:50px auto"><h1>Login failed</h1><p>Username, password or role is incorrect.</p><a class="btn" href="/">Back to website</a></div>'), 401
        session.clear(); session['user'] = {'id': u['id'], 'username': u['username'], 'role': u['role'], 'full_name': u['full_name']}
        return redirect('/portal')
    return layout('Login', '''<div class="card" style="max-width:520px;margin:50px auto"><h1>🔐 School Portal Login</h1>
    <form method="post"><label>Role</label><select name="role"><option value="admin">Admin</option><option value="teacher">Teacher</option><option value="student">Student</option></select>
    <label>Username</label><input name="username" required><label>Password</label><input type="password" name="password" required><br><br><button>Login</button></form></div>''')


@app.route('/logout')
def logout():
    session.clear(); return redirect('/')


@app.route('/portal')
def portal():
    if not current(): return redirect('/login')
    u = current(); c = db()
    if u['role'] == 'admin':
        stats = [('Users', c.execute('SELECT count(*) FROM users').fetchone()[0]), ('Teachers', c.execute("SELECT count(*) FROM users WHERE role='teacher'").fetchone()[0]), ('Students', c.execute("SELECT count(*) FROM users WHERE role='student'").fetchone()[0]), ('Admissions', c.execute('SELECT count(*) FROM admissions').fetchone()[0])]
        cards = ''.join(f'<div class="card"><div class="muted">{a}</div><div class="stat">{b}</div></div>' for a,b in stats)
        body = f'<h1>👑 Admin Dashboard</h1><p>Welcome, {u["full_name"]}.</p><div class="grid">{cards}</div><br><div class="grid"><div class="card"><h2>Management</h2><p>Accounts, classes, notices, events, gallery and admissions.</p><a class="btn blue" href="/admin/users">Open Admin Tools</a></div><div class="card"><h2>Website</h2><a class="btn" href="/">View Public Website</a></div></div>'
    elif u['role'] == 'teacher':
        n = c.execute("SELECT count(*) FROM users WHERE role='student' AND active=1").fetchone()[0]; hw = c.execute('SELECT count(*) FROM homework WHERE teacher_id=?', (u['id'],)).fetchone()[0]
        body = f'<h1>👩‍🏫 Teacher Dashboard</h1><p>Welcome, {u["full_name"]}.</p><div class="grid"><div class="card"><div class="muted">Active Students</div><div class="stat">{n}</div></div><div class="card"><div class="muted">My Homework</div><div class="stat">{hw}</div></div></div><br><div class="grid"><div class="card"><h2>Attendance</h2><a class="btn blue" href="/teacher/attendance">Manage</a></div><div class="card"><h2>Results</h2><a class="btn" href="/teacher/results">Enter</a></div><div class="card"><h2>Homework</h2><a class="btn" href="/teacher/homework">Manage</a></div></div>'
    else:
        sid = u['id']; att = c.execute('SELECT count(*) FROM attendance WHERE student_id=?',(sid,)).fetchone()[0]; res = c.execute('SELECT count(*) FROM results WHERE student_id=?',(sid,)).fetchone()[0]
        body = f'<h1>🎓 Student Dashboard</h1><p>Welcome, {u["full_name"]}.</p><div class="grid"><div class="card"><div class="muted">Attendance Records</div><div class="stat">{att}</div></div><div class="card"><div class="muted">Result Entries</div><div class="stat">{res}</div></div></div><br><div class="grid"><div class="card"><h2>Profile</h2><a class="btn blue" href="/student/profile">Open</a></div><div class="card"><h2>Results</h2><a class="btn" href="/student/results">View</a></div><div class="card"><h2>Homework</h2><a class="btn" href="/student/homework">View</a></div></div>'
    c.close(); return layout('Dashboard', body)


@app.route('/admin/users', methods=['GET','POST'])
def admin_users():
    c=db()
    if request.method=='POST':
        try:
            username=request.form['username'].strip(); password=request.form['password']; r=request.form['role']; name=request.form['full_name'].strip()
            c.execute('INSERT INTO users(username,password_hash,role,full_name,email,phone) VALUES(?,?,?,?,?,?)',(username,hpw(password),r,name,request.form.get('email',''),request.form.get('phone','')))
            uid=c.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()['id']
            if r=='student': c.execute('INSERT OR IGNORE INTO student_profiles(user_id) VALUES(?)',(uid,))
            if r=='teacher': c.execute('INSERT OR IGNORE INTO teacher_profiles(user_id) VALUES(?)',(uid,))
            c.commit(); flash('Account created.')
        except Exception as e: c.rollback(); flash('Could not create account: '+str(e))
    users=c.execute('SELECT username,role,full_name,email,phone,active,created_at FROM users ORDER BY role,full_name').fetchall(); c.close()
    body='''<h1>Users & Accounts</h1><div class="grid"><div class="card"><h2>Create Account</h2><form method="post"><label>Full name</label><input name="full_name" required><label>Username</label><input name="username" required><label>Role</label><select name="role"><option>admin</option><option>teacher</option><option>student</option></select><label>Password</label><input type="password" name="password" required><label>Email</label><input name="email"><label>Phone</label><input name="phone"><br><br><button>Create</button></form></div><div class="card"><h2>Accounts</h2>'''+rows_html(users,[('username','Username'),('role','Role'),('full_name','Name'),('email','Email'),('phone','Phone'),('active','Active')])+'</div></div>'
    return layout('Users', body)


@app.route('/admin/classes', methods=['GET','POST'])
def admin_classes():
    c=db()
    if request.method=='POST':
        try: c.execute('INSERT INTO classes(name,section,teacher_id) VALUES(?,?,?)',(request.form['name'],request.form.get('section',''),request.form.get('teacher_id') or None)); c.commit(); flash('Class added.')
        except Exception as e: c.rollback(); flash('Could not add class: '+str(e))
    teachers=c.execute("SELECT id,full_name FROM users WHERE role='teacher' AND active=1 ORDER BY full_name").fetchall(); classes=c.execute("SELECT cl.name,cl.section,COALESCE(u.full_name,'Unassigned') teacher FROM classes cl LEFT JOIN users u ON u.id=cl.teacher_id ORDER BY cl.name,cl.section").fetchall(); c.close()
    opts=''.join(f'<option value="{t["id"]}">{t["full_name"]}</option>' for t in teachers)
    body=f'<h1>Classes & Sections</h1><div class="grid"><div class="card"><h2>Add Class</h2><form method="post"><label>Class</label><input name="name" required><label>Section</label><input name="section"><label>Teacher</label><select name="teacher_id"><option value="">Unassigned</option>{opts}</select><br><br><button>Add</button></form></div><div class="card"><h2>Classes</h2>{rows_html(classes,[('name','Class'),('section','Section'),('teacher','Teacher')])}</div></div>'
    return layout('Classes', body)


@app.route('/admin/notices', methods=['GET','POST'])
def admin_notices():
    c=db()
    if request.method=='POST': c.execute('INSERT INTO notices(title,body,created_by) VALUES(?,?,?)',(request.form['title'],request.form['body'],current()['id'])); c.commit(); flash('Notice published.')
    rs=c.execute("SELECT n.title,n.body,n.created_at,COALESCE(u.full_name,'Admin') creator FROM notices n LEFT JOIN users u ON u.id=n.created_by ORDER BY n.id DESC").fetchall(); c.close()
    return layout('Notices','<h1>Notices</h1><div class="grid"><div class="card"><h2>Publish</h2><form method="post"><label>Title</label><input name="title" required><label>Message</label><textarea name="body" required></textarea><br><br><button>Publish</button></form></div><div class="card">'+rows_html(rs,[('title','Title'),('body','Message'),('creator','By'),('created_at','Date')])+'</div></div>')


@app.route('/admin/events', methods=['GET','POST'])
def admin_events():
    c=db()
    if request.method=='POST': c.execute('INSERT INTO events(title,details,event_date,created_by) VALUES(?,?,?,?)',(request.form['title'],request.form.get('details',''),request.form.get('event_date',''),current()['id'])); c.commit(); flash('Event added.')
    rs=c.execute('SELECT title,details,event_date,created_at FROM events ORDER BY event_date DESC,id DESC').fetchall(); c.close()
    return layout('Events','<h1>Events</h1><div class="card"><form method="post"><label>Event</label><input name="title" required><label>Date</label><input type="date" name="event_date"><label>Details</label><textarea name="details"></textarea><br><br><button>Add</button></form></div><br><div class="card">'+rows_html(rs,[('title','Event'),('details','Details'),('event_date','Date'),('created_at','Added')])+'</div>')


@app.route('/admin/gallery', methods=['GET','POST'])
def admin_gallery():
    c=db()
    if request.method=='POST':
        f=request.files.get('photo')
        if f and f.filename:
            fn=secrets.token_hex(8)+'_'+secure_filename(f.filename)
            f.save(os.path.join(UPLOAD,fn)); c.execute('INSERT INTO gallery(title,filename,created_by) VALUES(?,?,?)',(request.form.get('title','School Photo'),fn,current()['id'])); c.commit(); flash('Photo uploaded.')
    rs=c.execute('SELECT title,filename,created_at FROM gallery ORDER BY id DESC').fetchall(); c.close()
    imgs=''.join(f'<div class="card"><h3>{r["title"]}</h3><img src="/static/uploads/{r["filename"]}" style="max-width:100%;border-radius:12px"></div>' for r in rs)
    return layout('Gallery',f'<h1>Gallery</h1><div class="card"><form method="post" enctype="multipart/form-data"><label>Title</label><input name="title"><label>Photo</label><input type="file" name="photo" accept="image/*" required><br><br><button>Upload</button></form></div><br><div class="grid">{imgs or "<div class=card>No uploaded photos.</div>"}</div>')


@app.route('/admin/admissions')
def admin_admissions():
    c=db(); rs=c.execute('SELECT student_name,guardian_name,phone,class_name,message,status,created_at FROM admissions ORDER BY id DESC').fetchall(); c.close()
    return layout('Admissions','<h1>Admission Enquiries</h1><div class="card">'+rows_html(rs,[('student_name','Student'),('guardian_name','Guardian'),('phone','Phone'),('class_name','Class'),('message','Message'),('status','Status'),('created_at','Date')])+'</div>')


@app.route('/teacher/students')
def teacher_students():
    c=db(); rs=c.execute("SELECT u.full_name,u.username,COALESCE(sp.roll_no,'') roll_no,COALESCE(cl.name||' '||cl.section,'Unassigned') class_name FROM users u LEFT JOIN student_profiles sp ON sp.user_id=u.id LEFT JOIN classes cl ON cl.id=sp.class_id WHERE u.role='student' AND u.active=1 ORDER BY u.full_name").fetchall(); c.close()
    return layout('Students','<h1>Students</h1><div class="card">'+rows_html(rs,[('full_name','Name'),('username','Username'),('roll_no','Roll No'),('class_name','Class')])+'</div>')


@app.route('/teacher/attendance', methods=['GET','POST'])
def teacher_attendance():
    c=db(); students=c.execute("SELECT u.id,u.full_name,COALESCE(sp.roll_no,'') roll_no FROM users u LEFT JOIN student_profiles sp ON sp.user_id=u.id WHERE u.role='student' AND u.active=1 ORDER BY u.full_name").fetchall()
    if request.method=='POST':
        d=request.form.get('attendance_date') or str(date.today())
        for s in students:
            status=request.form.get(f'status_{s["id"]}','Present')
            c.execute('INSERT INTO attendance(student_id,attendance_date,status,marked_by) VALUES(?,?,?,?) ON CONFLICT(student_id,attendance_date) DO UPDATE SET status=excluded.status,marked_by=excluded.marked_by',(s['id'],d,status,current()['id']))
        c.commit(); flash('Attendance saved.')
    recent=c.execute("SELECT a.attendance_date,u.full_name,a.status FROM attendance a JOIN users u ON u.id=a.student_id ORDER BY a.attendance_date DESC,a.id DESC LIMIT 30").fetchall(); c.close()
    form=''.join(f'<div class="card"><b>{s["full_name"]}</b> <span class="muted">Roll {s["roll_no"]}</span><select name="status_{s["id"]}"><option>Present</option><option>Absent</option><option>Leave</option></select></div>' for s in students)
    return layout('Attendance',f'<h1>Attendance</h1><form method="post"><div class="card"><label>Date</label><input type="date" name="attendance_date" value="{date.today()}"></div><br><div class="grid">{form}</div><br><button>Save Attendance</button></form><br><div class="card"><h2>Recent</h2>{rows_html(recent,[('attendance_date','Date'),('full_name','Student'),('status','Status')])}</div>')


@app.route('/teacher/results', methods=['GET','POST'])
def teacher_results():
    c=db(); students=c.execute("SELECT id,full_name FROM users WHERE role='student' AND active=1 ORDER BY full_name").fetchall()
    if request.method=='POST':
        try:
            c.execute('INSERT INTO results(student_id,subject,exam,obtained,total,term,entered_by) VALUES(?,?,?,?,?,?,?) ON CONFLICT(student_id,subject,exam) DO UPDATE SET obtained=excluded.obtained,total=excluded.total,term=excluded.term,entered_by=excluded.entered_by',(request.form['student_id'],request.form['subject'],request.form['exam'],request.form['obtained'],request.form['total'],request.form.get('term',''),current()['id']))
            c.commit(); flash('Result saved.')
        except Exception as e: c.rollback(); flash('Could not save result: '+str(e))
    rs=c.execute("SELECT r.subject,r.exam,r.obtained,r.total,r.term,u.full_name FROM results r JOIN users u ON u.id=r.student_id ORDER BY r.id DESC LIMIT 50").fetchall(); c.close()
    opts=''.join(f'<option value="{s["id"]}">{s["full_name"]}</option>' for s in students)
    return layout('Results',f'<h1>Results</h1><div class="card"><form method="post"><label>Student</label><select name="student_id">{opts}</select><label>Subject</label><input name="subject" required><label>Exam</label><input name="exam" required><div class="grid"><div><label>Obtained</label><input type="number" step="0.01" name="obtained" required></div><div><label>Total</label><input type="number" step="0.01" name="total" required></div></div><label>Term</label><input name="term"><br><br><button>Save Result</button></form></div><br><div class="card">{rows_html(rs,[('full_name','Student'),('subject','Subject'),('exam','Exam'),('obtained','Obtained'),('total','Total'),('term','Term')])}</div>')


@app.route('/teacher/homework', methods=['GET','POST'])
def teacher_homework():
    c=db(); classes=c.execute('SELECT id,name,section FROM classes ORDER BY name,section').fetchall()
    if request.method=='POST':
        c.execute('INSERT INTO homework(class_id,subject,title,details,due_date,teacher_id) VALUES(?,?,?,?,?,?)',(request.form.get('class_id') or None,request.form['subject'],request.form['title'],request.form['details'],request.form.get('due_date',''),current()['id'])); c.commit(); flash('Homework posted.')
    rs=c.execute("SELECT h.subject,h.title,h.details,h.due_date,COALESCE(cl.name||' '||cl.section,'All') class_name FROM homework h LEFT JOIN classes cl ON cl.id=h.class_id WHERE h.teacher_id=? ORDER BY h.id DESC",(current()['id'],)).fetchall(); c.close()
    opts=''.join(f'<option value="{x["id"]}">{x["name"]} {x["section"]}</option>' for x in classes)
    return layout('Homework',f'<h1>Homework</h1><div class="card"><form method="post"><label>Class</label><select name="class_id"><option value="">All</option>{opts}</select><label>Subject</label><input name="subject" required><label>Title</label><input name="title" required><label>Details</label><textarea name="details" required></textarea><label>Due date</label><input type="date" name="due_date"><br><br><button>Post Homework</button></form></div><br><div class="card">{rows_html(rs,[('class_name','Class'),('subject','Subject'),('title','Title'),('details','Details'),('due_date','Due')])}</div>')


@app.route('/student/profile')
def student_profile():
    c=db(); r=c.execute("SELECT u.full_name,u.username,u.email,u.phone,COALESCE(sp.roll_no,'') roll_no,COALESCE(cl.name||' '||cl.section,'Unassigned') class_name,COALESCE(sp.guardian_name,'') guardian_name,COALESCE(sp.guardian_phone,'') guardian_phone,COALESCE(sp.address,'') address FROM users u LEFT JOIN student_profiles sp ON sp.user_id=u.id LEFT JOIN classes cl ON cl.id=sp.class_id WHERE u.id=?",(current()['id'],)).fetchone(); c.close()
    return layout('Profile',f'<h1>My Profile</h1><div class="card">'+rows_html([r],[('full_name','Name'),('username','Username'),('email','Email'),('phone','Phone'),('roll_no','Roll No'),('class_name','Class'),('guardian_name','Guardian'),('guardian_phone','Guardian Phone'),('address','Address')])+'</div>')


@app.route('/student/attendance')
def student_attendance():
    c=db(); rs=c.execute('SELECT attendance_date,status FROM attendance WHERE student_id=? ORDER BY attendance_date DESC',(current()['id'],)).fetchall(); c.close()
    return layout('Attendance','<h1>My Attendance</h1><div class="card">'+rows_html(rs,[('attendance_date','Date'),('status','Status')])+'</div>')


@app.route('/student/results')
def student_results():
    c=db(); rs=c.execute('SELECT subject,exam,obtained,total,term FROM results WHERE student_id=? ORDER BY id DESC',(current()['id'],)).fetchall(); c.close()
    return layout('Results','<h1>My Results</h1><div class="card">'+rows_html(rs,[('subject','Subject'),('exam','Exam'),('obtained','Obtained'),('total','Total'),('term','Term')])+'</div>')


@app.route('/student/homework')
def student_homework():
    c=db(); r=c.execute('SELECT sp.class_id FROM student_profiles sp WHERE sp.user_id=?',(current()['id'],)).fetchone(); class_id=r['class_id'] if r else None
    rs=c.execute("SELECT h.subject,h.title,h.details,h.due_date,COALESCE(cl.name||' '||cl.section,'All') class_name FROM homework h LEFT JOIN classes cl ON cl.id=h.class_id WHERE h.class_id IS NULL OR h.class_id=? ORDER BY h.id DESC",(class_id,)).fetchall(); c.close()
    return layout('Homework','<h1>My Homework</h1><div class="card">'+rows_html(rs,[('class_name','Class'),('subject','Subject'),('title','Title'),('details','Details'),('due_date','Due')])+'</div>')


@app.route('/student/notices')
def student_notices():
    c=db(); rs=c.execute('SELECT title,body,created_at FROM notices ORDER BY id DESC').fetchall(); c.close()
    return layout('Notices','<h1>School Notices</h1><div class="card">'+rows_html(rs,[('title','Title'),('body','Message'),('created_at','Date')])+'</div>')


@app.route('/admission', methods=['POST'])
def admission():
    data = request.form
    required = ['student_name','guardian_name','phone','class_name']
    if not all(data.get(k, '').strip() for k in required):
        return jsonify(ok=False, message='Please complete all required fields.'), 400
    c=db(); c.execute('INSERT INTO admissions(student_name,guardian_name,phone,class_name,message) VALUES(?,?,?,?,?)',(data['student_name'].strip(),data['guardian_name'].strip(),data['phone'].strip(),data['class_name'].strip(),data.get('message','').strip())); c.commit(); c.close()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept',''):
        return jsonify(ok=True)
    return redirect('/#online-services')


@app.route('/api/health')
def health():
    return jsonify(ok=True, service='The Eden Kids Campus backend')


@app.errorhandler(413)
def too_large(_):
    return jsonify(ok=False, message='File too large. Maximum 8 MB.'), 413


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
