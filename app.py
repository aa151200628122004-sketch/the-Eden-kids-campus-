import os, sqlite3, secrets, hashlib, hmac
from datetime import date
from flask import Flask, request, redirect, url_for, session, jsonify, render_template, flash
from werkzeug.utils import secure_filename

BASE_DIR=os.path.dirname(os.path.abspath(__file__))
DB=os.path.join(BASE_DIR,'eden_school.db')
UPLOAD=os.path.join(BASE_DIR,'static','uploads')
os.makedirs(UPLOAD, exist_ok=True)
app=Flask(__name__)
app.secret_key=os.environ.get('EDEN_SECRET_KEY','change-this-secret-before-production')
app.config['MAX_CONTENT_LENGTH']=8*1024*1024


def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def hpw(p, salt=None):
    salt=salt or secrets.token_bytes(16)
    d=hashlib.pbkdf2_hmac('sha256',p.encode(),salt,310000)
    return salt.hex()+':'+d.hex()

def cpw(p,stored):
    try:
        a,b=stored.split(':',1); d=hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(a),310000)
        return hmac.compare_digest(d.hex(),b)
    except Exception:return False

def init_db():
    c=db(); c.executescript('''
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')), full_name TEXT NOT NULL, email TEXT DEFAULT '', phone TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS classes(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, section TEXT DEFAULT '', teacher_id INTEGER, FOREIGN KEY(teacher_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS student_profiles(user_id INTEGER PRIMARY KEY, roll_no TEXT DEFAULT '', class_id INTEGER, guardian_name TEXT DEFAULT '', guardian_phone TEXT DEFAULT '', address TEXT DEFAULT '', FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(class_id) REFERENCES classes(id));
    CREATE TABLE IF NOT EXISTS teacher_profiles(user_id INTEGER PRIMARY KEY, designation TEXT DEFAULT 'Teacher', subject TEXT DEFAULT '', FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, class_id INTEGER, attendance_date TEXT NOT NULL, status TEXT NOT NULL, marked_by INTEGER, UNIQUE(student_id,attendance_date), FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, subject TEXT NOT NULL, exam TEXT NOT NULL, obtained REAL NOT NULL, total REAL NOT NULL, term TEXT DEFAULT '', entered_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(student_id,subject,exam), FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS homework(id INTEGER PRIMARY KEY AUTOINCREMENT, class_id INTEGER, subject TEXT NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL, due_date TEXT, teacher_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, details TEXT DEFAULT '', event_date TEXT, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS gallery(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, filename TEXT NOT NULL, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS admissions(id INTEGER PRIMARY KEY AUTOINCREMENT, student_name TEXT NOT NULL, guardian_name TEXT NOT NULL, phone TEXT NOT NULL, class_name TEXT NOT NULL, message TEXT DEFAULT '', status TEXT DEFAULT 'New', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    ''')
    seeds=[('admin','EdenAdmin#2026','admin','School Administrator'),('teacher01','Teacher#2026','teacher','Demo Teacher'),('student01','Student#2026','student','Demo Student')]
    for u,p,r,n in seeds:
        if not c.execute('SELECT id FROM users WHERE username=?',(u,)).fetchone():
            c.execute('INSERT INTO users(username,password_hash,role,full_name) VALUES(?,?,?,?)',(u,hpw(p),r,n))
    # demo class and profiles
    cls=c.execute('SELECT id FROM classes LIMIT 1').fetchone()
    if not cls:
        c.execute("INSERT INTO classes(name,section,teacher_id) VALUES('Grade 10','A',(SELECT id FROM users WHERE username='teacher01'))")
        cls=c.execute('SELECT id FROM classes LIMIT 1').fetchone()
    sid=c.execute("SELECT id FROM users WHERE username='student01'").fetchone()[0]
    if not c.execute('SELECT user_id FROM student_profiles WHERE user_id=?',(sid,)).fetchone():
        c.execute('INSERT INTO student_profiles(user_id,roll_no,class_id,guardian_name,guardian_phone) VALUES(?,?,?,?,?)',(sid,'001',cls['id'],'Demo Guardian','03000000000'))
    tid=c.execute("SELECT id FROM users WHERE username='teacher01'").fetchone()[0]
    if not c.execute('SELECT user_id FROM teacher_profiles WHERE user_id=?',(tid,)).fetchone():
        c.execute("INSERT INTO teacher_profiles(user_id,designation,subject) VALUES(?,?,?)",(tid,'Teacher','Science'))
    c.commit(); c.close()

init_db()

def current(): return session.get('user')
def role(r): return current() and current()['role']==r
def login_required(): return current() is not None

def layout(title, body, active=''):
    u=current(); name=u['full_name'] if u else ''
    nav='''<a href="/portal">Dashboard</a>'''
    if u and u['role']=='admin': nav+='''<a href="/admin/users">Users</a><a href="/admin/classes">Classes</a><a href="/admin/notices">Notices</a><a href="/admin/events">Events</a><a href="/admin/gallery">Gallery</a><a href="/admin/admissions">Admissions</a>'''
    elif u and u['role']=='teacher': nav+='''<a href="/teacher/students">Students</a><a href="/teacher/attendance">Attendance</a><a href="/teacher/results">Results</a><a href="/teacher/homework">Homework</a>'''
    elif u and u['role']=='student': nav+='''<a href="/student/profile">Profile</a><a href="/student/attendance">Attendance</a><a href="/student/results">Results</a><a href="/student/homework">Homework</a><a href="/student/notices">Notices</a>'''
    if u: nav+='''<a href="/logout">Logout</a>'''
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} | The Eden</title><style>
    *{{box-sizing:border-box}}body{{margin:0;font-family:Inter,Arial,sans-serif;background:#f4f7fb;color:#172033}}header{{background:linear-gradient(135deg,#10186f,#2436a5);color:#fff;padding:16px 24px;position:sticky;top:0;z-index:10}}.bar{{max-width:1200px;margin:auto;display:flex;align-items:center;justify-content:space-between;gap:16px}}.brand{{font-weight:900;letter-spacing:.3px}}nav{{display:flex;flex-wrap:wrap;gap:8px}}nav a{{color:#fff;text-decoration:none;padding:8px 10px;border-radius:9px}}nav a:hover{{background:#ffffff20}}main{{max-width:1200px;margin:26px auto;padding:0 18px}}h1,h2{{margin-top:0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}}.card{{background:#fff;border-radius:18px;padding:20px;box-shadow:0 8px 26px #16205c14;border:1px solid #e8ecf5}}.stat{{font-size:30px;font-weight:900;color:#b5122b}}label{{display:block;font-weight:700;margin:10px 0 5px}}input,select,textarea{{width:100%;padding:11px;border:1px solid #d5dbea;border-radius:10px;font:inherit}}textarea{{min-height:100px}}button,.btn{{background:#b5122b;color:#fff;border:0;border-radius:10px;padding:10px 14px;font-weight:800;cursor:pointer;text-decoration:none;display:inline-block}}.btn.blue{{background:#16227f}}table{{width:100%;border-collapse:collapse;background:#fff}}th,td{{padding:10px;border-bottom:1px solid #edf0f6;text-align:left}}.muted{{color:#68758d}}.flash{{background:#fff2f2;color:#9b1528;padding:10px 14px;border-radius:10px;margin-bottom:14px}}.success{{background:#effaf2;color:#1d7040}}@media(max-width:700px){{.bar{{align-items:flex-start;flex-direction:column}}nav{{width:100%}}}}
    </style></head><body><header><div class="bar"><div class="brand">🏫 The Eden Kids Campus & Girls College</div><nav>{nav}</nav></div></header><main>{body}</main></body></html>'''

def rows_html(rows, cols):
    out='<table><thead><tr>'+''.join('<th>'+c[1]+'</th>' for c in cols)+'</tr></thead><tbody>'
    for r in rows:
        out+='<tr>'+''.join('<td>'+str(r[c[0]])+'</td>' for c in cols)+'</tr>'
    return out+'</tbody></table>'

@app.route('/')
def home(): return render_template('public.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username','').strip(); password=request.form.get('password',''); selected=request.form.get('role','')
        c=db(); u=c.execute('SELECT * FROM users WHERE username=? AND active=1',(username,)).fetchone(); c.close()
        if not u or not cpw(password,u['password_hash']) or (selected and selected!=u['role']):
            flash('Invalid username/password or selected role.')
        else:
            session['user']={'id':u['id'],'username':u['username'],'role':u['role'],'full_name':u['full_name']}; return redirect('/portal')
    body='''<div class="card" style="max-width:520px;margin:50px auto"><h1>🔐 School Portal Login</h1><p class="muted">Choose your account type and sign in.</p>{fl}<form method="post"><label>Role</label><select name="role"><option value="admin">Admin</option><option value="teacher">Teacher</option><option value="student">Student</option></select><label>Username</label><input name="username" required><label>Password</label><input type="password" name="password" required><br><br><button>Login</button></form><hr><p class="muted"><b>Demo:</b> admin / EdenAdmin#2026 &nbsp; teacher01 / Teacher#2026 &nbsp; student01 / Student#2026</p></div>'''.format(fl=''.join(f'<div class="flash">{x}</div>' for x in []))
    return layout('Login',body)

@app.route('/logout')
def logout(): session.clear(); return redirect('/login')

@app.route('/portal')
def portal():
    if not login_required(): return redirect('/login')
    u=current(); c=db()
    if u['role']=='admin':
        stats=[('Users',c.execute('select count(*) from users').fetchone()[0]),('Teachers',c.execute("select count(*) from users where role='teacher'").fetchone()[0]),('Students',c.execute("select count(*) from users where role='student'").fetchone()[0]),('Admissions',c.execute('select count(*) from admissions').fetchone()[0])]
        cards=''.join(f'<div class="card"><div class="muted">{a}</div><div class="stat">{b}</div></div>' for a,b in stats)
        body=f'<h1>👑 Admin Dashboard</h1><p>Welcome, {u["full_name"]}. Full school management access.</p><div class="grid">{cards}</div><br><div class="grid"><div class="card"><h2>Quick Management</h2><p>Users, classes, notices, events, gallery and admissions.</p><a class="btn blue" href="/admin/users">Open Admin Tools</a></div><div class="card"><h2>Academic Management</h2><p>Manage classes and teacher assignments.</p><a class="btn" href="/admin/classes">Manage Classes</a></div></div>'
    elif u['role']=='teacher':
        n=c.execute("select count(*) from users where role='student' and active=1").fetchone()[0]; hw=c.execute('select count(*) from homework where teacher_id=?',(u['id'],)).fetchone()[0]
        body=f'<h1>👩‍🏫 Teacher Dashboard</h1><p>Welcome, {u["full_name"]}.</p><div class="grid"><div class="card"><div class="muted">Active Students</div><div class="stat">{n}</div></div><div class="card"><div class="muted">My Homework</div><div class="stat">{hw}</div></div></div><br><div class="grid"><div class="card"><h2>Attendance</h2><a class="btn blue" href="/teacher/attendance">Manage Attendance</a></div><div class="card"><h2>Results</h2><a class="btn" href="/teacher/results">Enter Results</a></div><div class="card"><h2>Homework</h2><a class="btn" href="/teacher/homework">Manage Homework</a></div></div>'
    else:
        sid=u['id']; att=c.execute('select count(*) from attendance where student_id=?',(sid,)).fetchone()[0]; res=c.execute('select count(*) from results where student_id=?',(sid,)).fetchone()[0]
        body=f'<h1>🎓 Student Dashboard</h1><p>Welcome, {u["full_name"]}.</p><div class="grid"><div class="card"><div class="muted">Attendance Records</div><div class="stat">{att}</div></div><div class="card"><div class="muted">Result Entries</div><div class="stat">{res}</div></div></div><br><div class="grid"><div class="card"><h2>My Profile</h2><a class="btn blue" href="/student/profile">Open Profile</a></div><div class="card"><h2>My Results</h2><a class="btn" href="/student/results">View Results</a></div><div class="card"><h2>Homework</h2><a class="btn" href="/student/homework">View Homework</a></div></div>'
    c.close(); return layout('Dashboard',body)

# ADMIN
@app.route('/admin/users',methods=['GET','POST'])
def admin_users():
    if not role('admin'): return redirect('/login')
    c=db()
    if request.method=='POST':
        try:
            u=request.form['username'].strip(); p=request.form['password']; r=request.form['role']; n=request.form['full_name'].strip(); email=request.form.get('email',''); phone=request.form.get('phone','')
            c.execute('insert into users(username,password_hash,role,full_name,email,phone) values(?,?,?,?,?,?)',(u,hpw(p),r,n,email,phone)); c.commit(); flash('Account created.')
        except Exception as e: flash('Could not create account: '+str(e))
    users=c.execute('select id,username,role,full_name,email,phone,active,created_at from users order by role,full_name').fetchall(); c.close()
    body='''<h1>Users & Accounts</h1><div class="grid"><div class="card"><h2>Create Account</h2><form method="post"><label>Full name</label><input name="full_name" required><label>Username</label><input name="username" required><label>Role</label><select name="role"><option>admin</option><option>teacher</option><option>student</option></select><label>Password</label><input type="password" name="password" required><label>Email</label><input name="email"><label>Phone</label><input name="phone"><br><br><button>Create</button></form></div><div class="card"><h2>Accounts</h2>'''+rows_html(users,[('username','Username'),('role','Role'),('full_name','Name'),('email','Email'),('phone','Phone'),('active','Active')])+'</div></div>'
    return layout('Users',body)

@app.route('/admin/classes',methods=['GET','POST'])
def admin_classes():
    if not role('admin'): return redirect('/login')
    c=db()
    if request.method=='POST':
        try: c.execute('insert into classes(name,section,teacher_id) values(?,?,?)',(request.form['name'],request.form.get('section',''),request.form.get('teacher_id') or None)); c.commit(); flash('Class added.')
        except Exception as e: flash('Could not add class: '+str(e))
    teachers=c.execute("select id,full_name from users where role='teacher' and active=1 order by full_name").fetchall(); classes=c.execute('select cl.id,cl.name,cl.section,coalesce(u.full_name,\'Unassigned\') teacher from classes cl left join users u on u.id=cl.teacher_id order by cl.name').fetchall(); c.close()
    opts=''.join(f'<option value="{t["id"]}">{t["full_name"]}</option>' for t in teachers)
    body=f'''<h1>Classes & Sections</h1><div class="grid"><div class="card"><h2>Add Class</h2><form method="post"><label>Class</label><input name="name" placeholder="Grade 9" required><label>Section</label><input name="section" placeholder="A"><label>Class Teacher</label><select name="teacher_id"><option value="">Unassigned</option>{opts}</select><br><br><button>Add Class</button></form></div><div class="card"><h2>Current Classes</h2>{rows_html(classes,[('name','Class'),('section','Section'),('teacher','Teacher')])}</div></div>'''
    return layout('Classes',body)

@app.route('/admin/notices',methods=['GET','POST'])
def admin_notices():
    if not role('admin'): return redirect('/login')
    c=db()
    if request.method=='POST': c.execute('insert into notices(title,body,created_by) values(?,?,?)',(request.form['title'],request.form['body'],current()['id'])); c.commit(); flash('Notice published.')
    rs=c.execute('select n.title,n.body,n.created_at,coalesce(u.full_name,\'Admin\') creator from notices n left join users u on u.id=n.created_by order by n.id desc').fetchall(); c.close()
    body='<h1>Notices</h1><div class="grid"><div class="card"><h2>Publish Notice</h2><form method="post"><label>Title</label><input name="title" required><label>Message</label><textarea name="body" required></textarea><br><br><button>Publish</button></form></div><div class="card"><h2>Published Notices</h2>'+rows_html(rs,[('title','Title'),('body','Message'),('creator','By'),('created_at','Date')])+'</div></div>'
    return layout('Notices',body)

@app.route('/admin/events',methods=['GET','POST'])
def admin_events():
    if not role('admin'): return redirect('/login')
    c=db()
    if request.method=='POST': c.execute('insert into events(title,details,event_date,created_by) values(?,?,?,?)',(request.form['title'],request.form.get('details',''),request.form.get('event_date',''),current()['id'])); c.commit(); flash('Event added.')
    rs=c.execute('select title,details,event_date,created_at from events order by event_date desc,id desc').fetchall(); c.close()
    body='<h1>Events & Functions</h1><div class="card"><form method="post"><label>Event</label><input name="title" placeholder="Annual Function" required><label>Date</label><input type="date" name="event_date"><label>Details</label><textarea name="details"></textarea><br><br><button>Add Event</button></form></div><br><div class="card">'+rows_html(rs,[('title','Event'),('details','Details'),('event_date','Date'),('created_at','Added')])+'</div>'
    return layout('Events',body)

@app.route('/admin/gallery',methods=['GET','POST'])
def admin_gallery():
    if not role('admin'): return redirect('/login')
    c=db()
    if request.method=='POST':
        f=request.files.get('photo'); title=request.form.get('title','School Photo').strip()
        if f and f.filename:
            fn=secrets.token_hex(8)+'_'+secure_filename(f.filename); f.save(os.path.join(UPLOAD,fn)); c.execute('insert into gallery(title,filename,created_by) values(?,?,?)',(title,fn,current()['id'])); c.commit(); flash('Photo uploaded.')
    rs=c.execute('select title,filename,created_at from gallery order by id desc').fetchall(); c.close()
    imgs=''.join(f'<div class="card"><h3>{r["title"]}</h3><img src="/static/uploads/{r["filename"]}" style="max-width:100%;border-radius:12px"></div>' for r in rs)
    body=f'<h1>Gallery</h1><div class="card"><form method="post" enctype="multipart/form-data"><label>Photo title</label><input name="title"><label>Photo</label><input type="file" name="photo" accept="image/*" required><br><br><button>Upload</button></form></div><br><div class="grid">{imgs or "<div class=\'card\'>No photos uploaded yet.</div>"}</div>'
    return layout('Gallery',body)

@app.route('/admin/admissions')
def admin_admissions():
    if not role('admin'): return redirect('/login')
    c=db(); rs=c.execute('select student_name,guardian_name,phone,class_name,message,status,created_at from admissions order by id desc').fetchall(); c.close()
    return layout('Admissions','<h1>Admission Enquiries</h1><div class="card">'+rows_html(rs,[('student_name','Student'),('guardian_name','Guardian'),('phone','Phone'),('class_name','Class'),('message','Message'),('status','Status'),('created_at','Date')])+'</div>')

# TEACHER
@app.route('/teacher/students')
def teacher_students():
    if not role('teacher'): return redirect('/login')
    c=db(); rs=c.execute('''select u.full_name,u.username,coalesce(sp.roll_no,'') roll_no,coalesce(cl.name||' '||cl.section,'Unassigned') class_name from users u left join student_profiles sp on sp.user_id=u.id left join classes cl on cl.id=sp.class_id where u.role='student' and u.active=1 order by cl.name,u.full_name''').fetchall(); c.close()
    return layout('Students','<h1>Students</h1><div class="card">'+rows_html(rs,[('full_name','Name'),('username','Username'),('roll_no','Roll No'),('class_name','Class')])+'</div>')

@app.route('/teacher/attendance',methods=['GET','POST'])
def teacher_attendance():
    if not role('teacher'): return redirect('/login')
    c=db(); students=c.execute("select id,full_name from users where role='student' and active=1 order by full_name").fetchall()
    if request.method=='POST':
        for sid in request.form.getlist('student_id'):
            status=request.form.get('status_'+sid,'present'); d=request.form.get('attendance_date') or str(date.today())
            c.execute('insert into attendance(student_id,attendance_date,status,marked_by) values(?,?,?,?) on conflict(student_id,attendance_date) do update set status=excluded.status,marked_by=excluded.marked_by',(int(sid),d,status,current()['id']))
        c.commit(); flash('Attendance saved.')
    c.close(); rows=''.join(f'<div style="padding:8px 0;border-bottom:1px solid #eee"><input type="hidden" name="student_id" value="{s["id"]}"><b>{s["full_name"]}</b> <select name="status_{s["id"]}"><option>present</option><option>absent</option><option>late</option><option>leave</option></select></div>' for s in students)
    body=f'<h1>Attendance</h1><div class="card"><form method="post"><label>Date</label><input type="date" name="attendance_date" value="{date.today()}"><br>{rows}<br><button>Save Attendance</button></form></div>'
    return layout('Attendance',body)

@app.route('/teacher/results',methods=['GET','POST'])
def teacher_results():
    if not role('teacher'): return redirect('/login')
    c=db(); students=c.execute("select id,full_name from users where role='student' and active=1 order by full_name").fetchall()
    if request.method=='POST':
        c.execute('insert into results(student_id,subject,exam,obtained,total,term,entered_by) values(?,?,?,?,?,?,?) on conflict(student_id,subject,exam) do update set obtained=excluded.obtained,total=excluded.total,term=excluded.term,entered_by=excluded.entered_by',(request.form['student_id'],request.form['subject'],request.form['exam'],request.form['obtained'],request.form['total'],request.form.get('term',''),current()['id'])); c.commit(); flash('Result saved.')
    rs=c.execute('select r.subject,r.exam,r.obtained,r.total,r.term,u.full_name student from results r join users u on u.id=r.student_id order by r.id desc limit 50').fetchall(); c.close()
    opts=''.join(f'<option value="{s["id"]}">{s["full_name"]}</option>' for s in students)
    body=f'<h1>Results</h1><div class="grid"><div class="card"><h2>Enter / Update Result</h2><form method="post"><label>Student</label><select name="student_id">{opts}</select><label>Subject</label><input name="subject" required><label>Exam</label><input name="exam" placeholder="Mid Term" required><label>Obtained</label><input type="number" step="0.01" name="obtained" required><label>Total</label><input type="number" step="0.01" name="total" required><label>Term</label><input name="term"><br><br><button>Save Result</button></form></div><div class="card"><h2>Recent Results</h2>{rows_html(rs,[('student','Student'),('subject','Subject'),('exam','Exam'),('obtained','Obtained'),('total','Total'),('term','Term')])}</div></div>'
    return layout('Results',body)

@app.route('/teacher/homework',methods=['GET','POST'])
def teacher_homework():
    if not role('teacher'): return redirect('/login')
    c=db(); classes=c.execute('select id,name,section from classes order by name').fetchall()
    if request.method=='POST': c.execute('insert into homework(class_id,subject,title,details,due_date,teacher_id) values(?,?,?,?,?,?)',(request.form.get('class_id') or None,request.form['subject'],request.form['title'],request.form['details'],request.form.get('due_date',''),current()['id'])); c.commit(); flash('Homework published.')
    rs=c.execute('select h.title,h.subject,h.details,h.due_date,coalesce(c.name||\' \'||c.section,\'All Classes\') class_name from homework h left join classes c on c.id=h.class_id where h.teacher_id=? order by h.id desc',(current()['id'],)).fetchall(); c.close()
    opts=''.join(f'<option value="{x["id"]}">{x["name"]} {x["section"]}</option>' for x in classes)
    body=f'<h1>Homework</h1><div class="grid"><div class="card"><h2>Publish Homework</h2><form method="post"><label>Class</label><select name="class_id"><option value="">All Classes</option>{opts}</select><label>Subject</label><input name="subject" required><label>Title</label><input name="title" required><label>Details</label><textarea name="details" required></textarea><label>Due Date</label><input type="date" name="due_date"><br><br><button>Publish</button></form></div><div class="card"><h2>My Homework</h2>{rows_html(rs,[('title','Title'),('subject','Subject'),('details','Details'),('due_date','Due'),('class_name','Class')])}</div></div>'
    return layout('Homework',body)

# STUDENT
@app.route('/student/profile')
def student_profile():
    if not role('student'): return redirect('/login')
    c=db(); r=c.execute('select u.full_name,u.username,u.email,u.phone,coalesce(sp.roll_no,\'\') roll_no,coalesce(cl.name||\' \'||cl.section,\'\') class_name,coalesce(sp.guardian_name,\'\') guardian_name,coalesce(sp.guardian_phone,\'\') guardian_phone,coalesce(sp.address,\'\') address from users u left join student_profiles sp on sp.user_id=u.id left join classes cl on cl.id=sp.class_id where u.id=?',(current()['id'],)).fetchone(); c.close()
    body='<h1>My Profile</h1><div class="card">'+''.join(f'<p><b>{k.replace("_"," ").title()}:</b> {r[k]}</p>' for k in r.keys())+'</div>'
    return layout('Profile',body)
@app.route('/student/attendance')
def student_attendance():
    if not role('student'): return redirect('/login')
    c=db(); rs=c.execute('select attendance_date,status from attendance where student_id=? order by attendance_date desc',(current()['id'],)).fetchall(); c.close(); return layout('Attendance','<h1>My Attendance</h1><div class="card">'+rows_html(rs,[('attendance_date','Date'),('status','Status')])+'</div>')
@app.route('/student/results')
def student_results():
    if not role('student'): return redirect('/login')
    c=db(); rs=c.execute('select subject,exam,obtained,total,term from results where student_id=? order by id desc',(current()['id'],)).fetchall(); c.close(); return layout('Results','<h1>My Results</h1><div class="card">'+rows_html(rs,[('subject','Subject'),('exam','Exam'),('obtained','Obtained'),('total','Total'),('term','Term')])+'</div>')
@app.route('/student/homework')
def student_homework():
    if not role('student'): return redirect('/login')
    c=db(); r=c.execute('select sp.class_id from student_profiles sp where sp.user_id=?',(current()['id'],)).fetchone(); cid=r['class_id'] if r else None
    rs=c.execute('select h.title,h.subject,h.details,h.due_date,coalesce(c.name||\' \'||c.section,\'All Classes\') class_name from homework h left join classes c on c.id=h.class_id where h.class_id=? or h.class_id is null order by h.id desc',(cid,)).fetchall(); c.close(); return layout('Homework','<h1>My Homework</h1><div class="card">'+rows_html(rs,[('title','Title'),('subject','Subject'),('details','Details'),('due_date','Due'),('class_name','Class')])+'</div>')
@app.route('/student/notices')
def student_notices():
    if not role('student'): return redirect('/login')
    c=db(); rs=c.execute('select title,body,created_at from notices order by id desc').fetchall(); c.close(); return layout('Notices','<h1>School Notices</h1><div class="card">'+rows_html(rs,[('title','Title'),('body','Message'),('created_at','Date')])+'</div>')

@app.post('/admission-enquiry')
def admission_enquiry():
    d=request.form; c=db(); c.execute('insert into admissions(student_name,guardian_name,phone,class_name,message) values(?,?,?,?,?)',(d.get('student_name',''),d.get('guardian_name',''),d.get('phone',''),d.get('class_name',''),d.get('message',''))); c.commit(); c.close(); return redirect(url_for('home'))

@app.get('/api/health')
def health(): return jsonify(ok=True,service='The Eden School Management System')

if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=False)
