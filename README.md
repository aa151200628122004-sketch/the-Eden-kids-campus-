# The Eden Kids Campus & Girls College — Complete School Management System

## Included in one package
- Public school website (approved HTML preserved)
- Portal Login
- Admin dashboard
- Teacher dashboard
- Student dashboard
- Role-based access
- Secure password hashing (PBKDF2-HMAC-SHA256)
- SQLite database
- User/account management
- Classes & teacher assignment
- Student profiles
- Teacher profiles
- Attendance
- Results/marks
- Homework
- Notices
- Events & functions
- Gallery upload
- Admission enquiries

## Demo accounts
- Admin: `admin` / `EdenAdmin#2026`
- Teacher: `teacher01` / `Teacher#2026`
- Student: `student01` / `Student#2026`

Change all demo passwords and `EDEN_SECRET_KEY` before any public deployment.

## Run
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000/`.

The public site is served at `/`; the portal is `/login`.