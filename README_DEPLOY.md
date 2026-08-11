# The Eden Kids Campus — complete backend package

## What is included
- Existing public school website (`templates/public.html`) with original embedded logo/images
- Flask backend (`app.py`)
- Admin / Teacher / Student authentication
- SQLite database with automatic table creation
- Users, classes, student/teacher profiles
- Attendance, results, homework
- Notices, events, gallery, admissions
- Admission enquiry form endpoint
- Mobile-friendly portal pages
- Health check at `/api/health`

## Local test
```bash
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

## Demo accounts
These are for initial testing only and MUST be changed before real use:
- admin / EdenAdmin#2026
- teacher01 / Teacher#2026
- student01 / Student#2026

## Render deployment
1. Push this package to a GitHub repository.
2. Create a Render Web Service from the repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add environment variable `EDEN_SECRET_KEY` to a long random value.
6. Add `EDEN_ADMIN_PASSWORD`, `EDEN_TEACHER_PASSWORD`, `EDEN_STUDENT_PASSWORD` with new passwords.
7. Set `COOKIE_SECURE=1`.

### Important database note
The default database is SQLite. On a cloud service with an ephemeral filesystem, SQLite data can be lost on redeploy/restart. For production, use a persistent disk or migrate the database layer to PostgreSQL/Supabase. This package deliberately keeps SQLite as the simple first deployment so it can be tested without creating a paid database first.

## GitHub Pages note
GitHub Pages can continue hosting the current public HTML, but a real login cannot execute there by itself. The Flask service must be hosted separately. After deployment, the public site's Login form should point to the backend domain.
