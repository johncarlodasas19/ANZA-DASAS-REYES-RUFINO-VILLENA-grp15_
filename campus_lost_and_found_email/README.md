Campus Lost & Found (Flask) — Email Notification build
-----------------------------------------------------
- Includes admin email notifications for claim actions (approve/reject/delete).
- Configure SMTP via environment variables:
  SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM (optional)
- Seed the DB with sample data: `flask seeddb` or `python app.py seeddb`
- Run: python app.py
