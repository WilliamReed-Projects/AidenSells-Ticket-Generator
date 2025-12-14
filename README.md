# AidenSells Ticket Generator backend

This repository now ships with a lightweight Python backend that powers the login flow, admin panel, and email sending for the invoice generator UI.

## Running the server

1. Make sure Python 3.11+ is available.
2. From the project root, run:

```bash
python server.py
```

The server listens on `http://0.0.0.0:3000` by default. You can change the port with the `PORT` environment variable.

## Authentication

- A default user is created on first start:
  - **Username:** `demo`
  - **Password:** `password123`
  - **isPaid:** `true` (unlocks generator actions)
- Default values can be overridden with the `DEFAULT_USER_USERNAME`, `DEFAULT_USER_PASSWORD`, and `DEFAULT_USER_IS_PAID` environment variables.
- The admin area uses the `ADMIN_PASSWORD` environment variable (default: `admin123`).

The frontend uses cookie-based sessions. Calling `/api/auth/login` sets an HTTP-only cookie that `/api/auth/me` uses to keep the user signed in.

## Email delivery

Invoices can be sent via `POST /api/invoices/email` with a JSON body containing `to`, `subject`, and `html`. Configure SMTP by setting `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and optionally `SMTP_FROM`. If SMTP is not configured, the server saves the email contents to `data/outbox/` for inspection so the UI button still reports success during development.

## Admin endpoints

- `POST /api/admin/login` — authenticate with the admin password.
- `GET /api/admin/users` — list users.
- `POST /api/auth/admin/create-user` — create a new login for the generator.
- `PATCH /api/admin/users/:id/toggle-paid` — flip the paid status that unlocks generator features.
- `DELETE /api/admin/users/:id` — remove a user.

User-facing endpoints:

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

The server automatically creates the `data/app.sqlite3` database on first run. Database and outbox files are ignored by git.
