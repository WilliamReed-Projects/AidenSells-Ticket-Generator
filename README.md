# AidenSells Ticket Generator backend

This repository now ships with a lightweight Python backend that powers the login flow, admin panel, and email sending for the invoice generator UI.

## Running the server

1. Make sure Python 3.11+ is available.
2. From the project root, run:

```bash
./start.sh
```

The server listens on `http://0.0.0.0:3000` by default. You can change the port with the `PORT` environment variable. `start.sh`
is included for platforms (like Railpack/Railway) that look for an executable start script during build detection; it simply exports
`PORT` and launches `python server.py`.

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

## Deploying to Railway

Railway apps are organized by project → service. Host your static frontend in one service and the Python backend in another service inside the same project so they can share the same project-level domain or separate custom domains.

1. In Railway, create **a new service** in your existing project and point it at this repository (or a fork) so it builds from the backend code.
2. In the service settings, set the **Start Command** to:

   ```bash
   ./start.sh
   ```

   Railway automatically injects the `PORT` environment variable; the start script exports it and launches the server.
3. Configure environment variables as needed (`ADMIN_PASSWORD`, `DEFAULT_USER_*`, SMTP settings, etc.).
4. Deploy the service. Railway will assign it a domain such as `https://<service>.up.railway.app`.
5. Point your frontend to the backend domain (for example, `https://<service>.up.railway.app/api/auth/login`). If you want a single domain, add a custom domain in Railway and attach it to the backend service; the server already mirrors the request `Origin` header for CORS.

Once deployed, the endpoints `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`, and `/api/invoices/email` will be reachable on your Railway URL.

### Connecting the frontend

Railway exposes two types of hostnames for a service:

- **Public networking** — a public URL such as `https://<service>.up.railway.app` or your custom domain. Use this for anything a browser needs to call; the backend will mirror the request `Origin` header so CORS succeeds.
- **Private networking** — an internal hostname like `backend-aidengen.railway.internal` that only works between Railway services inside the same project (for example, if you add a Node/React build service that proxies API calls). Browsers cannot reach this address directly.

To wire the UI to the backend:

1. Make sure **Public Networking** is enabled for the backend service and note its URL.
2. If you are hosting the static frontend elsewhere (another Railway service, Vercel, etc.), configure it to call the backend using the public URL, e.g. `https://your-backend.up.railway.app/api/auth/login`.
3. If you want everything on one domain, attach your custom domain to the backend service. This repository already includes the built static files, so the same backend service can serve both the HTML and the `/api/...` routes from that single domain.
4. Only use the internal hostname when another Railway service needs to talk to the backend privately (server-to-server); do not point the browser to the `.railway.internal` address.

## Admin endpoints


User-facing endpoints:

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

The server automatically creates the `data/app.sqlite3` database on first run. Database and outbox files are ignored by git.
