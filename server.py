import base64
import hashlib
import hmac
import json
import os
import secrets
import smtplib
import sqlite3
from datetime import datetime, timedelta
from email.message import EmailMessage
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).parent
DB_PATH = ROOT / "data" / "app.sqlite3"
DB_PATH.parent.mkdir(exist_ok=True)

SESSION_COOKIE = "session_id"
SESSION_TTL_HOURS = 12
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
DEFAULT_USER = os.getenv("DEFAULT_USER_USERNAME", "demo")
DEFAULT_PASS = os.getenv("DEFAULT_USER_PASSWORD", "password123")
DEFAULT_IS_PAID = os.getenv("DEFAULT_USER_IS_PAID", "true").lower() == "true"

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "noreply@example.com")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt + digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        data = base64.b64decode(stored.encode())
        salt, digest = data[:16], data[16:]
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        return hmac.compare_digest(candidate, digest)
    except Exception:
        return False


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = connect_db()
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_paid INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                is_admin INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
    seed_default_user(conn)
    conn.close()


def seed_default_user(conn: sqlite3.Connection):
    cur = conn.execute("SELECT COUNT(*) AS count FROM users")
    count = cur.fetchone()["count"]
    if count:
        return
    password_hash = hash_password(DEFAULT_PASS)
    conn.execute(
        "INSERT INTO users (telegram_username, password_hash, is_paid) VALUES (?, ?, ?)",
        (DEFAULT_USER, password_hash, 1 if DEFAULT_IS_PAID else 0),
    )
    conn.commit()


def serialize_user(row: sqlite3.Row | None):
    if row is None:
        return None
    return {
        "id": row["id"],
        "telegramUsername": row["telegram_username"],
        "isPaid": bool(row["is_paid"]),
    }


def clean_expired_sessions():
    cutoff = datetime.utcnow() - timedelta(hours=SESSION_TTL_HOURS)
    conn = connect_db()
    with conn:
        conn.execute(
            "DELETE FROM sessions WHERE created_at < ?",
            (cutoff.isoformat(timespec="seconds"),),
        )
    conn.close()


class RequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args):
        # Reduce noise in the console
        return

    def end_headers(self):
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type"
        )
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/me":
            return self.handle_me()
        if parsed.path == "/api/admin/users":
            return self.handle_admin_users()
        # Serve static files
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/login":
            return self.handle_login()
        if parsed.path == "/api/auth/logout":
            return self.handle_logout()
        if parsed.path == "/api/admin/login":
            return self.handle_admin_login()
        if parsed.path == "/api/auth/admin/create-user":
            return self.handle_create_user()
        if parsed.path == "/api/invoices/email":
            return self.handle_send_email()
        return super().do_POST()

    def do_PATCH(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/admin/users/") and parsed.path.endswith("/toggle-paid"):
            return self.handle_toggle_paid()
        return self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/admin/users/"):
            return self.handle_delete_user()
        return self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")

    # Helpers
    def json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        data = self.rfile.read(length) if length else b""
        if not data:
            return {}
        try:
            return json.loads(data.decode())
        except json.JSONDecodeError:
            return {}

    def current_session(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookie = SimpleCookie(cookie_header)
        if SESSION_COOKIE not in cookie:
            return None
        session_id = cookie[SESSION_COOKIE].value
        conn = connect_db()
        cur = conn.execute(
            "SELECT * FROM sessions WHERE id = ?",
            (session_id,),
        )
        row = cur.fetchone()
        conn.close()
        return row

    def set_session_cookie(self, session_id: str):
        return ("Set-Cookie", f"{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax")

    def clear_session_cookie(self):
        return (
            "Set-Cookie",
            f"{SESSION_COOKIE}=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        )

    def respond_json(self, status: int, payload, extra_headers=None):
        extra_headers = extra_headers or []
        data = json.dumps(payload).encode()
        self.send_response(status)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
        for header, value in extra_headers:
            self.send_header(header, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # Endpoint handlers
    def handle_login(self):
        body = self.json_body()
        username = body.get("telegramUsername", "").strip()
        password = body.get("password", "")
        if not username or not password:
            return self.respond_json(HTTPStatus.BAD_REQUEST, {"message": "Missing credentials"})
        conn = connect_db()
        cur = conn.execute(
            "SELECT * FROM users WHERE telegram_username = ?",
            (username,),
        )
        user = cur.fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            conn.close()
            return self.respond_json(HTTPStatus.UNAUTHORIZED, {"message": "Identifiants invalides"})
        session_id = secrets.token_hex(24)
        with conn:
            conn.execute(
                "INSERT INTO sessions (id, user_id, is_admin) VALUES (?, ?, 0)",
                (session_id, user["id"]),
            )
        conn.close()
        cookie = self.set_session_cookie(session_id)
        user_payload = serialize_user(user)
        return self.respond_json(HTTPStatus.OK, {"user": user_payload}, [cookie])

    def handle_logout(self):
        session = self.current_session()
        if session is not None:
            conn = connect_db()
            with conn:
                conn.execute("DELETE FROM sessions WHERE id = ?", (session["id"],))
            conn.close()
        cookie = self.clear_session_cookie()
        return self.respond_json(HTTPStatus.OK, {"message": "Logged out"}, [cookie])

    def handle_me(self):
        session = self.current_session()
        if session is None or session["user_id"] is None:
            return self.respond_json(HTTPStatus.UNAUTHORIZED, {"message": "Not authenticated"})
        conn = connect_db()
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
        conn.close()
        if not user:
            return self.respond_json(HTTPStatus.UNAUTHORIZED, {"message": "Not authenticated"})
        return self.respond_json(HTTPStatus.OK, {"user": serialize_user(user)})

    def handle_admin_login(self):
        body = self.json_body()
        password = body.get("password", "")
        if password != ADMIN_PASSWORD:
            return self.respond_json(HTTPStatus.UNAUTHORIZED, {"message": "Mot de passe incorrect"})
        session = self.current_session()
        session_id = session["id"] if session else secrets.token_hex(24)
        conn = connect_db()
        with conn:
            # Upsert session for admin use
            conn.execute(
                "INSERT OR REPLACE INTO sessions (id, user_id, is_admin) VALUES (?, COALESCE((SELECT user_id FROM sessions WHERE id = ?), NULL), 1)",
                (session_id, session_id),
            )
        conn.close()
        cookie = self.set_session_cookie(session_id)
        return self.respond_json(HTTPStatus.OK, {"message": "Admin authenticated"}, [cookie])

    def require_admin(self):
        session = self.current_session()
        if session is None or not session["is_admin"]:
            self.respond_json(HTTPStatus.UNAUTHORIZED, {"message": "Admin access required"})
            return None
        return session

    def handle_admin_users(self):
        session = self.require_admin()
        if session is None:
            return
        conn = connect_db()
        cur = conn.execute("SELECT * FROM users ORDER BY created_at DESC")
        users = [serialize_user(row) | {"createdAt": row["created_at"]} for row in cur.fetchall()]
        conn.close()
        return self.respond_json(HTTPStatus.OK, {"users": users})

    def handle_create_user(self):
        session = self.require_admin()
        if session is None:
            return
        body = self.json_body()
        username = body.get("telegramUsername", "").strip()
        password = body.get("password", "")
        if not username or not password:
            return self.respond_json(HTTPStatus.BAD_REQUEST, {"message": "Remplissez tous les champs"})
        password_hash = hash_password(password)
        conn = connect_db()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO users (telegram_username, password_hash, is_paid) VALUES (?, ?, 0)",
                    (username, password_hash),
                )
        except sqlite3.IntegrityError:
            conn.close()
            return self.respond_json(HTTPStatus.BAD_REQUEST, {"message": "Utilisateur déjà existant"})
        cur = conn.execute("SELECT * FROM users WHERE telegram_username = ?", (username,))
        user = cur.fetchone()
        conn.close()
        return self.respond_json(HTTPStatus.CREATED, {"user": serialize_user(user)})

    def handle_toggle_paid(self):
        session = self.require_admin()
        if session is None:
            return
        parts = self.path.split("/")
        try:
            user_id = int(parts[4])
        except (IndexError, ValueError):
            return self.respond_json(HTTPStatus.BAD_REQUEST, {"message": "Invalid user id"})
        conn = connect_db()
        cur = conn.execute("SELECT is_paid FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return self.respond_json(HTTPStatus.NOT_FOUND, {"message": "User not found"})
        new_status = 0 if row["is_paid"] else 1
        with conn:
            conn.execute("UPDATE users SET is_paid = ? WHERE id = ?", (new_status, user_id))
        conn.close()
        return self.respond_json(HTTPStatus.OK, {"isPaid": bool(new_status)})

    def handle_delete_user(self):
        session = self.require_admin()
        if session is None:
            return
        parts = self.path.split("/")
        try:
            user_id = int(parts[4])
        except (IndexError, ValueError):
            return self.respond_json(HTTPStatus.BAD_REQUEST, {"message": "Invalid user id"})
        conn = connect_db()
        with conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.close()
        return self.respond_json(HTTPStatus.NO_CONTENT, {})

    def handle_send_email(self):
        session = self.current_session()
        if session is None or session["user_id"] is None:
            return self.respond_json(HTTPStatus.UNAUTHORIZED, {"message": "Not authenticated"})
        body = self.json_body()
        recipient = body.get("to")
        subject = body.get("subject") or "Votre facture"
        html = body.get("html") or ""
        if not recipient:
            return self.respond_json(HTTPStatus.BAD_REQUEST, {"message": "Veuillez entrer une adresse email"})
        success, detail = send_email(recipient, subject, html)
        status = HTTPStatus.OK if success else HTTPStatus.INTERNAL_SERVER_ERROR
        return self.respond_json(status, {"message": detail})


    # Static path override to serve from repository root
    def translate_path(self, path):
        path = super().translate_path(path)
        return path


def send_email(to_address: str, subject: str, html: str):
    if SMTP_HOST and SMTP_USER and SMTP_PASS:
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
                msg = EmailMessage()
                msg["From"] = SMTP_FROM
                msg["To"] = to_address
                msg["Subject"] = subject
                msg.set_content("Votre facture est jointe.")
                msg.add_alternative(html, subtype="html")
                smtp.send_message(msg)
            return True, "Email envoyé"
        except Exception as exc:
            return False, f"Erreur d'envoi: {exc}"
    # Fallback: write email contents to disk for inspection
    outbox = ROOT / "data" / "outbox"
    outbox.mkdir(exist_ok=True)
    filename = outbox / f"email-{datetime.utcnow().isoformat(timespec='seconds').replace(':','-')}.html"
    try:
        filename.write_text(html or "(email body vide)")
        return True, f"Email enregistré localement: {filename.name}"
    except Exception as exc:
        return False, f"Impossible d'enregistrer l'email: {exc}"


def run_server(port: int = 3000):
    os.chdir(ROOT)
    init_db()
    clean_expired_sessions()
    server = HTTPServer(("0.0.0.0", port), RequestHandler)
    print(f"Serveur démarré sur http://0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Arrêt du serveur...")
    finally:
        server.server_close()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "3000"))
    run_server(port)
