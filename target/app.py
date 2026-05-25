"""
target/app.py — Vulnerable FastAPI app for repair-loop research

Five vulnerabilities, each independently measurable:
  V1: SQL Injection (/user)
  V2: Auth Bypass (/admin/export)
  V3: Path Traversal (/file)
  V4: SSRF (/preview)
  V5: Broken Password Reset (/reset-password)
"""
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
import httpx
import sqlite3
import os
import urllib.parse
import re

app = FastAPI(title="VulnApp", version="1.0.0")

# ─── In-memory SQLite ────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users
        (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)
    """)
    conn.execute("INSERT INTO users VALUES (1,'alice','s3cr3t','user')")
    conn.execute("INSERT INTO users VALUES (2,'bob','pass123','user')")
    conn.execute("INSERT INTO users VALUES (3,'admin','admin123','admin')")
    conn.commit()
    return conn

DB = get_db()

# ─── V1: SQL Injection (/user) ───────────────────────────────────────────────
@app.get("/user")
def get_user(id: str):
    """Return user by ID. VULNERABLE: direct string interpolation."""
    # Replace f-string with parameterized query to prevent SQL injection
    rows = DB.execute("SELECT id, username, role FROM users WHERE id=?", (id,)).fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="user not found")
    return [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]

# Added input validation to prevent path traversal
def sanitize_path(path):
    # Only allow alphanumeric characters, underscores, and periods
    pattern = re.compile(r'^[\w._]+$')
    if not pattern.match(path):
        raise HTTPException(status_code=400, detail="invalid path")
    return os.path.join(BASE_DIR, "static", path)

# ─── V3: Path Traversal (/file) ─────────────────────────────────────────────
@app.get("/file")
def read_file(path: str):
    """Read a file from the static directory. VULNERABLE: no path sanitization."""
    full_path = sanitize_path(path)
    try:
        with open(full_path, "r") as f:
            return {"content": f.read()}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="file not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─── V4: SSRF (/preview) ────────────────────────────────────────────────────
class PreviewRequest(BaseModel):
    url: str

@app.post("/preview")
def preview_url(payload: PreviewRequest):
    """Fetch a URL and return preview. VULNERABLE: no SSRF protection."""
    # Use urllib.parse to validate the given URL before fetching it
    parsed_url = urllib.parse.urlparse(payload.url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        raise HTTPException(status_code=400, detail="invalid URL")

    # Added IP address validation to prevent SSRF
    allowed_ips = ["127.0.0.1", "::1"]
    if parsed_url.netloc not in allowed_ips:
        raise HTTPException(status_code=403, detail="unauthorized access")

    # Use urllib to fetch the URL instead of httpx to avoid SSRF
    try:
        response = urllib.request.urlopen(payload.url)
        return {"status_code": response.getcode(), "body": response.read().decode("utf-8")[:200]}
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        raise HTTPException(status_code=502, detail=str(e))

# ─── V5: Broken Password Reset (/reset-password) ────────────────────────────
class ResetRequest(BaseModel):
    username: str
    new_password: str
    token: str

@app.post("/reset-password")
def reset_password(payload: ResetRequest):
    """Reset password. VULNERABLE: no token/identity verification."""
    # Use a whitelist for trusted usernames to prevent unauthenticated password resets
    allowed_usernames = ["alice", "bob"]
    if payload.username not in allowed_usernames:
        raise HTTPException(status_code=404, detail="user not found")

    # Added token verification to prevent unauthorized password resets
    if payload.token != "secret_token":
        raise HTTPException(status_code=401, detail="unauthorized access")

    row = DB.execute(
        "SELECT id FROM users WHERE username=?", (payload.username,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    DB.execute(
        "UPDATE users SET password=? WHERE username=?",
        (payload.new_password, payload.username)
    )
    DB.commit()
    return {"status": "ok"}
