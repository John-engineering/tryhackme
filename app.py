"""
Meridian Trust Bank — intentionally vulnerable practice target.

This is a DELIBERATELY INSECURE web application built for security education
and offline hacking practice (CTF / TryHackMe style). Do NOT deploy it on a
public network or reuse any of this code in a real application.

Run it locally, poke at it, and try to reach the hidden developer panel and
recover the flag. See README.md for setup; see SOLUTION.md only if you're
stuck.
"""

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from flask import Flask, g, jsonify, request, render_template, Response

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_ROOT, "bank.db")

# The server "secret" for signing tokens. It is intentionally never used to
# reject a forged token when the caller claims alg=none (see verify_token).
TOKEN_SECRET = b"meridian-prod-signing-key-do-not-change"

FLAG = "FLAG{cl13nt_s1de_trust_1s_n0_trust_at_all}"

app = Flask(__name__)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def sha256(text):
    # Unsalted SHA-256 — fast and rainbow-table friendly. That's the point.
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def init_db():
    fresh = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email    TEXT,
            pw_sha256 TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'customer',
            balance  INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            acct_id  INTEGER NOT NULL,
            memo     TEXT,
            amount   INTEGER NOT NULL,
            ts       INTEGER NOT NULL
        );
        """
    )
    if fresh:
        seed = [
            # username, email, password, role, balance
            ("m.okafor",  "m.okafor@meridiantrust.example",  "sunshine1",   "customer", 4210),
            ("d.laurent", "d.laurent@meridiantrust.example", "letmein2020", "customer", 87650),
            ("s.petrov",  "s.petrov@meridiantrust.example",  "iloveyou",    "customer", 300),
            # The administrator. Weak, crackable password on purpose.
            ("admin",     "root@meridiantrust.example",      "trustno1",    "admin",    9999999),
        ]
        for username, email, pw, role, bal in seed:
            db.execute(
                "INSERT INTO users (username, email, pw_sha256, role, balance) VALUES (?,?,?,?,?)",
                (username, email, sha256(pw), role, bal),
            )
        db.commit()
        txns = [
            (2, "Payroll — Northwind Ltd",     52000, int(time.time()) - 864000),
            (2, "Transfer to savings",         -3000, int(time.time()) - 600000),
            (2, "Card payment — Blue Bottle",    -18, int(time.time()) - 90000),
            (1, "Refund — Contoso Store",        120, int(time.time()) - 200000),
            (4, "Internal settlement",       9000000, int(time.time()) - 400000),
        ]
        for acct, memo, amt, ts in txns:
            db.execute(
                "INSERT INTO transactions (acct_id, memo, amount, ts) VALUES (?,?,?,?)",
                (acct, memo, amt, ts),
            )
        db.commit()
    db.close()


# --------------------------------------------------------------------------
# Token handling  (JWT-lookalike, hand-rolled so the flaw is self-contained)
# --------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def issue_token(uid, username, role):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"uid": uid, "user": username, "role": role, "iat": int(time.time())}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = b64url(hmac.new(TOKEN_SECRET, signing_input, hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def verify_token(token):
    """Return the payload dict if the token is 'valid', else None.

    The flaw: an attacker-supplied header with alg='none' skips the signature
    check entirely, so the role field can be rewritten at will.
    """
    try:
        h_b64, p_b64, sig = token.split(".")
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except Exception:
        return None

    alg = header.get("alg", "")
    if alg == "none":
        # "Unsecured" JWT support. Convenient for internal tooling.
        return payload

    signing_input = f"{h_b64}.{p_b64}".encode()
    expected = b64url(hmac.new(TOKEN_SECRET, signing_input, hashlib.sha256).digest())
    if hmac.compare_digest(expected, sig):
        return payload
    return None


def current_user():
    # Accept the session token from the Authorization header (used by the
    # front-end's fetch/XHR calls) OR from the mtb_token cookie (sent
    # automatically on plain page navigations, e.g. opening /console/dev).
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = verify_token(auth[7:].strip())
        if payload:
            return payload
    cookie_tok = request.cookies.get("mtb_token")
    if cookie_tok:
        return verify_token(cookie_tok)
    return None


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/signup")
def signup_page():
    return render_template("signup.html")


@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /dashboard\n"
        "Disallow: /console/dev\n"        # <- internal only
        "Disallow: /api/_internal/\n"     # <- do not index
    )
    return Response(body, mimetype="text/plain")


# The developer panel. Server-side gate: must present a token whose role is
# 'admin'. The gate is real — but the token that feeds it is forgeable.
@app.route("/console/dev")
def dev_panel():
    user = current_user()
    if not user or user.get("role") != "admin":
        return render_template("dev_denied.html"), 403
    return render_template("dev.html", who=user.get("user", "?"))


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify(error="username and password required"), 400
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return jsonify(error="username already taken"), 409
    db.execute(
        "INSERT INTO users (username, email, pw_sha256, role, balance) VALUES (?,?,?,?,?)",
        (username, email, sha256(password), "customer", 1000),
    )
    db.commit()
    return jsonify(ok=True, message="account created")


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username=? AND pw_sha256=?",
        (username, sha256(password)),
    ).fetchone()
    if not row:
        return jsonify(error="invalid credentials"), 401
    token = issue_token(row["id"], row["username"], row["role"])
    return jsonify(ok=True, token=token, uid=row["id"], role=row["role"])


# Broken object-level authorization: any authenticated caller can read any
# account by id. No check that the account belongs to them.
@app.route("/api/account/<int:acct_id>")
def api_account(acct_id):
    if not current_user():
        return jsonify(error="unauthenticated"), 401
    db = get_db()
    row = db.execute(
        "SELECT id, username, email, role, balance FROM users WHERE id=?",
        (acct_id,),
    ).fetchone()
    if not row:
        return jsonify(error="no such account"), 404
    txns = db.execute(
        "SELECT memo, amount, ts FROM transactions WHERE acct_id=? ORDER BY ts DESC",
        (acct_id,),
    ).fetchall()
    return jsonify(
        account={k: row[k] for k in row.keys()},
        transactions=[dict(t) for t in txns],
    )


# Broken function-level authorization: 'from' is taken from the request body,
# so a caller can move money out of an account that isn't theirs.
@app.route("/api/transfer", methods=["POST"])
def api_transfer():
    if not current_user():
        return jsonify(error="unauthenticated"), 401
    data = request.get_json(silent=True) or {}
    try:
        src = int(data["from"])
        dst = int(data["to"])
        amount = int(data["amount"])
    except Exception:
        return jsonify(error="from, to, amount required"), 400
    if amount <= 0:
        return jsonify(error="amount must be positive"), 400
    db = get_db()
    s = db.execute("SELECT balance FROM users WHERE id=?", (src,)).fetchone()
    d = db.execute("SELECT 1 FROM users WHERE id=?", (dst,)).fetchone()
    if not s or not d:
        return jsonify(error="account not found"), 404
    if s["balance"] < amount:
        return jsonify(error="insufficient funds"), 400
    now = int(time.time())
    db.execute("UPDATE users SET balance=balance-? WHERE id=?", (amount, src))
    db.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, dst))
    db.execute("INSERT INTO transactions (acct_id, memo, amount, ts) VALUES (?,?,?,?)",
               (src, f"Transfer to #{dst}", -amount, now))
    db.execute("INSERT INTO transactions (acct_id, memo, amount, ts) VALUES (?,?,?,?)",
               (dst, f"Transfer from #{src}", amount, now))
    db.commit()
    return jsonify(ok=True)


# Internal debug endpoint — gated behind admin role like the dev panel.
# Dumps the raw user table, password hashes included.
@app.route("/api/_internal/users")
def api_internal_users():
    user = current_user()
    if not user or user.get("role") != "admin":
        return jsonify(error="forbidden"), 403
    db = get_db()
    rows = db.execute("SELECT id, username, email, role, pw_sha256, balance FROM users").fetchall()
    return jsonify(users=[dict(r) for r in rows])


@app.route("/api/_internal/flag")
def api_internal_flag():
    user = current_user()
    if not user or user.get("role") != "admin":
        return jsonify(error="forbidden"), 403
    return jsonify(flag=FLAG)


if __name__ == "__main__":
    init_db()
    print(" * Meridian Trust Bank (vulnerable practice target) on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
