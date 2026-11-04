# -*- coding: utf-8 -*-
import os
import re
import json
import time
import hashlib
import sqlite3
import secrets
import ipaddress
import traceback
from datetime import datetime, timezone, timedelta
from threading import Lock

import requests
from flask import Flask, request, jsonify, render_template, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# --- GÜVENLİK ---
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12)
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

# --- VERİTABANI (Render için /tmp) ---
DB_FILE = os.path.join(os.environ.get("DB_DIR", "/tmp" if os.name != 'nt' else "."), "siber_karargah.db")

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    with get_db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, banned INTEGER DEFAULT 0, created_at TEXT);
        CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, query_type TEXT, query_param TEXT, ip TEXT, timestamp TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        """)
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('maintenance', '0')")
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('broadcast', 'Sistemimize hoş geldiniz!')")
        c.commit()

init_db()

# --- CSRF & GÜVENLİK DUVARI ---
def csrf_token():
    if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

BANNED_IPS = {}
WAF_PATTERNS = [re.compile(r"(?i)(union\s+select|<script>|javascript:|onerror=|\.\./|\.\.\\)")]

@app.before_request
def firewall():
    ip = request.remote_addr or "0.0.0.0"
    now = time.time()
    if ip in BANNED_IPS and now < BANNED_IPS[ip]:
        return jsonify({"success": False, "error": "IP engellendi."}), 403
    
    data_str = str(request.args) + str(request.form) + str(request.get_json(silent=True))
    for pattern in WAF_PATTERNS:
        if pattern.search(data_str):
            BANNED_IPS[ip] = now + 900
            return jsonify({"success": False, "error": "Güvenlik ihlali!"}), 403

    if request.method in ("POST", "PUT", "DELETE"):
        token = request.headers.get("X-CSRF-Token") or request.form.get("_csrf")
        stored = session.get("_csrf")
        if not token or not stored or not secrets.compare_digest(token, stored):
            if request.path.startswith("/api/"): return jsonify({"success": False, "error": "CSRF Hatası."}), 403
            return "CSRF doğrulaması başarısız.", 403

# --- RATE LIMIT ---
RATE_LIMIT = {}
def check_rate_limit(key, max_req=30):
    now = time.time()
    RATE_LIMIT.setdefault(key, [])
    RATE_LIMIT[key] = [t for t in RATE_LIMIT[key] if now - t < 60]
    if len(RATE_LIMIT[key]) >= max_req: return False
    RATE_LIMIT[key].append(now)
    return True

def get_setting(k):
    with get_db() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
        return r[0] if r else ""

def set_setting(k, v):
    with get_db() as c:
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (k, v)); c.commit()

def log_query(uid, uname, q_type, param, ip, status):
    try:
        with get_db() as c:
            c.execute("INSERT INTO logs (user_id, username, query_type, query_param, ip, timestamp, status) VALUES (?,?,?,?,?,?,?)",
                      (uid, uname, q_type, param, ip, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), status)); c.commit()
    except: pass

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")

# --- ROTALAR ---
@app.route("/")
def home():
    if 'user_id' not in session: return redirect('/login')
    with get_db() as c:
        row = c.execute("SELECT username, created_at FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not row: session.clear(); return redirect('/login')
        total_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_queries = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        user_queries = c.execute("SELECT COUNT(*) FROM logs WHERE user_id=?", (session['user_id'],)).fetchone()[0]
    return render_template('index.html', total_users=total_users, total_queries=total_queries, user_queries=user_queries, username=row[0], created=row[1])

@app.route("/login")
def login_page():
    if 'user_id' in session: return redirect('/')
    return render_template('login.html')

# --- ADMIN ---
@app.route("/admin-panel-x9", methods=["GET", "POST"])
def admin_dashboard():
    ip = request.remote_addr or "?"
    if not session.get("admin"):
        error = None
        if request.method == "POST":
            if not check_rate_limit(f"admin_{ip}", max_req=5): error = "Çok fazla deneme."
            elif secrets.compare_digest(request.form.get("pass", ""), ADMIN_PASSWORD):
                session["admin"] = True; session["admin_since"] = time.time(); return redirect("/admin-panel-x9")
            else: error = "Hatalı şifre."
        
        return render_template('admin.html', show_login=True, login_error=error, 
                               total_users=0, total_queries=0, banned_users=0, users=[], logs=[], 
                               maint="0", current_bc="", chart_labels="[]", chart_data="[]", 
                               daily_labels="[]", daily_data="[]", temp_passes={})

    if time.time() - session.get("admin_since", 0) > 3600:
        session.pop("admin", None); return redirect("/admin-panel-x9")

    temp_passes = session.pop("_temp_passes", {})
    with get_db() as c:
        logs = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100").fetchall()
        users = c.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
        total_queries = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        total_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        banned_users = c.execute("SELECT COUNT(*) FROM users WHERE banned=1").fetchone()[0]
        q_stats = c.execute("SELECT query_type, COUNT(*) FROM logs GROUP BY query_type").fetchall()
        chart_labels = json.dumps([q[0] for q in q_stats]); chart_data = json.dumps([q[1] for q in q_stats])
        dates = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        daily_counts = [c.execute("SELECT COUNT(*) FROM logs WHERE timestamp LIKE ?", (f"{d}%",)).fetchone()[0] for d in dates]
        daily_labels = json.dumps(dates); daily_data = json.dumps(daily_counts)

    return render_template('admin.html', show_login=False, logs=logs, users=users, total_queries=total_queries, total_users=total_users, banned_users=banned_users, maint=get_setting("maintenance"), current_bc=get_setting("broadcast"), chart_labels=chart_labels, chart_data=chart_data, daily_labels=daily_labels, daily_data=daily_data, temp_passes=temp_passes)

# --- API AUTH ---
@app.route("/api/check_username")
def api_check_username():
    u = (request.args.get("u") or "").strip()
    if not USERNAME_RE.match(u): return jsonify({"available": False, "reason": "format"})
    with get_db() as c: exists = c.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone()
    return jsonify({"available": not exists})

@app.route("/api/register", methods=["POST"])
def api_register():
    req = request.json or {}
    u, p = (req.get("username") or "").strip(), (req.get("password") or "").strip()
    if not USERNAME_RE.match(u) or len(p) < 6: return jsonify({"success": False, "error": "Geçersiz veri."})
    try:
        with get_db() as c:
            c.execute("INSERT INTO users (username, password, created_at) VALUES (?,?,?)", (u, generate_password_hash(p), datetime.now(timezone.utc).strftime("%Y-%m-%d")))
            row = c.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone(); c.commit()
        session.permanent = True; session['user_id'] = row[0]; session['username'] = u
        return jsonify({"success": True, "auto_login": True})
    except sqlite3.IntegrityError: return jsonify({"success": False, "error": "Kullanıcı adı alınmış."})

@app.route("/api/login", methods=["POST"])
def api_login():
    req = request.json or {}
    u, p = (req.get("username") or "").strip(), req.get("password") or ""
    with get_db() as c: r = c.execute("SELECT id, username, password, banned FROM users WHERE username=?", (u,)).fetchone()
    if r and check_password_hash(r[2], p):
        if r[3] == 1: return jsonify({"success": False, "error": "Hesap askıya alınmış."})
        session.permanent = True; session['user_id'] = r[0]; session['username'] = r[1]
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Hatalı giriş."})

@app.route("/api/logout", methods=["POST"])
def api_logout(): session.clear(); return jsonify({"success": True})

@app.route("/api/get_broadcast")
def api_get_broadcast(): return jsonify({"success": True, "broadcast": get_setting("broadcast")})

@app.route("/api/change_password", methods=["POST"])
def api_change_password():
    if 'user_id' not in session: return jsonify({"success": False}), 401
    req = request.json or {}
    old, new = (req.get("old") or "").strip(), (req.get("new") or "").strip()
    if len(new) < 6: return jsonify({"success": False, "error": "Yeni şifre kısa."})
    with get_db() as c:
        r = c.execute("SELECT password FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not r or not check_password_hash(r[0], old): return jsonify({"success": False, "error": "Mevcut şifre yanlış."})
        c.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new), session['user_id'])); c.commit()
    return jsonify({"success": True})

# --- SORGU API ---
@app.route("/api/sorgu", methods=["POST"])
def api_sorgu():
    if get_setting("maintenance") == "1": return jsonify({"success": False, "error": "Sistem bakımda."})
    if 'user_id' not in session: return jsonify({"success": False, "error": "Giriş yapın."}), 401
    ip = request.remote_addr or "?"; req = request.json or {}; q_type = req.get("type")
    try:
        if q_type == "osint_ip": return jsonify({"success": True, "data": requests.get(f"http://ip-api.com/json/{req.get('ip')}", timeout=8).json()})
        if q_type == "osint_domain": return jsonify({"success": True, "data": requests.get(f"https://dns.google/resolve?name={req.get('domain')}&type=A", timeout=8).json()})
        if q_type == "osint_hash":
            txt = (req.get('text') or '').encode()
            return jsonify({"success": True, "data": {"MD5": hashlib.md5(txt).hexdigest(), "SHA1": hashlib.sha1(txt).hexdigest(), "SHA256": hashlib.sha256(txt).hexdigest()}})
        
        API_MAP = {
            "adsoyad": {"url": "https://violetpanel.cc/furkanapi/adsoyadapi.php", "params": {"ad":"ad","soyad":"soyad"}},
            "adsoyad_proxy": {"url": "https://violetpanel.cc/furkanapi/adsoyadproxapi.php", "params": {"ad":"ad","soyad":"soyad","il":"il"}},
            "aile": {"url": "https://violetpanel.cc/furkanapi/ailesorguapi.php", "params": {"tc":"tc"}},
            "adres": {"url": "https://violetpanel.cc/furkanapi/adrespro.php", "params": {"tc":"tc"}},
            "tcgsm": {"url": "https://violetpanel.cc/furkanapi/gsmpro.php", "params": {"tc":"tc"}},
            "gsmtc": {"url": "https://violetpanel.cc/furkanapi/gsmpro.php", "params": {"gsm":"gsm"}},
        }
        if q_type not in API_MAP: return jsonify({"success": False, "error": "Geçersiz sorgu."})
        api_info = API_MAP[q_type]; params = {}
        for k, rk in api_info["params"].items():
            val = (req.get(k) or "").strip()
            if val: params[rk] = val[:100]
        if not params: return jsonify({"success": False, "error": "Eksik parametre."})
        
        r = requests.get(api_info["url"], params=params, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        data = r.json()
        is_ok = data.get("success") in [True, "true"] or data.get("durum") in ["basarili", "başarılı"] or data.get("status") == "success"
        result = data.get("data") or data.get("veri") or data.get("result")
        if not is_ok or not result: return jsonify({"success": False, "error": "Bulunamadı."})
        return jsonify({"success": True, "data": result})
    except Exception: return jsonify({"success": False, "error": "Dış API hatası."})

@app.route("/admin-logout-x9", methods=["POST"])
def admin_logout(): session.pop("admin", None); return redirect("/admin-panel-x9")

# --- HATA YÖNETİMİ (Hata detayını ekrana basar) ---
@app.errorhandler(500)
def server_error(e):
    return f"<h1 style='color:red;'>500 - Hata Detayı</h1><pre style='background:#f4f4f4; padding:20px;'>{traceback.format_exc()}</pre>", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)