# -*- coding: utf-8 -*-
import os
import sqlite3
import hashlib
import time
import re
import json
import requests
import urllib3
import ssl
import socket
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12)
)

DB_FILE = "siber_karargah.db"
API_BASE = "https://violetpanel.cc/furkanapi"

# --- RATE LIMIT ---
RATE_LIMIT_DB = {}
def check_rate_limit(user_id):
    now = time.time()
    if user_id not in RATE_LIMIT_DB: RATE_LIMIT_DB[user_id] = []
    RATE_LIMIT_DB[user_id] = [t for t in RATE_LIMIT_DB[user_id] if now - t < 60]
    if len(RATE_LIMIT_DB[user_id]) >= 30: return False
    RATE_LIMIT_DB[user_id].append(now)
    return True

# --- GÜVENLİK BAŞLIKLARI ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

# --- DB ---
def init_db():
    with sqlite3.connect(DB_FILE) as c:
        c.execute("PRAGMA journal_mode=WAL;")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, banned INTEGER DEFAULT 0, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT,
            query_type TEXT, query_param TEXT, ip TEXT, timestamp TEXT, status TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        """)
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('maintenance', '0')")
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('broadcast', 'Sistemimize hoş geldiniz!')")
        c.commit()

init_db()

def log_query(uid, uname, q_type, param, ip, status):
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.execute("INSERT INTO logs (user_id, username, query_type, query_param, ip, timestamp, status) VALUES (?,?,?,?,?,?,?)",
                      (uid, uname, q_type, param, ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), status))
            c.commit()
    except: pass

def get_setting(k):
    with sqlite3.connect(DB_FILE) as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
        return r[0] if r else ""

def set_setting(k, v):
    with sqlite3.connect(DB_FILE) as c:
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (k, v))
        c.commit()

# --- ROUTE'LAR ---
@app.route("/")
def home():
    if 'user_id' not in session: return redirect('/login')
    with sqlite3.connect(DB_FILE) as c:
        total_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_queries = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        user_queries = c.execute("SELECT COUNT(*) FROM logs WHERE user_id=?", (session['user_id'],)).fetchone()[0]
    return render_template('index.html', total_users=total_users, total_queries=total_queries, user_queries=user_queries)

@app.route("/login")
def login_page():
    if 'user_id' in session: return redirect('/')
    return render_template('login.html')

# --- KULLANICI API'LERİ ---
@app.route("/api/me")
def api_me():
    if 'user_id' not in session: return jsonify({"success": False})
    with sqlite3.connect(DB_FILE) as c:
        created = c.execute("SELECT created_at FROM users WHERE id=?", (session['user_id'],)).fetchone()[0]
    return jsonify({"success": True, "username": session['username'], "created": created})

@app.route("/api/change_password", methods=["POST"])
def api_change_password():
    if 'user_id' not in session: return jsonify({"success": False})
    req = request.json or {}
    old, new = req.get("old",""), req.get("new","")
    if len(new) < 6: return jsonify({"success": False, "error": "Yeni şifre en az 6 karakter olmalı."})
    with sqlite3.connect(DB_FILE) as c:
        r = c.execute("SELECT password FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not r or not check_password_hash(r[0], old): return jsonify({"success": False, "error": "Mevcut şifre yanlış."})
        c.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new), session['user_id']))
        c.commit()
    return jsonify({"success": True})

@app.route("/api/my_history")
def api_my_history():
    if 'user_id' not in session: return jsonify({"success": False})
    with sqlite3.connect(DB_FILE) as c:
        logs = c.execute("SELECT query_type, query_param, timestamp, status FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 50", (session['user_id'],)).fetchall()
    return jsonify({"success": True, "history": [{"type": l[0], "param": l[1], "time": l[2], "status": l[3]} for l in logs]})

@app.route("/api/register", methods=["POST"])
def api_register():
    req = request.json or {}
    u, p = req.get("username","").strip(), req.get("password","").strip()
    if len(u) < 3 or len(p) < 6: return jsonify({"success": False, "error": "Kullanıcı adı (min 3) veya şifre (min 6) kısa."})
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.execute("INSERT INTO users (username, password, created_at) VALUES (?,?,?)", (u, generate_password_hash(p), datetime.now().strftime("%Y-%m-%d")))
            c.commit()
        return jsonify({"success": True})
    except sqlite3.IntegrityError: return jsonify({"success": False, "error": "Bu kullanıcı adı zaten alınmış."})
    except: return jsonify({"success": False, "error": "Sunucu hatası."})

@app.route("/api/login", methods=["POST"])
def api_login():
    req = request.json or {}
    u, p = req.get("username","").strip(), req.get("password","").strip()
    with sqlite3.connect(DB_FILE) as c:
        r = c.execute("SELECT id, username, password, banned FROM users WHERE username=?", (u,)).fetchone()
    if r and check_password_hash(r[2], p):
        if r[3] == 1: return jsonify({"success": False, "error": "Hesabınız askıya alınmış."})
        session.permanent = True
        session['user_id'] = r[0]; session['username'] = r[1]
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Hatalı giriş."})

@app.route("/api/logout")
def api_logout(): session.clear(); return jsonify({"success": True})

@app.route("/api/get_broadcast")
def api_get_broadcast(): return jsonify({"success": True, "broadcast": get_setting("broadcast")})

@app.route("/api/sorgu", methods=["POST"])
def api_sorgu():
    if get_setting("maintenance") == "1": return jsonify({"success": False, "error": "Sistem bakımda."})
    if 'user_id' not in session: return jsonify({"success": False, "error": "Giriş yapmalısınız."})
    if not check_rate_limit(session['user_id']): return jsonify({"success": False, "error": "Çok fazla istek attınız."})

    req = request.json or {}
    q_type = req.get("type")
    uid, uname, ip = session['user_id'], session['username'], request.remote_addr

    try:
        if q_type == "osint_ip": return jsonify({"success": True, "data": requests.get(f"http://ip-api.com/json/{req.get('ip')}", timeout=10).json()})
        elif q_type == "osint_domain": return jsonify({"success": True, "data": requests.get(f"https://dns.google/resolve?name={req.get('domain')}&type=A", timeout=10).json()})
        elif q_type == "osint_hash":
            txt = req.get('text').encode()
            return jsonify({"success": True, "data": {"MD5": hashlib.md5(txt).hexdigest(), "SHA1": hashlib.sha1(txt).hexdigest(), "SHA256": hashlib.sha256(txt).hexdigest()}})
        elif q_type == "osint_whois":
            r = requests.get(f"https://rdap.org/domain/{req.get('domain')}", timeout=10).json()
            return jsonify({"success": True, "data": {"Domain": r.get("ldhName"), "Status": r.get("status")}})
        elif q_type == "osint_github":
            r = requests.get(f"https://api.github.com/users/{req.get('user')}", timeout=10).json()
            if r.get('message') == 'Not Found': return jsonify({"success": False, "error": "Kullanıcı yok."})
            return jsonify({"success": True, "data": r})
        elif q_type == "osint_mac":
            return jsonify({"success": True, "data": {"MAC": req.get('mac'), "Uretici": requests.get(f"https://api.macvendors.com/{req.get('mac')}", timeout=10).text}})
        elif q_type == "osint_url":
            return jsonify({"success": True, "data": {"Asıl_Link": requests.get(f"https://unshorten.me/api/v2/unshorten?url={req.get('url')}", timeout=10).json().get("resolved_url")}})
        elif q_type == "osint_cve":
            r = requests.get(f"https://cve.circl.lu/api/last", timeout=10).json()
            kw = req.get('keyword').lower()
            return jsonify({"success": True, "data": [{"ID": c.get('id'), "Özet": c.get('summary')} for c in r if kw in c.get('summary', '').lower()][:10]})
        elif q_type == "osint_ssl":
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=req.get('domain')) as s:
                s.settimeout(5); s.connect((req.get('domain'), 443)); cert = s.getpeercert()
            return jsonify({"success": True, "data": {"Subject": dict(x[0] for x in cert.get("subject", [])), "Issuer": dict(x[0] for x in cert.get("issuer", [])), "Bitiş": cert.get("notAfter")}})
        elif q_type == "osint_subdomain":
            r = requests.get(f"https://crt.sh/?q=%25.{req.get('domain')}&output=json", timeout=15).json()
            subs = list(set([n.strip() for e in r for n in str(e.get("name_value","")).split("\n") if "*" not in n]))[:50]
            return jsonify({"success": True, "data": {"Domain": req.get('domain'), "Toplam": len(subs), "Subdomainler": subs}})
        elif q_type == "osint_email":
            email = req.get('email')
            if not re.match(r"^[\w.+-]+@[\w-]+\.[\w.-]+$", email): return jsonify({"success": False, "error": "Geçersiz e-posta formatı."})
            domain = email.split("@")[1]
            r = requests.get(f"https://dns.google/resolve?name={domain}&type=MX", timeout=6).json()
            mx = [a["data"] for a in r.get("Answer", []) if a.get("type") == 15]
            return jsonify({"success": True, "data": {"Email": email, "Gecerli": len(mx) > 0, "MX_Kayitlari": mx}})

        if q_type in ["aile", "adres", "tcgsm"] and len(req.get("tc","")) != 11:
             return jsonify({"success": False, "error": "TC Kimlik 11 haneli olmalıdır."})

        API_MAP = {
            "adsoyad": {"url": f"{API_BASE}/adsoyadapi.php", "params": {"ad":"ad","soyad":"soyad"}},
            "aile": {"url": f"{API_BASE}/ailesorguapi.php", "params": {"tc":"tc"}},
            "adres": {"url": f"{API_BASE}/adrespro.php", "params": {"tc":"tc"}},
            "tcgsm": {"url": f"{API_BASE}/gsmpro.php", "params": {"tc":"tc"}},
            "gsmtc": {"url": f"{API_BASE}/gsmpro.php", "params": {"gsm":"gsm"}},
        }
        if q_type in API_MAP:
            api_info = API_MAP[q_type]
            params = {}; query_str = ""
            for k, rk in api_info["params"].items():
                val = req.get(k)
                if val: params[rk] = val; query_str += f"{val} "
            if not params: return jsonify({"success": False, "error": "Eksik parametre."})

            r = requests.get(api_info["url"], params=params, timeout=20, verify=False, headers={"User-Agent":"Mozilla/5.0"})
            data = r.json()
            is_ok = data.get("success") in [True, "true"] or data.get("durum") in ["basarili", "başarılı"] or data.get("status") == "success"
            result = data.get("data") or data.get("veri") or data.get("result")
            if not result and not is_ok:
                log_query(uid, uname, q_type, query_str, ip, "basarisiz")
                return jsonify({"success": False, "error": data.get("message") or "Bulunamadı."})
            log_query(uid, uname, q_type, query_str, ip, "basarili")
            return jsonify({"success": True, "data": result or data})

        return jsonify({"success": False, "error": "Geçersiz sorgu."})
    except Exception as e:
        return jsonify({"success": False, "error": f"Sunucu hatası: {str(e)[:50]}"})

# --- ADMIN ROUTE'LARI ---
@app.route("/admin-login-x9", methods=["GET", "POST"])
def secret_login():
    if request.method == "POST":
        if request.form.get("pass") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin-panel-x9")
        return "Hatalı Şifre"
    return """<body style="background:#f8fafc;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;">
        <form method="POST" style="background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 6px rgba(0,0,0,0.1);text-align:center;">
            <h2 style="color:#1e293b;margin-bottom:20px;">Yönetici Girişi</h2>
            <input type="password" name="pass" placeholder="Şifre" style="padding:12px;border:1px solid #cbd5e1;border-radius:8px;width:100%;margin-bottom:15px;">
            <button type="submit" style="padding:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;width:100%;font-weight:bold;cursor:pointer;">Giriş Yap</button>
        </form></body>"""

@app.route("/admin-panel-x9")
def admin_dashboard():
    if not session.get("admin"): return redirect("/admin-login-x9")
    with sqlite3.connect(DB_FILE) as c:
        logs = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100").fetchall()
        users = c.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
        total_queries = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        total_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        
        # Grafik Verileri
        q_stats = c.execute("SELECT query_type, COUNT(*) FROM logs GROUP BY query_type").fetchall()
        chart_labels = json.dumps([q[0] for q in q_stats])
        chart_data = json.dumps([q[1] for q in q_stats])
        
        # Son 7 günün sorguları
        dates = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        daily_counts = []
        for d in dates:
            cnt = c.execute("SELECT COUNT(*) FROM logs WHERE timestamp LIKE ?", (f"{d}%",)).fetchone()[0]
            daily_counts.append(cnt)
        daily_labels = json.dumps(dates)
        daily_data = json.dumps(daily_counts)

    return render_template('admin.html', logs=logs, users=users, total_queries=total_queries, total_users=total_users, 
                           maint=get_setting("maintenance"), current_bc=get_setting("broadcast"),
                           chart_labels=chart_labels, chart_data=chart_data, daily_labels=daily_labels, daily_data=daily_data)

@app.route("/admin-history/<int:uid>")
def admin_user_history(uid):
    if not session.get("admin"): return jsonify({"success": False})
    with sqlite3.connect(DB_FILE) as c:
        logs = c.execute("SELECT query_type, query_param, timestamp, status FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 30", (uid,)).fetchall()
    return jsonify({"success": True, "history": [{"type": l[0], "param": l[1], "time": l[2], "status": l[3]} for l in logs]})

@app.route("/admin-reset-pass/<int:uid>")
def admin_reset_pass(uid):
    if not session.get("admin"): return redirect("/")
    with sqlite3.connect(DB_FILE) as c:
        c.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash("123456"), uid))
        c.commit()
    return redirect("/admin-panel-x9")

@app.route("/gizli-bakim-degistir")
def admin_toggle_maint():
    if not session.get("admin"): return redirect("/")
    set_setting("maintenance", "0" if get_setting("maintenance") == "1" else "1")
    return redirect("/admin-panel-x9")

@app.route("/gizli-duyuru-gonder", methods=["POST"])
def admin_broadcast():
    if not session.get("admin"): return redirect("/")
    set_setting("broadcast", request.form.get("bc_text", "").strip())
    return redirect("/admin-panel-x9")

@app.route("/admin-ban/<int:uid>")
def admin_ban_user(uid):
    if not session.get("admin"): return redirect("/")
    with sqlite3.connect(DB_FILE) as c:
        c.execute("UPDATE users SET banned = CASE WHEN banned=1 THEN 0 ELSE 1 END WHERE id=?", (uid,)); c.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-delete/<int:uid>")
def admin_delete_user(uid):
    if not session.get("admin"): return redirect("/")
    with sqlite3.connect(DB_FILE) as c:
        c.execute("DELETE FROM users WHERE id=?", (uid,)); c.execute("DELETE FROM logs WHERE user_id=?", (uid,)); c.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-logout-x9")
def admin_logout():
    session.pop("admin", None)
    return redirect("/")