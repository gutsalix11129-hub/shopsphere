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

DB_DIR = "/var/data" if os.path.exists("/var/data") else "/tmp"
if os.name == 'nt': DB_DIR = "."
DB_FILE = os.path.join(DB_DIR, "siber_karargah.db")

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    with get_db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, banned INTEGER DEFAULT 0, vip INTEGER DEFAULT 0, created_at TEXT, avatar TEXT);
        CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, query_type TEXT, query_param TEXT, ip TEXT, timestamp TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, subject TEXT, message TEXT, reply TEXT, status TEXT DEFAULT 'open', created_at TEXT, replied_at TEXT);
        CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user_id);
        """)
        try: c.execute("ALTER TABLE users ADD COLUMN vip INTEGER DEFAULT 0")
        except: pass
        
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('maintenance', '0')")
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('broadcast', 'Sistemimize hoş geldiniz!')")
        c.commit()

init_db()

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
        return jsonify({"success": False, "error": "IP engellendi. Çok fazla istek attınız."}), 403
    
    data_str = str(request.args) + str(request.form) + str(request.get_json(silent=True))
    for pattern in WAF_PATTERNS:
        if pattern.search(data_str):
            BANNED_IPS[ip] = now + 900
            return jsonify({"success": False, "error": "Güvenlik ihlali tespit edildi! IP'niz 15 dk banlandı."}), 403

    if request.method in ("POST", "PUT", "DELETE"):
        token = request.headers.get("X-CSRF-Token") or request.form.get("_csrf")
        stored = session.get("_csrf")
        if not token or not stored or not secrets.compare_digest(str(token).encode('utf-8'), str(stored).encode('utf-8')):
            if request.path.startswith("/api/"): return jsonify({"success": False, "error": "CSRF Hatası."}), 403
            return "CSRF doğrulaması başarısız.", 403

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

@app.route("/")
def home():
    if 'user_id' not in session: return redirect('/login')
    with get_db() as c:
        row = c.execute("SELECT username, created_at, avatar, vip FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not row: session.clear(); return redirect('/login')
        total_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_queries = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        user_queries = c.execute("SELECT COUNT(*) FROM logs WHERE user_id=?", (session['user_id'],)).fetchone()[0]
    
    avatar = row[2] if row[2] else f"https://api.dicebear.com/7.x/bottts/svg?seed={row[0]}"
    is_vip = row[3] == 1
    return render_template('index.html', total_users=total_users, total_queries=total_queries, user_queries=user_queries, username=row[0], created=row[1], avatar=avatar, is_vip=is_vip)

@app.route("/login")
def login_page():
    if 'user_id' in session: return redirect('/')
    return render_template('login.html')

@app.route("/api/check_username")
def api_check_username():
    u = (request.args.get("u") or "").strip().lower()
    if not USERNAME_RE.match(u): return jsonify({"available": False, "reason": "format"})
    with get_db() as c: exists = c.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone()
    return jsonify({"available": not exists})

@app.route("/api/register", methods=["POST"])
def api_register():
    req = request.json or {}
    u, p, avatar = (req.get("username") or "").strip().lower(), (req.get("password") or "").strip(), (req.get("avatar") or "").strip()
    if not USERNAME_RE.match(u) or len(p) < 6: return jsonify({"success": False, "error": "Geçersiz veri."})
    try:
        with get_db() as c:
            c.execute("INSERT INTO users (username, password, created_at, avatar) VALUES (?,?,?,?)", (u, generate_password_hash(p), datetime.now(timezone.utc).strftime("%Y-%m-%d"), avatar))
            c.commit()
        return jsonify({"success": True})
    except sqlite3.IntegrityError: return jsonify({"success": False, "error": "Kullanıcı adı alınmış."})

@app.route("/api/login", methods=["POST"])
def api_login():
    req = request.json or {}
    u, p = (req.get("username") or "").strip().lower(), req.get("password") or ""
    with get_db() as c: r = c.execute("SELECT id, username, password, banned FROM users WHERE username=?", (u,)).fetchone()
    if r and check_password_hash(r[2], p):
        if r[3] == 1: return jsonify({"success": False, "error": "Hesap askıya alınmış."})
        session.permanent = True; session['user_id'] = r[0]; session['username'] = r[1]
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Kullanıcı adı veya şifre hatalı."})

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

@app.route("/api/upload_avatar", methods=["POST"])
def api_upload_avatar():
    if 'user_id' not in session: return jsonify({"success": False, "error": "Giriş yapın."}), 401
    req = request.json or {}
    img_data = req.get("image")
    if not img_data or not img_data.startswith("data:image"):
        return jsonify({"success": False, "error": "Geçersiz resim verisi."})
    if len(img_data) > 2 * 1024 * 1024: 
        return jsonify({"success": False, "error": "Resim boyutu çok büyük."})
    with get_db() as c:
        c.execute("UPDATE users SET avatar=? WHERE id=?", (img_data, session['user_id']))
        c.commit()
    return jsonify({"success": True})

@app.route("/api/my_history")
def api_my_history():
    if 'user_id' not in session: return jsonify({"success": False}), 401
    with get_db() as c:
        rows = c.execute("SELECT timestamp, query_type, query_param, status FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 100", (session['user_id'],)).fetchall()
    return jsonify({"success": True, "history": [{"time": r[0], "type": r[1], "param": r[2], "status": r[3]} for r in rows]})

@app.route("/api/create_ticket", methods=["POST"])
def api_create_ticket():
    if 'user_id' not in session: return jsonify({"success": False}), 401
    req = request.json or {}
    subject = (req.get("subject") or "").strip()
    message = (req.get("message") or "").strip()
    if not subject or not message: return jsonify({"success": False, "error": "Konu ve mesaj zorunludur."})
    with get_db() as c:
        c.execute("INSERT INTO tickets (user_id, username, subject, message, status, created_at) VALUES (?,?,?,?, 'open', ?)", 
                  (session['user_id'], session['username'], subject, message, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))
        c.commit()
    return jsonify({"success": True})

@app.route("/api/my_tickets")
def api_my_tickets():
    if 'user_id' not in session: return jsonify({"success": False}), 401
    with get_db() as c:
        rows = c.execute("SELECT id, subject, message, reply, status, created_at FROM tickets WHERE user_id=? ORDER BY id DESC", (session['user_id'],)).fetchall()
    return jsonify({"success": True, "tickets": [{"id": r[0], "subject": r[1], "message": r[2], "reply": r[3], "status": r[4], "time": r[5]} for r in rows]})

@app.route("/api/sorgu", methods=["POST"])
def api_sorgu():
    if get_setting("maintenance") == "1": return jsonify({"success": False, "error": "Sistem bakımda."})
    if 'user_id' not in session: return jsonify({"success": False, "error": "Giriş yapın."}), 401
    
    ip = request.remote_addr or "?"
    req = request.json or {}; q_type = req.get("type"); uid, uname = session['user_id'], session['username']
    
    # VIP KONTROLÜ (OSINT ve Gelişmiş API'ler VIP)
    VIP_TOOLS = ["osint_ip", "osint_domain", "osint_hash", "api_wayback", "api_whois", "api_currency", "api_bin", "api_crypto", "api_email", "api_weather"]
    if q_type in VIP_TOOLS:
        with get_db() as c:
            u_row = c.execute("SELECT vip FROM users WHERE id=?", (uid,)).fetchone()
        if not u_row or u_row[0] != 1:
            return jsonify({"success": False, "error": "Bu OSINT/Gelişmiş sorgu VIP üyelere özeldir. Lütfen VIP paket satın alın."})
    
    try:
        # --- ÜCRETSİZ SORGULAR (Mernis, GSM, Plaka vb.) ---
        if q_type == "osint_hash":
            txt = (req.get('text') or '').encode()
            return jsonify({"success": True, "data": {"MD5": hashlib.md5(txt).hexdigest(), "SHA1": hashlib.sha1(txt).hexdigest(), "SHA256": hashlib.sha256(txt).hexdigest()}})
        
        if q_type == "plaka_sorgu":
            plaka = (req.get('plaka') or '').strip().upper()
            if not plaka: return jsonify({"success": False, "error": "Plaka girin."})
            r = requests.get(f"https://eokulsorguapi.onrender.com/plaka/api?plaka={plaka}", timeout=15)
            data = r.json()
            log_query(uid, uname, q_type, plaka, ip, "basarili")
            return jsonify({"success": True, "data": data})

        if q_type == "osint_ip": return jsonify({"success": True, "data": requests.get(f"http://ip-api.com/json/{req.get('ip')}", timeout=8).json()})
        if q_type == "osint_domain": return jsonify({"success": True, "data": requests.get(f"https://dns.google/resolve?name={req.get('domain')}&type=A", timeout=8).json()})

        # --- DÜNYA API'LERİ (VIP) ---
        if q_type == "api_wayback":
            url = (req.get('url') or '').strip()
            data = requests.get(f"http://archive.org/wayback/available?url={url}", timeout=15).json()
            log_query(uid, uname, q_type, url, ip, "basarili")
            return jsonify({"success": True, "data": data})

        if q_type == "api_whois":
            domain = (req.get('domain') or '').strip()
            r = requests.get(f"https://rdap.org/domain/{domain}", timeout=15)
            if r.status_code == 200:
                log_query(uid, uname, q_type, domain, ip, "basarili")
                return jsonify({"success": True, "data": r.json()})
            else: return jsonify({"success": False, "error": "Domain bulunamadı."})

        if q_type == "api_bin":
            bin_no = (req.get('bin') or '').strip()
            r = requests.get(f"https://lookup.binlist.net/{bin_no}", headers={"Accept-Version": "3"}, timeout=15)
            if r.status_code == 200:
                log_query(uid, uname, q_type, bin_no, ip, "basarili")
                return jsonify({"success": True, "data": r.json()})
            else: return jsonify({"success": False, "error": "BIN bulunamadı."})

        if q_type == "api_currency":
            r = requests.get("https://api.frankfurter.app/latest?from=USD&to=TRY,EUR,GBP", timeout=10)
            log_query(uid, uname, q_type, "USD", ip, "basarili")
            return jsonify({"success": True, "data": r.json()})

        if q_type == "api_crypto":
            r = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,ripple,solana&vs_currencies=usd,try&include_24hr_change=true", timeout=10)
            log_query(uid, uname, q_type, "Crypto", ip, "basarili")
            return jsonify({"success": True, "data": r.json()})

        if q_type == "api_email":
            email = (req.get('email') or '').strip()
            r = requests.get(f"https://open.kickbox.com/v1/disposable/{email}", timeout=10)
            if r.status_code == 200:
                log_query(uid, uname, q_type, email, ip, "basarili")
                return jsonify({"success": True, "data": r.json()})
            else: return jsonify({"success": False, "error": "Geçersiz e-posta."})

        if q_type == "api_weather":
            city = (req.get('city') or '').strip()
            geo = requests.get(f"https://geocoding-api.open-meteo.com/v1/search?name={city}&count=1&language=tr&format=json", timeout=10).json()
            if not geo.get("results"): return jsonify({"success": False, "error": "Şehir bulunamadı."})
            lat = geo["results"][0]["latitude"]; lon = geo["results"][0]["longitude"]
            w = requests.get(f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current_weather=true", timeout=10).json()
            log_query(uid, uname, q_type, city, ip, "basarili")
            return jsonify({"success": True, "data": {"sehir": geo["results"][0]["name"], "hava_durumu": w["current_weather"]}})

        # --- MERNİS / GSM / ADRES (ÜCRETSİZ) ---
        API_MAP = {
            "adsoyad": {"url": "https://violetpanel.cc/furkanapi/adsoyadapi.php", "params": {"ad":"ad","soyad":"soyad"}},
            "aile": {"url": "https://violetpanel.cc/furkanapi/ailesorguapi.php", "params": {"tc":"tc"}},
            "adres": {"url": "https://violetpanel.cc/furkanapi/adrespro.php", "params": {"tc":"tc"}},
            "tcgsm": {"url": "https://violetpanel.cc/furkanapi/gsmpro.php", "params": {"tc":"tc"}},
            "gsmtc": {"url": "https://violetpanel.cc/furkanapi/gsmpro.php", "params": {"gsm":"gsm"}},
        }
        if q_type not in API_MAP: return jsonify({"success": False, "error": "Geçersiz sorgu."})
        
        api_info = API_MAP[q_type]; params = {}; query_str = ""
        for k, rk in api_info["params"].items():
            val = (req.get(k) or "").strip()
            if not val: continue
            if rk == "tc" and not re.fullmatch(r"\d{11}", val): return jsonify({"success": False, "error": "TC 11 haneli sayı olmalı."})
            if rk == "gsm" and not re.fullmatch(r"\d{10,11}", val): return jsonify({"success": False, "error": "GSM 10-11 haneli sayı olmalı."})
            params[rk] = val[:100]; query_str += f"{rk}={val[:100]} "
            
        if not params: return jsonify({"success": False, "error": "Eksik parametre."})
        time.sleep(0.8) 
        
        r = requests.get(api_info["url"], params=params, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        try: data = r.json()
        except ValueError: return jsonify({"success": False, "error": "Dış API limiti aşıldı."})

        is_ok = data.get("success") in [True, "true"] or data.get("durum") in ["basarili", "başarılı"] or data.get("status") == "success"
        result = data.get("data") or data.get("veri") or data.get("result")
        
        if not is_ok or not result: 
            log_query(uid, uname, q_type, query_str.strip(), ip, "basarisiz")
            return jsonify({"success": False, "error": "Bulunamadı veya API hatası."})
            
        log_query(uid, uname, q_type, query_str.strip(), ip, "basarili")
        return jsonify({"success": True, "data": result})
    except Exception: 
        return jsonify({"success": False, "error": "Bağlantı hatası oluştu."})

@app.route("/api/bulk_sorgu", methods=["POST"])
def api_bulk_sorgu():
    if get_setting("maintenance") == "1": return jsonify({"success": False, "error": "Sistem bakımda."})
    if 'user_id' not in session: return jsonify({"success": False}), 401
    
    uid = session['user_id']
    with get_db() as c:
        u_row = c.execute("SELECT vip FROM users WHERE id=?", (uid,)).fetchone()
    if not u_row or u_row[0] != 1:
        return jsonify({"success": False, "error": "Toplu sorgu VIP üyelere özeldir."})

    ip = request.remote_addr or "?"
    req = request.json or {}; q_type = req.get("type"); items = req.get("items", [])
    uname = session['username']
    
    if not items or not isinstance(items, list): return jsonify({"success": False, "error": "Geçersiz veri."})
    if len(items) > 20: return jsonify({"success": False, "error": "Tek seferde en fazla 20 sorgu yapabilirsiniz."})
    
    API_MAP = {
        "aile": {"url": "https://violetpanel.cc/furkanapi/ailesorguapi.php", "param_key": "tc", "pattern": r"^\d{11}$"},
        "adres": {"url": "https://violetpanel.cc/furkanapi/adrespro.php", "param_key": "tc", "pattern": r"^\d{11}$"},
        "tcgsm": {"url": "https://violetpanel.cc/furkanapi/gsmpro.php", "param_key": "tc", "pattern": r"^\d{11}$"},
        "gsmtc": {"url": "https://violetpanel.cc/furkanapi/gsmpro.php", "param_key": "gsm", "pattern": r"^\d{10,11}$"},
    }
    if q_type not in API_MAP: return jsonify({"success": False, "error": "Bu sorgu tipi toplu aramayı desteklemiyor."})
    
    api = API_MAP[q_type]
    results = []
    
    for item in items:
        item = str(item).strip()
        if not re.match(api["pattern"], item):
            results.append({"query": item, "success": False, "error": "Format hatası"})
            continue
        try:
            time.sleep(0.8) 
            r = requests.get(api["url"], params={api["param_key"]: item}, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            data = r.json()
            is_ok = data.get("success") in [True, "true"] or data.get("durum") in ["basarili", "başarılı"]
            result = data.get("data") or data.get("veri") or data.get("result")
            if is_ok and result:
                results.append({"query": item, "success": True, "data": result})
                log_query(uid, uname, f"bulk_{q_type}", item, ip, "basarili")
            else:
                results.append({"query": item, "success": False, "error": "Bulunamadı"})
                log_query(uid, uname, f"bulk_{q_type}", item, ip, "basarisiz")
        except Exception:
            results.append({"query": item, "success": False, "error": "Bağlantı hatası"})
    return jsonify({"success": True, "results": results})

@app.route("/admin-panel-x9", methods=["GET", "POST"])
def admin_dashboard():
    ip = request.remote_addr or "?"
    if not session.get("admin"):
        error = None
        if request.method == "POST":
            if not check_rate_limit(f"admin_{ip}", max_req=5): error = "Çok fazla deneme."
            else:
                girilen_sifre = request.form.get("pass", "")
                if secrets.compare_digest(str(girilen_sifre).encode('utf-8'), str(ADMIN_PASSWORD).encode('utf-8')):
                    session["admin"] = True; session["admin_since"] = time.time(); return redirect("/admin-panel-x9")
                else: error = "Hatalı şifre."
        return render_template('admin.html', show_login=True, login_error=error, total_users=0, total_queries=0, banned_users=0, users=[], logs=[], maint="0", current_bc="", chart_labels="[]", chart_data="[]", daily_labels="[]", daily_data="[]", temp_passes={}, popular_queries=[], success_count=0, fail_count=0, tickets=[], vip_users=0)

    if time.time() - session.get("admin_since", 0) > 3600:
        session.pop("admin", None); return redirect("/admin-panel-x9")

    temp_passes = session.pop("_temp_passes", {})
    with get_db() as c:
        logs = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 500").fetchall()
        users = c.execute("""
            SELECT u.id, u.username, u.password, u.banned, u.created_at, COUNT(l.id) as query_count, u.vip
            FROM users u LEFT JOIN logs l ON u.id = l.user_id
            GROUP BY u.id ORDER BY u.id DESC
        """).fetchall()
        tickets = c.execute("SELECT * FROM tickets ORDER BY status ASC, id DESC").fetchall()
        total_queries = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        total_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        banned_users = c.execute("SELECT COUNT(*) FROM users WHERE banned=1").fetchone()[0]
        vip_users = c.execute("SELECT COUNT(*) FROM users WHERE vip=1").fetchone()[0]
        q_stats = c.execute("SELECT query_type, COUNT(*) FROM logs GROUP BY query_type").fetchall()
        
        popular_queries = c.execute("SELECT query_type, query_param, COUNT(*) as count FROM logs WHERE status='basarili' AND query_param != '' GROUP BY query_param ORDER BY count DESC LIMIT 10").fetchall()
        success_count = c.execute("SELECT COUNT(*) FROM logs WHERE status='basarili'").fetchone()[0]
        fail_count = c.execute("SELECT COUNT(*) FROM logs WHERE status='basarisiz'").fetchone()[0]
        
        chart_labels = json.dumps([q[0] for q in q_stats]); chart_data = json.dumps([q[1] for q in q_stats])
        dates = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        daily_counts = [c.execute("SELECT COUNT(*) FROM logs WHERE timestamp LIKE ?", (f"{d}%",)).fetchone()[0] for d in dates]
        daily_labels = json.dumps(dates); daily_data = json.dumps(daily_counts)

    return render_template('admin.html', show_login=False, logs=logs, users=users, total_queries=total_queries, total_users=total_users, banned_users=banned_users, vip_users=vip_users, maint=get_setting("maintenance"), current_bc=get_setting("broadcast"), chart_labels=chart_labels, chart_data=chart_data, daily_labels=daily_labels, daily_data=daily_data, temp_passes=temp_passes, popular_queries=popular_queries, success_count=success_count, fail_count=fail_count, tickets=tickets)

@app.route("/admin-toggle-vip/<int:uid>", methods=["POST"])
def admin_toggle_vip(uid):
    if not session.get("admin"): return redirect("/")
    with get_db() as c: 
        c.execute("UPDATE users SET vip = CASE WHEN vip=1 THEN 0 ELSE 1 END WHERE id=?", (uid,))
        c.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-reply-ticket/<int:tid>", methods=["POST"])
def admin_reply_ticket(tid):
    if not session.get("admin"): return redirect("/")
    reply = request.form.get("reply", "").strip()
    if reply:
        with get_db() as c:
            c.execute("UPDATE tickets SET reply=?, status='closed', replied_at=? WHERE id=?", (reply, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), tid))
            c.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-logout-x9", methods=["POST"])
def admin_logout(): session.pop("admin", None); return redirect("/admin-panel-x9")

@app.route("/admin-history/<int:uid>")
def admin_history(uid):
    if not session.get("admin"): return jsonify({"success": False}), 401
    with get_db() as c:
        rows = c.execute("SELECT timestamp, query_type, query_param, ip, status FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 200", (uid,)).fetchall()
    return jsonify({"success": True, "history": [{"time": r[0], "type": r[1], "param": r[2], "ip": r[3], "status": r[4]} for r in rows]})

@app.route("/admin-reset-pass/<int:uid>", methods=["POST"])
def admin_reset_pass(uid):
    if not session.get("admin"): return redirect("/")
    tmp = secrets.token_urlsafe(9)
    with get_db() as c:
        c.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(tmp), uid)); c.commit()
    tp = session.get("_temp_passes", {}); tp[str(uid)] = tmp; session["_temp_passes"] = dict(list(tp.items())[-5:])
    return redirect("/admin-panel-x9")

@app.route("/gizli-bakim-degistir", methods=["POST"])
def admin_toggle_maint():
    if not session.get("admin"): return redirect("/")
    set_setting("maintenance", "0" if get_setting("maintenance") == "1" else "1")
    return redirect("/admin-panel-x9")

@app.route("/gizli-duyuru-gonder", methods=["POST"])
def admin_broadcast():
    if not session.get("admin"): return redirect("/")
    set_setting("broadcast", (request.form.get("bc_text") or "").strip()[:500])
    return redirect("/admin-panel-x9")

@app.route("/admin-ban/<int:uid>", methods=["POST"])
def admin_ban_user(uid):
    if not session.get("admin"): return redirect("/")
    with get_db() as c: c.execute("UPDATE users SET banned = CASE WHEN banned=1 THEN 0 ELSE 1 END WHERE id=?", (uid,)); c.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-delete/<int:uid>", methods=["POST"])
def admin_delete_user(uid):
    if not session.get("admin"): return redirect("/")
    with get_db() as c:
        c.execute("DELETE FROM users WHERE id=?", (uid,)); c.execute("DELETE FROM logs WHERE user_id=?", (uid,)); c.commit()
    return redirect("/admin-panel-x9")

@app.errorhandler(500)
def server_error(e):
    return f"<h1 style='color:red;'>500 - Hata Detayı</h1><pre style='background:#f4f4f4; padding:20px;'>{traceback.format_exc()}</pre>", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)