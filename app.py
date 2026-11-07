import os
import sqlite3
import json
import time
import secrets
import requests
import traceback
from datetime import datetime, timezone
from contextlib import contextmanager
from flask import Flask, request, jsonify, render_template, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

DB_DIR = "/var/data" if os.path.exists("/var/data") else "."
DB_FILE = os.path.join(DB_DIR, "siber_karargah.db")

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, banned INTEGER DEFAULT 0, vip INTEGER DEFAULT 0, created_at TEXT, avatar TEXT);
        CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, query_type TEXT, query_param TEXT, ip TEXT, timestamp TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, subject TEXT, message TEXT, reply TEXT, status TEXT DEFAULT 'open', created_at TEXT, replied_at TEXT);
        """)
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('maintenance', '0')")
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('broadcast', 'Sistemimize hoş geldiniz!')")
        c.commit()

init_db()

def get_setting(k):
    with get_db() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
        return r['value'] if r else ""

def set_setting(k, v):
    with get_db() as c:
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (k, v))
        c.commit()

def log_query(uid, uname, q_type, param, ip, status):
    try:
        with get_db() as c:
            c.execute("INSERT INTO logs (user_id, username, query_type, query_param, ip, timestamp, status) VALUES (?,?,?,?,?,?,?)",
                      (uid, uname, q_type, param, ip, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), status))
            c.commit()
    except: pass

def csrf_token():
    if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

# --- KULLANICI ROTALARI ---
@app.route("/")
def home():
    if 'user_id' not in session: return redirect('/login')
    return render_template('index.html', username=session.get('username'))

@app.route("/login")
def login_page():
    if 'user_id' in session: return redirect('/')
    return render_template('login.html')

@app.route("/api/login", methods=["POST"])
def api_login():
    req = request.json or {}
    u, p = req.get("username", "").strip().lower(), req.get("password", "")
    with get_db() as c:
        user = c.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    if user and check_password_hash(user['password'], p):
        if user['banned'] == 1: return jsonify({"success": False, "error": "Hesap askıya alınmış."})
        session['user_id'] = user['id']; session['username'] = user['username']
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Hatalı giriş."})

@app.route("/api/register", methods=["POST"])
def api_register():
    req = request.json or {}
    u, p = req.get("username", "").strip().lower(), req.get("password", "").strip()
    if len(u) < 3 or len(p) < 6: return jsonify({"success": False, "error": "Geçersiz veri."})
    try:
        with get_db() as c:
            c.execute("INSERT INTO users (username, password, created_at) VALUES (?,?,?)", (u, generate_password_hash(p), datetime.now().strftime("%Y-%m-%d")))
            c.commit()
        return jsonify({"success": True})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Kullanıcı adı alınmış."})

@app.route("/api/logout", methods=["POST"])
def api_logout(): session.clear(); return jsonify({"success": True})

# --- API SORGU MOTORU ---
@app.route("/api/sorgu", methods=["POST"])
def api_sorgu():
    if 'user_id' not in session and not session.get('admin'): return jsonify({"success": False, "error": "Giriş yapın."}), 401
    req = request.json or {}
    q_type = req.get("type")
    api_key = req.get("api_key", "").strip()
    uid = session.get('user_id', 0); uname = session.get('username', 'admin')
    ip = request.remote_addr or "?"

    try:
        result = None
        
        # 1. OPENARCHIVEX API'LERİ
        if q_type.startswith("oax_"):
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            oax_map = {
                "oax_status": {"url": "https://openarchivex.net/api/v2/status", "method": "GET"},
                "oax_providers": {"url": "https://openarchivex.net/api/v2/providers", "method": "GET"},
                "oax_pricing": {"url": "https://openarchivex.net/api/pricing/api-plans", "method": "GET"},
                "oax_sources": {"url": "https://openarchivex.net/api/v2/sources", "method": "GET"},
                "oax_forum": {"url": "https://openarchivex.net/api/forum/public/overview", "method": "GET"},
                "oax_intelx_search": {"url": "https://openarchivex.net/api/v2/search", "method": "POST"},
                "oax_discord": {"url": "https://openarchivex.net/api/discord-osint/", "method": "POST"},
                "oax_tiktok": {"url": "https://openarchivex.net/api/tiktok-osint/", "method": "POST"},
            }
            if q_type in oax_map:
                target = oax_map[q_type]
                query_param = req.get("query", "") or req.get("username", "") or req.get("param", "")
                if target["method"] == "POST" and not api_key: return jsonify({"success": False, "error": "Bu araç için OpenArchiveX API Key gereklidir."})
                
                if target["method"] == "GET":
                    r = requests.get(target["url"], headers=headers, timeout=20)
                else:
                    r = requests.post(target["url"], headers=headers, json={"query": query_param}, timeout=20)
                
                if r.status_code == 401: return jsonify({"success": False, "error": "Yetkisiz (401). Geçerli bir API Key girin."})
                elif r.status_code != 200: return jsonify({"success": False, "error": f"OpenArchiveX Hatası: HTTP {r.status_code}"})
                result = r.json()

        # 2. DİĞER API'LER
        elif q_type == "plaka_sorgu":
            plaka = req.get('plaka', '').strip().upper()
            if not plaka: return jsonify({"success": False, "error": "Plaka gerekli."})
            r = requests.get(f"https://eokulsorguapi.onrender.com/plaka/api?plaka={plaka}", timeout=15)
            result = r.json()
            
        elif q_type == "adsoyad":
            ad, soyad = req.get('ad', '').strip(), req.get('soyad', '').strip()
            r = requests.get("https://violetpanel.cc/furkanapi/adsoyadapi.php", params={"ad": ad, "soyad": soyad}, timeout=15)
            result = r.json()

        elif q_type == "aile":
            tc = req.get('tc', '').strip()
            r = requests.get("https://violetpanel.cc/furkanapi/ailesorguapi.php", params={"tc": tc}, timeout=15)
            result = r.json()

        elif q_type == "api_whois":
            domain = req.get('domain', '').strip()
            r = requests.get(f"https://rdap.org/domain/{domain}", timeout=15)
            result = r.json() if r.status_code == 200 else {"error": "Bulunamadı"}

        elif q_type == "api_bin":
            bin_num = req.get('bin', '').strip()
            r = requests.get(f"https://lookup.binlist.net/{bin_num}", headers={"Accept-Version": "3"}, timeout=15)
            result = r.json() if r.status_code == 200 else {"error": "Bulunamadı"}

        if result:
            log_query(uid, uname, q_type, str(req)[:100], ip, "basarili")
            return jsonify({"success": True, "data": result})
        else:
            log_query(uid, uname, q_type, str(req)[:100], ip, "basarisiz")
            return jsonify({"success": False, "error": "Sonuç alınamadı veya geçersiz sorgu."})

    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"success": False, "error": "Sunucu veya API bağlantı hatası."})

# --- ADMIN PANELİ (Senin Tasarımına Birebir Uyumlu) ---
@app.route("/admin-panel-x9", methods=["GET", "POST"])
def admin_dashboard():
    if not session.get("admin"):
        error = None
        if request.method == "POST":
            if request.form.get("pass") == ADMIN_PASSWORD:
                session["admin"] = True; return redirect("/admin-panel-x9")
            error = "Hatalı şifre."
        return render_template('admin.html', show_login=True, login_error=error)

    with get_db() as c:
        # admin.html'in beklediği sıralama: id, username, pass, banned, created, q_count, vip
        users = c.execute("SELECT id, username, password, banned, created_at, (SELECT COUNT(*) FROM logs WHERE logs.user_id = users.id), vip FROM users ORDER BY id DESC").fetchall()
        logs = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 500").fetchall()
        tickets = c.execute("SELECT * FROM tickets ORDER BY status ASC, id DESC").fetchall()
        
        total_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_queries = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        vip_users = c.execute("SELECT COUNT(*) FROM users WHERE vip=1").fetchone()[0]
        banned_users = c.execute("SELECT COUNT(*) FROM users WHERE banned=1").fetchone()[0]
        
        success_count = c.execute("SELECT COUNT(*) FROM logs WHERE status='basarili'").fetchone()[0]
        fail_count = c.execute("SELECT COUNT(*) FROM logs WHERE status='basarisiz'").fetchone()[0]
        
        popular_queries = c.execute("SELECT query_type, query_param, COUNT(*) FROM logs WHERE status='basarili' AND query_param != '' GROUP BY query_param ORDER BY 3 DESC LIMIT 10").fetchall()
        
        q_stats = c.execute("SELECT query_type, COUNT(*) FROM logs GROUP BY query_type").fetchall()
        chart_labels = json.dumps([q[0] for q in q_stats]); chart_data = json.dumps([q[1] for q in q_stats])
        daily_labels = json.dumps([]); daily_data = json.dumps([]) 

    return render_template('admin.html', 
        show_login=False, users=users, logs=logs, tickets=tickets, 
        total_users=total_users, total_queries=total_queries, vip_users=vip_users, banned_users=banned_users,
        success_count=success_count, fail_count=fail_count, popular_queries=popular_queries,
        chart_labels=chart_labels, chart_data=chart_data, daily_labels=daily_labels, daily_data=daily_data,
        maint=get_setting("maintenance"), current_bc=get_setting("broadcast"))

@app.route("/admin-toggle-vip/<int:uid>", methods=["POST"])
def admin_toggle_vip(uid):
    if not session.get("admin"): return redirect("/")
    with get_db() as c:
        c.execute("UPDATE users SET vip = CASE WHEN vip=1 THEN 0 ELSE 1 END WHERE id=?", (uid,))
        c.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-ban/<int:uid>", methods=["POST"])
def admin_ban_user(uid):
    if not session.get("admin"): return redirect("/")
    with get_db() as c:
        c.execute("UPDATE users SET banned = CASE WHEN banned=1 THEN 0 ELSE 1 END WHERE id=?", (uid,))
        c.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-delete/<int:uid>", methods=["POST"])
def admin_delete_user(uid):
    if not session.get("admin"): return redirect("/")
    with get_db() as c:
        c.execute("DELETE FROM users WHERE id=?", (uid,))
        c.execute("DELETE FROM logs WHERE user_id=?", (uid,))
        c.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-reset-pass/<int:uid>", methods=["POST"])
def admin_reset_pass(uid):
    if not session.get("admin"): return redirect("/")
    tmp = secrets.token_urlsafe(6)
    with get_db() as c:
        c.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(tmp), uid))
        c.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-history/<int:uid>")
def admin_history(uid):
    if not session.get("admin"): return jsonify({"success": False}), 401
    with get_db() as c:
        logs = c.execute("SELECT timestamp, query_type, query_param, ip, status FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 100", (uid,)).fetchall()
    return jsonify({"success": True, "history": [{"time": l[0], "type": l[1], "param": l[2], "ip": l[3], "status": l[4]} for l in logs]})

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

@app.route("/admin-add-user", methods=["POST"])
def admin_add_user():
    if not session.get("admin"): return redirect("/")
    u, p = request.form.get("username", "").strip().lower(), request.form.get("password", "")
    if len(u) >= 3 and len(p) >= 6:
        try:
            with get_db() as c:
                c.execute("INSERT INTO users (username, password, created_at) VALUES (?,?,?)", (u, generate_password_hash(p), datetime.now().strftime("%Y-%m-%d")))
                c.commit()
        except: pass
    return redirect("/admin-panel-x9")

@app.route("/admin-logout-x9", methods=["POST"])
def admin_logout(): session.pop("admin", None); return redirect("/admin-panel-x9")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))