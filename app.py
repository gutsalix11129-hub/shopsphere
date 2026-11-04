# -*- coding: utf-8 -*-
import os
import sqlite3
import hashlib
import json
import time
import requests
import urllib3
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, session, redirect, abort
from werkzeug.security import generate_password_hash, check_password_hash

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --- GÜVENLİK AYARLARI ---
# Render'da Environment kısmına SECRET_KEY ekleyeceğiz, yoksa rastgele üretir.
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())
# Render'da ADMIN_PASSWORD ekleyeceğiz.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# Çerez güvenliği (XSS ve CSRF koruması)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12)
)

DB_FILE = "siber_karargah.db"
API_BASE = "https://violetpanel.cc/furkanapi"

# --- RATE LIMIT (Brute Force Koruması) ---
# Bir kullanıcı dakikada en fazla 20 sorgu yapabilir.
RATE_LIMIT_DB = {}

def check_rate_limit(user_id):
    now = time.time()
    if user_id not in RATE_LIMIT_DB:
        RATE_LIMIT_DB[user_id] = []
    # Son 60 saniyedeki istekleri tut
    RATE_LIMIT_DB[user_id] = [t for t in RATE_LIMIT_DB[user_id] if now - t < 60]
    if len(RATE_LIMIT_DB[user_id]) >= 20:
        return False
    RATE_LIMIT_DB[user_id].append(now)
    return True

# --- GÜVENLİK BAŞLIKLARI (Header Koruması) ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- VERİTABANI İŞLEMLERİ ---
def init_db():
    with sqlite3.connect(DB_FILE) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT,
            query_type TEXT, query_param TEXT, ip TEXT, timestamp TEXT, status TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        """)
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('maintenance', '0')")
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('broadcast', 'Sisteme hoş geldiniz.')")
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

# --- HTML ŞABLONU (Aynı kalıyor) ---
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>ShopSphere | Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #09090b; --surface: #18181b; --surface-hover: #27272a; --border: #27272a; --text-main: #f4f4f5; --text-muted: #a1a1aa; --primary: #6366f1; --success: #22c55e; --danger: #ef4444; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; -webkit-tap-highlight-color: transparent; outline: none; }
        body { background-color: var(--bg); color: var(--text-main); min-height: 100vh; display: flex; }
        .auth-wrapper { display: flex; align-items: center; justify-content: center; width: 100%; padding: 20px; background: radial-gradient(circle at top right, rgba(99, 102, 241, 0.15), transparent 40%); }
        .auth-card { background: var(--surface); border: 1px solid var(--border); padding: 40px; border-radius: 16px; width: 100%; max-width: 400px; box-shadow: 0 20px 40px rgba(0,0,0,0.4); }
        .auth-card h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; text-align: center; }
        .auth-card p { color: var(--text-muted); font-size: 14px; text-align: center; margin-bottom: 30px; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; font-size: 13px; font-weight: 500; color: var(--text-muted); margin-bottom: 6px; }
        .form-group input { width: 100%; padding: 12px 16px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text-main); font-size: 14px; }
        .btn { width: 100%; padding: 12px; background: var(--primary); color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; }
        .auth-switch { text-align: center; margin-top: 20px; font-size: 13px; color: var(--text-muted); cursor: pointer; }
        .auth-switch span { color: var(--primary); font-weight: 600; }
        .app-layout { display: flex; width: 100%; min-height: 100vh; }
        .sidebar { width: 260px; background: var(--surface); border-right: 1px solid var(--border); position: fixed; height: 100vh; left: 0; top: 0; transform: translateX(-100%); transition: transform 0.3s; overflow-y: auto; z-index: 999; }
        .sidebar.open { transform: translateX(0); }
        .sidebar-header { padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; }
        .sidebar-nav { padding: 15px 10px; }
        .nav-title { font-size: 11px; font-weight: 600; color: var(--text-muted); margin: 15px 10px 8px; }
        .nav-item { display: flex; padding: 10px 12px; border-radius: 8px; color: var(--text-muted); font-size: 14px; cursor: pointer; margin-bottom: 2px; }
        .nav-item:hover, .nav-item.active { background: var(--surface-hover); color: var(--primary); }
        .main-content { flex: 1; display: flex; flex-direction: column; min-width: 0; }
        .topbar { height: 64px; background: var(--surface); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; padding: 0 20px; align-items: center; }
        .hamburger { width: 24px; height: 20px; cursor: pointer; display: flex; flex-direction: column; justify-content: space-around; }
        .hamburger span { width: 100%; height: 2px; background: var(--text-main); }
        .content-area { padding: 24px; max-width: 1000px; margin: 0 auto; width: 100%; display: flex; flex-direction: column; gap: 24px; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; }
        .card-header { display: flex; justify-content: space-between; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 16px; }
        .input-wrapper { margin-bottom: 16px; }
        .input-wrapper input { width: 100%; padding: 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; color: white; }
        .data-card { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 10px; }
        .data-header { background: var(--surface-hover); padding: 12px; font-size: 13px; border-bottom: 1px solid var(--border); }
        .data-grid { display: grid; grid-template-columns: 1fr; gap: 1px; background: var(--border); }
        .data-item { background: var(--surface); padding: 12px; }
        .data-label { font-size: 11px; color: var(--text-muted); }
        .data-val { font-family: 'JetBrains Mono', monospace; font-size: 14px; word-break: break-all; cursor: pointer; }
        .toast { position: fixed; bottom: 24px; right: 24px; background: var(--surface); padding: 12px; border-radius: 8px; transform: translateY(150%); transition: 0.3s; z-index: 2000; }
        .toast.show { transform: translateY(0); }
        .empty-state { text-align: center; color: var(--text-muted); padding: 40px; }
        .spinner { width: 30px; height: 30px; border: 3px solid var(--border); border-top-color: var(--primary); border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @media (min-width: 992px) { .sidebar { position: static; transform: none; } .hamburger { display: none; } .data-grid { grid-template-columns: 1fr 1fr; } }
    </style>
</head>
<body>
    <div class="toast" id="toast"></div>
    <div id="screen-auth" class="auth-wrapper">
        <div class="auth-card">
            <h1>ShopSphere</h1>
            <p>Gelişmiş OSINT & İstihbarat Paneli</p>
            <div id="form-login">
                <div class="form-group"><label>Kullanıcı Adı</label><input type="text" id="l_user"></div>
                <div class="form-group"><label>Şifre</label><input type="password" id="l_pass"></div>
                <button class="btn" onclick="doLogin()">Giriş Yap</button>
                <div class="auth-switch" onclick="toggleAuth()">Hesabınız yok mu? <span>Kayıt Olun</span></div>
            </div>
            <div id="form-register" style="display:none;">
                <div class="form-group"><label>Kullanıcı Adı</label><input type="text" id="r_user"></div>
                <div class="form-group"><label>Şifre</label><input type="password" id="r_pass"></div>
                <button class="btn" onclick="doRegister()">Kayıt Ol</button>
                <div class="auth-switch" onclick="toggleAuth()">Giriş yapmak için tıklayın</div>
            </div>
        </div>
    </div>
    <div id="screen-app" class="app-layout" style="display:none;">
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header"><h2>ShopSphere</h2><button class="btn" style="width:auto; padding:5px 10px;" onclick="doLogout()">Çıkış</button></div>
            <div class="sidebar-nav">
                <div class="nav-title">Sorgular</div>
                <div class="nav-item active" onclick="setForm('adsoyad', this)">👤 Ad Soyad</div>
                <div class="nav-item" onclick="setForm('aile', this)">👨‍👩‍👧‍👦 Aile</div>
                <div class="nav-item" onclick="setForm('tcgsm', this)">📱 TC → GSM</div>
                <div class="nav-item" onclick="setForm('gsmtc', this)">📞 GSM → TC</div>
                <div class="nav-title">OSINT</div>
                <div class="nav-item" onclick="setForm('osint_ip', this)">🌐 IP Sorgu</div>
                <div class="nav-item" onclick="setForm('osint_domain', this)">🔗 DNS Sorgu</div>
                <div class="nav-item" onclick="setForm('osint_hash', this)">🧬 Hash</div>
            </div>
        </aside>
        <main class="main-content">
            <header class="topbar">
                <div class="hamburger" onclick="document.getElementById('sidebar').classList.toggle('open')"><span></span><span></span><span></span></div>
                <div id="bc-text" style="font-size:13px; color:var(--primary);"></div>
                <div id="uname" style="font-size:13px;"></div>
            </header>
            <div class="content-area">
                <div class="card">
                    <div class="card-header"><div class="card-title" id="qTitle">Sorgu</div></div>
                    <div id="inputs"></div>
                    <button class="btn" id="submitBtn" onclick="runQuery()">Sorgula</button>
                </div>
                <div class="card">
                    <div class="card-header"><div class="card-title">Sonuçlar</div></div>
                    <div id="output"><div class="empty-state">Formu doldurun.</div></div>
                </div>
            </div>
        </main>
    </div>
    <script>
        function toast(m, t='success') { let x=document.getElementById('toast'); x.innerText=m; x.className='toast show '+t; setTimeout(()=>x.className='toast',3000); }
        function toggleAuth() { let a=document.getElementById('form-login'), b=document.getElementById('form-register'); a.style.display = a.style.display==='none'?'block':'none'; b.style.display = b.style.display==='none'?'block':'none'; }
        async function doLogin() { let r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('l_user').value,password:document.getElementById('l_pass').value})}).then(x=>x.json()); if(r.success) initApp(); else toast(r.error,'error'); }
        async function doRegister() { let r=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('r_user').value,password:document.getElementById('r_pass').value})}).then(x=>x.json()); if(r.success) { toast('Kayıt başarılı'); toggleAuth(); } else toast(r.error,'error'); }
        function doLogout() { fetch('/api/logout').then(()=>location.reload()); }
        async function initApp() { let r=await fetch('/api/check_auth').then(x=>x.json()); if(!r.success) return; document.getElementById('screen-auth').style.display='none'; document.getElementById('screen-app').style.display='flex'; document.getElementById('uname').innerText=r.username; setForm('adsoyad',document.querySelector('.nav-item')); setInterval(async()=>{let b=await fetch('/api/get_broadcast').then(x=>x.json()); if(b.success) document.getElementById('bc-text').innerText=b.broadcast;},10000); }
        let currentType='adsoyad';
        const MENU = { "adsoyad":{title:"Ad Soyad",fields:[{id:'ad',label:'Ad'},{id:'soyad',label:'Soyad'}]}, "aile":{title:"Aile",fields:[{id:'tc',label:'TC'}]}, "tcgsm":{title:"TC->GSM",fields:[{id:'tc',label:'TC'}]}, "gsmtc":{title:"GSM->TC",fields:[{id:'gsm',label:'GSM'}]}, "osint_ip":{title:"IP",fields:[{id:'ip',label:'IP'}]}, "osint_domain":{title:"DNS",fields:[{id:'domain',label:'Domain'}]}, "osint_hash":{title:"Hash",fields:[{id:'text',label:'Metin'}]} };
        function setForm(t, el) { currentType=t; document.querySelectorAll('.nav-item').forEach(i=>i.classList.remove('active')); el.classList.add('active'); document.getElementById('qTitle').innerText=MENU[t].title; document.getElementById('inputs').innerHTML=MENU[t].fields.map(f=>`<div class="input-wrapper"><label>${f.label}</label><input type="text" id="${f.id}"></div>`).join(''); document.getElementById('output').innerHTML='<div class="empty-state">Bekleniyor...</div>'; }
        async function runQuery() { let p={type:currentType}; for(let f of MENU[currentType].fields) { let v=document.getElementById(f.id).value; if(!v) return toast('Boş bırakma','error'); p[f.id]=v; } document.getElementById('submitBtn').disabled=true; document.getElementById('output').innerHTML='<div class="spinner"></div>'; try { let r=await fetch('/api/sorgu',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)}).then(x=>x.json()); renderResult(r); } catch(e) { renderResult({success:false,error:'Hata'}); } document.getElementById('submitBtn').disabled=false; }
        function esc(s) { return String(s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
        function renderResult(r) { let o=document.getElementById('output'); if(!r.success) { o.innerHTML=`<div class="empty-state" style="color:red">${esc(r.error)}</div>`; return; } let items=Array.isArray(r.data)?r.data:[r.data]; o.innerHTML=items.map((i,x)=>`<div class="data-card"><div class="data-header">Kayıt #${x+1}</div><div class="data-grid">${Object.entries(i).map(([k,v])=>v?`<div class="data-item"><div class="data-label">${k.toUpperCase()}</div><div class="data-val">${esc(v)}</div></div>`:'').join('')}</div></div>`).join(''); }
        initApp();
    </script>
</body>
</html>
"""

@app.route("/")
def home(): return render_template_string(HTML_TEMPLATE)

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
    except sqlite3.IntegrityError: return jsonify({"success": False, "error": "Bu kullanıcı adı alınmış."})
    except: return jsonify({"success": False, "error": "Sunucu hatası."})

@app.route("/api/login", methods=["POST"])
def api_login():
    req = request.json or {}
    u, p = req.get("username","").strip(), req.get("password","").strip()
    with sqlite3.connect(DB_FILE) as c:
        r = c.execute("SELECT id, username, password FROM users WHERE username=?", (u,)).fetchone()
    if r and check_password_hash(r[2], p):
        session.permanent = True
        session['user_id'] = r[0]; session['username'] = r[1]
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Hatalı giriş."})

@app.route("/api/logout")
def api_logout(): session.clear(); return jsonify({"success": True})

@app.route("/api/check_auth")
def api_check_auth():
    if 'user_id' in session: return jsonify({"success": True, "username": session['username']})
    return jsonify({"success": False})

@app.route("/api/get_broadcast")
def api_get_broadcast(): return jsonify({"success": True, "broadcast": get_setting("broadcast")})

@app.route("/api/sorgu", methods=["POST"])
def api_sorgu():
    if get_setting("maintenance") == "1": return jsonify({"success": False, "error": "Sistem bakımda."})
    if 'user_id' not in session: return jsonify({"success": False, "error": "Giriş yapmalısınız."})
    
    # BRUTE FORCE KORUMASI
    if not check_rate_limit(session['user_id']):
        return jsonify({"success": False, "error": "Çok fazla istek attınız. Lütfen 1 dakika bekleyin."})

    req = request.json or {}
    q_type = req.get("type")
    uid, uname, ip = session['user_id'], session['username'], request.remote_addr

    try:
        if q_type == "osint_ip":
            return jsonify({"success": True, "data": requests.get(f"http://ip-api.com/json/{req.get('ip')}", timeout=10).json()})
        elif q_type == "osint_domain":
            return jsonify({"success": True, "data": requests.get(f"https://dns.google/resolve?name={req.get('domain')}&type=A", timeout=10).json()})
        elif q_type == "osint_hash":
            txt = req.get('text').encode()
            return jsonify({"success": True, "data": {"MD5": hashlib.md5(txt).hexdigest(), "SHA1": hashlib.sha1(txt).hexdigest(), "SHA256": hashlib.sha256(txt).hexdigest()}})

        API_MAP = {
            "adsoyad": {"url": f"{API_BASE}/adsoyadapi.php", "params": {"ad":"ad","soyad":"soyad"}},
            "aile": {"url": f"{API_BASE}/ailesorguapi.php", "params": {"tc":"tc"}},
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
        return jsonify({"success": False, "error": "Sunucu hatası."})

@app.route("/gizli-admin-narcissist", methods=["GET", "POST"])
def secret_login():
    if request.method == "POST":
        if request.form.get("pass") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/gizli-dashboard-narcissist")
        return "Hatalı Şifre"
    return """
    <body style="background:#09090b;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;">
        <form method="POST" style="background:#18181b;padding:40px;border-radius:12px;text-align:center;border:1px solid #27272a;">
            <h2 style="margin-bottom:20px;">Admin Girişi</h2>
            <input type="password" name="pass" placeholder="Şifre" style="padding:12px;border-radius:8px;border:1px solid #27272a;background:#09090b;color:#fff;width:100%;margin-bottom:15px;">
            <button type="submit" style="padding:12px;background:#6366f1;color:#fff;border:none;border-radius:8px;width:100%;font-weight:bold;cursor:pointer;">Giriş</button>
        </form>
    </body>
    """

@app.route("/gizli-dashboard-narcissist")
def admin_dashboard():
    if not session.get("admin"): return redirect("/gizli-admin-narcissist")
    with sqlite3.connect(DB_FILE) as c:
        logs = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 50").fetchall()
        total_queries = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        total_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return f"""
    <body style="background:#09090b;color:#fff;padding:20px;font-family:sans-serif;">
        <h1>Yönetim Paneli</h1>
        <p>Toplam Sorgu: {total_queries} | Kullanıcı: {total_users}</p>
        <a href="/gizli-cikis-narcissist" style="color:red;">Çıkış Yap</a>
        <hr style="border-color:#333; margin:20px 0;">
        <h3>Son Sorgular</h3>
        <table style="width:100%; text-align:left; border-collapse:collapse;">
            <tr style="background:#222;"><th>Tarih</th><th>Kullanıcı</th><th>Tip</th><th>Parametre</th></tr>
            {"".join([f"<tr style='border-bottom:1px solid #333;'><td>{l[6]}</td><td>{l[2]}</td><td>{l[3]}</td><td>{l[4]}</td></tr>" for l in logs])}
        </table>
    </body>
    """

@app.route("/gizli-bakim-degistir", methods=["POST"])
def admin_toggle_maint():
    if not session.get("admin"): return redirect("/")
    set_setting("maintenance", "0" if get_setting("maintenance") == "1" else "1")
    return redirect("/gizli-dashboard-narcissist")

@app.route("/gizli-duyuru-gonder", methods=["POST"])
def admin_broadcast():
    if not session.get("admin"): return redirect("/")
    set_setting("broadcast", request.form.get("bc_text", "").strip())
    return redirect("/gizli-dashboard-narcissist")

@app.route("/gizli-cikis-narcissist")
def admin_logout():
    session.pop("admin", None)
    return redirect("/")