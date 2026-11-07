# -*- coding: utf-8 -*-
import os
import json
import time
import secrets
import logging
import traceback
from datetime import datetime, timezone, timedelta

import requests
from cachetools import TTLCache
from flask import Flask, request, jsonify, render_template, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import create_engine, Column, Integer, String, Text, func
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool

# --- YAPILANDIRMA ---
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', handlers=[logging.FileHandler("app.log", encoding="utf-8"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# --- VERİTABANI ---
DB_DIR = "/var/data" if os.path.exists("/var/data") else "/tmp"
if os.name == 'nt': DB_DIR = "."
DB_FILE = os.path.join(DB_DIR, "siber_karargah.db")
engine = create_engine(f"sqlite:///{DB_FILE}", connect_args={"check_same_thread": False}, poolclass=StaticPool)
db_session = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(32), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    banned = Column(Integer, default=0)
    vip = Column(Integer, default=0)
    created_at = Column(String(20))
    avatar = Column(Text)

class Log(Base):
    __tablename__ = 'logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, index=True)
    username = Column(String(32))
    query_type = Column(String(50))
    query_param = Column(Text)
    ip = Column(String(45))
    timestamp = Column(String(30))
    status = Column(String(20))

class Setting(Base):
    __tablename__ = 'settings'
    key = Column(String(50), primary_key=True)
    value = Column(Text)

class Ticket(Base):
    __tablename__ = 'tickets'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer)
    username = Column(String(32))
    subject = Column(String(100))
    message = Column(Text)
    reply = Column(Text)
    status = Column(String(20), default='open')
    created_at = Column(String(30))
    replied_at = Column(String(30))

Base.metadata.create_all(engine)
cache = TTLCache(maxsize=1000, ttl=300)

def init_db():
    db = sessionmaker(bind=engine)()
    if not db.query(Setting).filter_by(key='maintenance').first(): db.add(Setting(key='maintenance', value='0'))
    if not db.query(Setting).filter_by(key='broadcast').first(): db.add(Setting(key='broadcast', value='Sistemimize hoş geldiniz!'))
    db.commit(); db.close()

init_db()

def get_setting(k):
    s = db_session.query(Setting).filter_by(key=k).first()
    return s.value if s else ""

def set_setting(k, v):
    s = db_session.query(Setting).filter_by(key=k).first()
    if s: s.value = v
    else: db_session.add(Setting(key=k, value=v))
    db_session.commit()

def log_query(uid, uname, q_type, param, ip, status):
    try:
        log = Log(user_id=uid, username=uname, query_type=q_type, query_param=param, ip=ip, timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), status=status)
        db_session.add(log); db_session.commit()
    except Exception as e: logger.error(f"Log hatasi: {e}")

def csrf_token():
    if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.teardown_appcontext
def remove_session(exception=None): db_session.remove()

# --- ROTALAR ---
@app.route("/")
def home():
    if 'user_id' not in session: return redirect('/login')
    user = db_session.query(User).get(session['user_id'])
    if not user: session.clear(); return redirect('/login')
    return render_template('index.html', username=user.username, avatar=user.avatar or f"https://api.dicebear.com/7.x/bottts/svg?seed={user.username}")

@app.route("/login")
def login_page():
    if 'user_id' in session: return redirect('/')
    return render_template('login.html')

@app.route("/api/login", methods=["POST"])
def api_login():
    req = request.json or {}
    u, p = (req.get("username") or "").strip().lower(), req.get("password") or ""
    user = db_session.query(User).filter_by(username=u).first()
    if user and check_password_hash(user.password, p):
        if user.banned == 1: return jsonify({"success": False, "error": "Hesap askıya alınmış."})
        session.permanent = True; session['user_id'] = user.id; session['username'] = user.username
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Kullanıcı adı veya şifre hatalı."})

@app.route("/api/register", methods=["POST"])
def api_register():
    req = request.json or {}
    u, p = (req.get("username") or "").strip().lower(), (req.get("password") or "").strip()
    if len(u) < 3 or len(p) < 6: return jsonify({"success": False, "error": "Geçersiz veri."})
    if db_session.query(User).filter_by(username=u).first(): return jsonify({"success": False, "error": "Kullanıcı adı alınmış."})
    db_session.add(User(username=u, password=generate_password_hash(p), created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d")))
    db_session.commit()
    return jsonify({"success": True})

@app.route("/api/logout", methods=["POST"])
def api_logout(): session.clear(); return jsonify({"success": True})

@app.route("/api/sorgu", methods=["POST"])
def api_sorgu():
    if 'user_id' not in session and not session.get('admin'): return jsonify({"success": False, "error": "Giriş yapın."}), 401
    req = request.json or {}; q_type = req.get("type"); ip = request.remote_addr or "?"
    uid = session.get('user_id', 0); uname = session.get('username', 'admin')
    
    cache_key = f"{q_type}_{str(req)}"
    if cache_key in cache: return jsonify({"success": True, "data": cache[cache_key]})

    try:
        result = None
        if q_type == "plaka_sorgu":
            r = requests.get(f"https://eokulsorguapi.onrender.com/plaka/api?plaka={req.get('plaka')}", timeout=15)
            result = r.json()
        elif q_type == "adsoyad":
            r = requests.get("https://violetpanel.cc/furkanapi/adsoyadapi.php", params={"ad": req.get('ad'), "soyad": req.get('soyad')}, timeout=15)
            result = r.json()
        elif q_type == "aile":
            r = requests.get("https://violetpanel.cc/furkanapi/ailesorguapi.php", params={"tc": req.get('tc')}, timeout=15)
            result = r.json()
        elif q_type == "api_whois":
            r = requests.get(f"https://rdap.org/domain/{req.get('domain')}", timeout=15)
            result = r.json() if r.status_code == 200 else {"error": "Bulunamadı"}
        elif q_type == "api_bin":
            r = requests.get(f"https://lookup.binlist.net/{req.get('bin')}", headers={"Accept-Version": "3"}, timeout=15)
            result = r.json() if r.status_code == 200 else {"error": "Bulunamadı"}
        else: return jsonify({"success": False, "error": "Geçersiz sorgu."})

        if result:
            log_query(uid, uname, q_type, str(req), ip, "basarili")
            cache[cache_key] = result
            return jsonify({"success": True, "data": result})
        return jsonify({"success": False, "error": "Sonuç alınamadı."})
    except Exception as e:
        logger.error(f"Sorgu Hatasi: {traceback.format_exc()}")
        return jsonify({"success": False, "error": "Sunucu hatası."})

# --- ADMIN PANELİ ---
@app.route("/admin-panel-x9", methods=["GET", "POST"])
def admin_dashboard():
    if not session.get("admin"):
        error = None
        if request.method == "POST":
            if secrets.compare_digest(str(request.form.get("pass", "")), str(ADMIN_PASSWORD)):
                session["admin"] = True; session["admin_since"] = time.time(); return redirect("/admin-panel-x9")
            error = "Hatalı şifre."
        return render_template('admin.html', show_login=True, login_error=error)

    if time.time() - session.get("admin_since", 0) > 3600:
        session.pop("admin", None); return redirect("/admin-panel-x9")

    temp_passes = session.pop("_temp_passes", {})
    
    # Kullanıcılar (Senin admin.html dosyanın beklediği tuple formatında)
    users = db_session.query(
        User.id, User.username, User.password, User.banned, 
        User.created_at, func.count(Log.id).label('q_count'), User.vip
    ).outerjoin(Log, User.id == Log.user_id).group_by(User.id).order_by(User.id.desc()).all()
    
    tickets = db_session.query(Ticket).order_by(Ticket.status.asc(), Ticket.id.desc()).all()
    logs = db_session.query(Log).order_by(Log.id.desc()).limit(500).all()
    
    total_users = db_session.query(func.count(User.id)).scalar()
    total_queries = db_session.query(func.count(Log.id)).scalar()
    vip_users = db_session.query(func.count(User.id)).filter_by(vip=1).scalar()
    banned_users = db_session.query(func.count(User.id)).filter_by(banned=1).scalar()
    
    popular_queries = db_session.query(Log.query_type, Log.query_param, func.count(Log.id)).filter(Log.status == 'basarili', Log.query_param != '').group_by(Log.query_param).order_by(func.count(Log.id).desc()).limit(10).all()
    success_count = db_session.query(func.count(Log.id)).filter_by(status='basarili').scalar()
    fail_count = db_session.query(func.count(Log.id)).filter_by(status='basarisiz').scalar()

    q_stats = db_session.query(Log.query_type, func.count(Log.id)).group_by(Log.query_type).all()
    chart_labels = json.dumps([q[0] for q in q_stats]); chart_data = json.dumps([q[1] for q in q_stats])
    dates = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    daily_counts = [db_session.query(func.count(Log.id)).filter(Log.timestamp.like(f"{d}%")).scalar() for d in dates]
    daily_labels = json.dumps(dates); daily_data = json.dumps(daily_counts)

    return render_template('admin.html', 
        show_login=False, login_error=None, temp_passes=temp_passes,
        users=users, tickets=tickets, logs=logs, popular_queries=popular_queries,
        total_users=total_users, total_queries=total_queries, vip_users=vip_users, banned_users=banned_users,
        success_count=success_count, fail_count=fail_count,
        chart_labels=chart_labels, chart_data=chart_data, daily_labels=daily_labels, daily_data=daily_data,
        maint=get_setting("maintenance"), current_bc=get_setting("broadcast")
    )

@app.route("/admin-add-user", methods=["POST"])
def admin_add_user():
    if not session.get("admin"): return redirect("/")
    u, p = request.form.get("username", "").strip().lower(), request.form.get("password", "")
    if len(u) >= 3 and len(p) >= 6 and not db_session.query(User).filter_by(username=u).first():
        db_session.add(User(username=u, password=generate_password_hash(p), created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d")))
        db_session.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-reply-ticket/<int:tid>", methods=["POST"])
def admin_reply_ticket(tid):
    if not session.get("admin"): return redirect("/")
    reply = request.form.get("reply", "").strip()
    if reply:
        t = db_session.query(Ticket).get(tid)
        if t: t.reply = reply; t.status = 'closed'; t.replied_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"); db_session.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-reset-pass/<int:uid>", methods=["POST"])
def admin_reset_pass(uid):
    if not session.get("admin"): return redirect("/")
    tmp = secrets.token_urlsafe(6)
    user = db_session.query(User).get(uid)
    if user:
        user.password = generate_password_hash(tmp); db_session.commit()
        tp = session.get("_temp_passes", {}); tp[str(uid)] = tmp; session["_temp_passes"] = dict(list(tp.items())[-5:])
    return redirect("/admin-panel-x9")

@app.route("/admin-ban/<int:uid>", methods=["POST"])
def admin_ban_user(uid):
    if not session.get("admin"): return redirect("/")
    user = db_session.query(User).get(uid)
    if user: user.banned = 0 if user.banned == 1 else 1; db_session.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-toggle-vip/<int:uid>", methods=["POST"])
def admin_toggle_vip(uid):
    if not session.get("admin"): return redirect("/")
    user = db_session.query(User).get(uid)
    if user: user.vip = 0 if user.vip == 1 else 1; db_session.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-delete/<int:uid>", methods=["POST"])
def admin_delete_user(uid):
    if not session.get("admin"): return redirect("/")
    user = db_session.query(User).get(uid)
    if user: db_session.query(Log).filter_by(user_id=uid).delete(); db_session.delete(user); db_session.commit()
    return redirect("/admin-panel-x9")

@app.route("/admin-history/<int:uid>")
def admin_history(uid):
    if not session.get("admin"): return jsonify({"success": False}), 401
    logs = db_session.query(Log).filter_by(user_id=uid).order_by(Log.id.desc()).limit(200).all()
    return jsonify({"success": True, "history": [{"time": l.timestamp, "type": l.query_type, "param": l.query_param, "ip": l.ip, "status": l.status} for l in logs]})

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

@app.route("/admin-logout-x9", methods=["POST"])
def admin_logout(): session.pop("admin", None); return redirect("/admin-panel-x9")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)