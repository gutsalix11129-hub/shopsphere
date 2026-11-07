# -*- coding: utf-8 -*-
import os
import re
import json
import time
import hashlib
import secrets
import logging
import traceback
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor

import httpx
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

# Gelişmiş Loglama
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', handlers=[logging.FileHandler("app.log", encoding="utf-8"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# --- VERİTABANI (SQLAlchemy) ---
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

Base.metadata.create_all(engine)

# --- ÖNBELLEK ---
cache = TTLCache(maxsize=1000, ttl=300)
executor = ThreadPoolExecutor(max_workers=10)

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
        db_session.add(log)
        db_session.commit()
    except Exception as e:
        logger.error(f"Log kayit hatasi: {e}")

def csrf_token():
    if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.teardown_appcontext
def remove_session(exception=None):
    db_session.remove()

# --- ROTALAR ---
@app.route("/")
def home():
    if 'user_id' not in session: return redirect('/login')
    user = db_session.query(User).get(session['user_id'])
    if not user: session.clear(); return redirect('/login')
    
    total_users = db_session.query(func.count(User.id)).scalar()
    total_queries = db_session.query(func.count(Log.id)).scalar()
    user_queries = db_session.query(func.count(Log.id)).filter_by(user_id=user.id).scalar()
    avatar = user.avatar if user.avatar else f"https://api.dicebear.com/7.x/bottts/svg?seed={user.username}"
    return render_template('index.html', total_users=total_users, total_queries=total_queries, user_queries=user_queries, username=user.username, created=user.created_at, avatar=avatar, is_vip=(user.vip==1))

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
    u, p, avatar = (req.get("username") or "").strip().lower(), (req.get("password") or "").strip(), (req.get("avatar") or "").strip()
    if len(u) < 3 or len(p) < 6: return jsonify({"success": False, "error": "Geçersiz veri."})
    if db_session.query(User).filter_by(username=u).first(): return jsonify({"success": False, "error": "Kullanıcı adı alınmış."})
    db_session.add(User(username=u, password=generate_password_hash(p), created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d"), avatar=avatar))
    db_session.commit()
    return jsonify({"success": True})

@app.route("/api/logout", methods=["POST"])
def api_logout(): session.clear(); return jsonify({"success": True})

@app.route("/api/sorgu", methods=["POST"])
def api_sorgu():
    if 'user_id' not in session: return jsonify({"success": False, "error": "Giriş yapın."}), 401
    
    req = request.json or {}
    q_type = req.get("type")
    api_key = req.get("api_key", "").strip() # Kullanıcıdan gelen API Key
    uid, uname = session['user_id'], session['username']
    ip = request.remote_addr or "?"
    
    # Önbellek kontrolü
    cache_key = f"{q_type}_{str(req)}"
    if cache_key in cache: return jsonify({"success": True, "data": cache[cache_key]})

    try:
        result = None
        
        # --- OPENARCHIVEX API ENTEGRASYONU ---
        if q_type.startswith("oax_"):
            # 401 hatası verenler için API Key zorunlu
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
                "oax_roblox": {"url": "https://openarchivex.net/api/roblox-osint/", "method": "POST"},
                "oax_breach": {"url": "https://openarchivex.net/v3/openarchive-breach", "method": "GET"},
            }
            
            if q_type not in oax_map: return jsonify({"success": False, "error": "Geçersiz OpenArchiveX aracı."})
            
            target = oax_map[q_type]
            query_param = req.get("query", "") or req.get("domain", "") or req.get("username", "")
            
            # API Key kontrolü (Gerekli olanlar için)
            if target["method"] == "POST" and not api_key:
                return jsonify({"success": False, "error": "Bu araç için OpenArchiveX API Key gereklidir."})
            
            with httpx.Client(timeout=20) as client:
                if target["method"] == "GET":
                    r = client.get(target["url"], headers=headers)
                else:
                    r = client.post(target["url"], headers=headers, json={"query": query_param})
                
                if r.status_code == 401:
                    return jsonify({"success": False, "error": "Yetkisiz (401). Lütfen geçerli bir OpenArchiveX API Key girin."})
                elif r.status_code != 200:
                    return jsonify({"success": False, "error": f"OpenArchiveX Hatası: HTTP {r.status_code}"})
                
                try: result = r.json()
                except: result = r.text

        # --- DİĞER ESKİ API'LER ---
        elif q_type == "plaka_sorgu":
            with httpx.Client(timeout=15) as client:
                r = client.get(f"https://eokulsorguapi.onrender.com/plaka/api?plaka={req.get('plaka')}")
                result = r.json()
        else:
            return jsonify({"success": False, "error": "Bilinmeyen sorgu tipi."})

        if result:
            log_query(uid, uname, q_type, str(req), ip, "basarili")
            cache[cache_key] = result
            return jsonify({"success": True, "data": result})
        else:
            return jsonify({"success": False, "error": "Sonuç alınamadı."})
            
    except Exception as e:
        logger.error(f"Sorgu Hatasi ({q_type}): {traceback.format_exc()}")
        return jsonify({"success": False, "error": "Sunucu veya bağlantı hatası."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)