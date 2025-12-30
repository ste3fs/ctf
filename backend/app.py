# -*- coding: utf-8 -*-
import os
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import Flask, jsonify, request, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

from sqlalchemy import func

# ============ 路径与基础配置 ============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

DB_PATH = os.path.join(INSTANCE_DIR, "local_ctf.db")
DB_URI = "sqlite:///" + DB_PATH.replace("\\", "/")

STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(
    __name__,
    static_folder=STATIC_DIR,
    static_url_path="/static",
    instance_path=INSTANCE_DIR,
)

app.config.update(
    SQLALCHEMY_DATABASE_URI=DB_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY", "dev-only-change-me-in-production"),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=24),
)

CORS(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)

INVITATION_CODES = {
    "SDHG2026CTF": {"max_uses": 65, "type": "student", "label": "学生邀请码"},
    "TEACHER01": {"max_uses": 5, "type": "teacher", "label": "教师邀请码"},
}

# ============ 数据模型 ============
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    real_name = db.Column(db.String(64))
    student_id = db.Column(db.String(64))
    class_info = db.Column(db.String(128))
    invitation_code = db.Column(db.String(64))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    status = db.Column(db.String(16), default="pending", nullable=False)  # pending/approved/rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    solves = db.relationship("Solve", backref="user", lazy=True, cascade="all, delete-orphan")
    submissions = db.relationship("Submission", backref="user", lazy=True, cascade="all, delete-orphan")


class Challenge(db.Model):
    __tablename__ = "challenge"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(32), nullable=False, index=True)
    points = db.Column(db.Integer, nullable=False, default=100)
    flag = db.Column(db.String(256), nullable=False)
    file_path = db.Column(db.String(256))  # 例如 "misc1.zip"（位于 backend/static/misc1.zip）
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    solves = db.relationship("Solve", backref="challenge", lazy=True, cascade="all, delete-orphan")
    submissions = db.relationship("Submission", backref="challenge", lazy=True, cascade="all, delete-orphan")


class Solve(db.Model):
    __tablename__ = "solve"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenge.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "challenge_id", name="uniq_user_challenge_solve"),)


class Submission(db.Model):
    __tablename__ = "submission"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenge.id"), nullable=False, index=True)
    submitted_flag = db.Column(db.String(256), nullable=False, default="")
    is_correct = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


# ============ 工具函数 ============
def json_response(data=None, message="", error=None, status=200):
    payload = {"success": error is None, "message": message}
    if error is not None:
        payload["error"] = error
    if data is not None:
        payload["data"] = data
    return jsonify(payload), status


def get_current_user():
    """获取当前登录用户（兼容 @jwt_required 与手动校验）"""
    try:
        verify_jwt_in_request()
        uid = get_jwt_identity()
        if uid is None:
            return None
        try:
            uid = int(uid)
        except Exception:
            return None
        return User.query.get(uid)
    except Exception:
        return None


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = get_current_user()
        if not u:
            return json_response(error="未登录", status=401)
        if not u.is_admin:
            return json_response(error="需要管理员权限", status=403)
        return fn(u, *args, **kwargs)
    return wrapper


def calc_user_score(uid: int) -> int:
    """用户总分 = 已解题 points 之和"""
    total = (
        db.session.query(func.coalesce(func.sum(Challenge.points), 0))
        .join(Solve, Solve.challenge_id == Challenge.id)
        .filter(Solve.user_id == uid)
        .scalar()
    )
    return int(total or 0)


def ensure_frontend_dir():
    """
    兼容你的仓库目录结构：
    - 有的项目把 html 放 backend/ 里
    - 有的放 ../frontend 或 ../frotend
    """
    cand = [
        os.path.join(os.path.dirname(BASE_DIR), "frontend"),
        os.path.join(os.path.dirname(BASE_DIR), "frotend"),
        BASE_DIR,
    ]
    for d in cand:
        if os.path.isdir(d):
            return d
    return BASE_DIR


FRONTEND_DIR = ensure_frontend_dir()


# ============ 前端页面路由 ============
@app.route("/")
def page_root():
    # 优先打开 login.html（若不存在就退回 admin.html）
    for name in ("login.html", "admin.html", "index.html"):
        p = os.path.join(FRONTEND_DIR, name)
        if os.path.isfile(p):
            return send_from_directory(FRONTEND_DIR, name)
    abort(404)


@app.route("/<path:filename>")
def page_files(filename):
    if filename.startswith("api/"):
        abort(404)

    # 允许访问前端目录文件
    p = os.path.join(FRONTEND_DIR, filename)
    if os.path.isfile(p):
        return send_from_directory(FRONTEND_DIR, filename)

    # 允许访问 backend 目录下文件（兼容你旧结构）
    p2 = os.path.join(BASE_DIR, filename)
    if os.path.isfile(p2):
        return send_from_directory(BASE_DIR, filename)

    abort(404)


# ============ ✅ 下载接口：解决 404 ============
@app.route("/download/<path:fname>")
def download_file(fname):
    full = os.path.join(STATIC_DIR, fname)
    if not os.path.isfile(full):
        abort(404)
    return send_from_directory(STATIC_DIR, fname, as_attachment=True)


# ============ Auth API ============
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")

    if not username or not password:
        return json_response(error="请输入用户名和密码", status=400)

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return json_response(error="用户名或密码错误", status=401)

    if user.status != "approved":
        return json_response(error=f"账号状态：{user.status}（需管理员审核通过后才能登录）", status=403)

    token = create_access_token(identity=str(user.id))

    return jsonify({
        "success": True,
        "message": "登录成功",
        "data": {
            "token": token,
            "user_id": user.id,
            "username": user.username,
            "is_admin": bool(user.is_admin),
        }
    })


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")
    real_name = (data.get("real_name") or "").strip()
    student_id = (data.get("student_id") or "").strip()
    class_info = (data.get("class_info") or "").strip()
    invitation_code = (data.get("invitation_code") or "").strip()

    if not username or not password:
        return json_response(error="用户名和密码不能为空", status=400)
    if len(username) < 3:
        return json_response(error="用户名至少 3 位", status=400)
    if len(password) < 6:
        return json_response(error="密码至少 6 位", status=400)

    if User.query.filter_by(username=username).first():
        return json_response(error="用户名已存在", status=400)

    meta = INVITATION_CODES.get(invitation_code)
    if not meta:
        return json_response(error="邀请码无效", status=400)

    used = User.query.filter_by(invitation_code=invitation_code).count()
    max_uses = int(meta.get("max_uses") or 0)
    if max_uses > 0 and used >= max_uses:
        return json_response(error="邀请码已用尽", status=400)

    is_teacher = (meta.get("type") == "teacher")

    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        real_name=real_name or None,
        student_id=student_id or None,
        class_info=class_info or None,
        invitation_code=invitation_code,
        is_admin=True if is_teacher else False,
        status="approved" if is_teacher else "pending",
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "注册成功（教师/管理员账号已自动激活）" if is_teacher else "注册申请已提交，等待管理员审核",
        "data": {"status": user.status, "is_admin": bool(user.is_admin)}
    })


@app.route("/api/logout", methods=["POST", "GET"])
def api_logout():
    # JWT 无状态，这里给前端一个“成功”响应即可
    return json_response(message="已退出登录")


@app.route("/api/user_status", methods=["GET"])
@jwt_required()
def api_user_status():
    u = get_current_user()
    if not u:
        return json_response(error="未登录", status=401)
    return json_response(data={"username": u.username, "is_admin": bool(u.is_admin)})


# ============ 题目 & 提交 ============
@app.route("/api/challenges", methods=["GET"])
@jwt_required()
def api_challenges():
    u = get_current_user()
    if not u:
        return json_response(error="未登录", status=401)

    solved_ids = {s.challenge_id for s in Solve.query.filter_by(user_id=u.id).all()}
    challenges = Challenge.query.order_by(Challenge.id.asc()).all()

    out = []
    for c in challenges:
        out.append({
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "category": c.category,
            "points": c.points,
            "file_url": f"/download/{c.file_path}" if c.file_path else None,
            "solved": c.id in solved_ids,
            "solvers": [],
        })
    return json_response(data=out)


@app.route("/api/submit", methods=["POST"])
@jwt_required()
def api_submit():
    u = get_current_user()
    if not u:
        return json_response(error="未登录", status=401)

    data = request.get_json(silent=True) or {}
    cid = data.get("challenge_id")
    flag = (data.get("flag") or "").strip()

    if not cid or not flag:
        return json_response(error="参数错误", status=400)

    chal = Challenge.query.get(int(cid))
    if not chal:
        return json_response(error="题目不存在", status=404)

    # 记录提交
    sub = Submission(user_id=u.id, challenge_id=chal.id, submitted_flag=flag, is_correct=False)
    db.session.add(sub)
    db.session.flush()

    # 已解过
    already = Solve.query.filter_by(user_id=u.id, challenge_id=chal.id).first()
    if already:
        sub.is_correct = (flag == chal.flag)
        db.session.commit()
        return jsonify({"correct": False, "message": "该题已完成，无需重复提交"})

    if flag == chal.flag:
        sub.is_correct = True
        db.session.add(Solve(user_id=u.id, challenge_id=chal.id))
        db.session.commit()
        return jsonify({"correct": True, "message": "恭喜，Flag 正确！", "score": calc_user_score(u.id)})

    db.session.commit()
    return jsonify({"correct": False, "message": "Flag 错误"})


# ============ 活动流 / 榜单 / 专业榜单 ============
@app.route("/api/activity", methods=["GET"])
def api_activity():
    # 最近 10 次正确提交
    q = (
        db.session.query(Submission, User, Challenge)
        .join(User, User.id == Submission.user_id)
        .join(Challenge, Challenge.id == Submission.challenge_id)
        .filter(Submission.is_correct == True)
        .order_by(Submission.created_at.desc())
        .limit(10)
        .all()
    )
    out = []
    for sub, u, c in q:
        out.append({
            "username": u.username,
            "title": c.title,
            "time": sub.created_at.strftime("%H:%M:%S"),
        })
    return jsonify(out)


@app.route("/api/scoreboard", methods=["GET"])
def api_scoreboard():
    users = User.query.filter_by(status="approved").all()
    rows = []
    for u in users:
        rows.append({
            "username": u.username,
            "score": calc_user_score(u.id),
            "solved": Solve.query.filter_by(user_id=u.id).count(),
        })
    rows.sort(key=lambda x: (-x["score"], -x["solved"], x["username"]))
    return jsonify(rows)


@app.route("/api/scoreboard_pro", methods=["GET"])
def api_scoreboard_pro():
    # 前端 scoreboard/matrix 常用格式：{data:{users:[...],trends:[...]}}
    users = User.query.filter_by(status="approved").all()
    rows = []
    for u in users:
        rows.append({
            "username": u.username,
            "score": calc_user_score(u.id),
            "solved": Solve.query.filter_by(user_id=u.id).count(),
        })
    rows.sort(key=lambda x: (-x["score"], -x["solved"], x["username"]))

    for i, r in enumerate(rows, start=1):
        r["rank"] = i
        r["tag"] = "综合"
        r["first_blood"] = 0
        r["last_active"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    trends = [{"t": datetime.utcnow().strftime("%H:%M:%S"), "top_score": (rows[0]["score"] if rows else 0)}]
    return jsonify({"data": {"users": rows[:100], "trends": trends}})


# ============ 管理员 API ============
@app.route("/api/admin/users", methods=["GET"])
@jwt_required()
@admin_required
def api_admin_users(admin_user):
    users = User.query.order_by(User.created_at.desc()).all()
    return json_response(data=[
        {
            "id": u.id,
            "username": u.username,
            "real_name": u.real_name,
            "student_id": u.student_id,
            "class_info": u.class_info,
            "status": u.status,
            "is_admin": bool(u.is_admin),
            "invitation_code": u.invitation_code,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for u in users
    ])


@app.route("/api/admin/registrations", methods=["GET"])
@jwt_required()
@admin_required
def api_admin_regs(admin_user):
    users = User.query.filter_by(status="pending").order_by(User.created_at.desc()).all()
    return json_response(data=[
        {
            "id": u.id,
            "username": u.username,
            "real_name": u.real_name,
            "student_id": u.student_id,
            "class_info": u.class_info,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for u in users
    ])


@app.route("/api/admin/approve/<int:uid>", methods=["POST"])
@jwt_required()
@admin_required
def api_admin_approve(admin_user, uid):
    u = User.query.get(uid)
    if not u:
        return json_response(error="用户不存在", status=404)
    u.status = "approved"
    db.session.commit()
    return json_response(message="已批准")


@app.route("/api/admin/reject/<int:uid>", methods=["POST"])
@jwt_required()
@admin_required
def api_admin_reject(admin_user, uid):
    u = User.query.get(uid)
    if not u:
        return json_response(error="用户不存在", status=404)
    u.status = "rejected"
    db.session.commit()
    return json_response(message="已拒绝")


@app.route("/api/admin/codes", methods=["GET"])
@jwt_required()
@admin_required
def api_admin_codes(admin_user):
    out = []
    for code, meta in INVITATION_CODES.items():
        used = User.query.filter_by(invitation_code=code).count()
        max_uses = int(meta.get("max_uses") or 0)
        remaining = max_uses - used if max_uses > 0 else -1
        out.append({
            "code": code,
            "label": meta.get("label", ""),
            "type": meta.get("type", ""),
            "max_uses": max_uses,
            "used": used,
            "remaining": remaining,
        })
    return json_response(data=out)


@app.route("/api/admin/flags", methods=["GET"])
@jwt_required()
@admin_required
def api_admin_flags(admin_user):
    challenges = Challenge.query.order_by(Challenge.id.asc()).all()
    out = []
    for c in challenges:
        out.append({
            "id": c.id,
            "title": c.title,
            "category": c.category,
            "points": c.points,
            "difficulty": "Easy" if c.points <= 100 else ("Medium" if c.points <= 200 else "Hard"),
            "flag": c.flag,
        })
    return json_response(data=out)


# ============ JWT错误处理 ============
@jwt.unauthorized_loader
def unauthorized_callback(_):
    return jsonify({"success": False, "error": "未提供有效的认证令牌"}), 401


@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return jsonify({"success": False, "error": f"无效的认证令牌: {reason}"}), 422


@jwt.expired_token_loader
def expired_token_callback(_, __):
    return jsonify({"success": False, "error": "认证令牌已过期"}), 401


# ============ 初始化数据库 ============
def init_database():
    with app.app_context():
        db.create_all()

        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                password_hash=generate_password_hash("admin123"),
                real_name="系统管理员",
                invitation_code="TEACHER01",
                is_admin=True,
                status="approved",
            )
            db.session.add(admin_user)
            db.session.commit()
            print("✅ 已创建默认管理员账号: admin / admin123")


if __name__ == "__main__":
    init_database()
    port = int(os.environ.get("PORT", "5000"))
    print(f"✅ 服务器启动: http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
