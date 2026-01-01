import os
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

from werkzeug.security import generate_password_hash, check_password_hash

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request,
)

# =========================
# 基础配置
# =========================
TZ_OFFSET_HOURS = int(os.getenv("TZ_OFFSET_HOURS", "8"))  # 默认东八区
LOCAL_TZ = timezone(timedelta(hours=TZ_OFFSET_HOURS))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACH_DIR = os.path.join(BASE_DIR, "attachments")
os.makedirs(ATTACH_DIR, exist_ok=True)

STUDENT_INVITE = os.getenv("STUDENT_INVITE", "STUDENT2026")
TEACHER_INVITE = os.getenv("TEACHER_INVITE", "TEACHER2026")


def utcnow():
    return datetime.now(timezone.utc)


def to_local(dt: datetime):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(LOCAL_TZ)


def fmt_local(dt: datetime, with_date=True, with_sec=True):
    if not dt:
        return "-"
    dt = to_local(dt)
    if with_date and with_sec:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    if with_date and not with_sec:
        return dt.strftime("%Y-%m-%d %H:%M")
    if (not with_date) and with_sec:
        return dt.strftime("%H:%M:%S")
    return dt.strftime("%H:%M")


def json_response(success=True, msg="ok", data=None, status=200):
    return jsonify({"success": success, "msg": msg, "data": data}), status


# =========================
# Flask / DB / JWT
# =========================
app = Flask(__name__)

db_url = os.getenv("DATABASE_URL", "sqlite:///ctf.db")
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

# JWT：支持 query_string token
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "jwt-secret-change-me")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
app.config["JWT_TOKEN_LOCATION"] = ["headers", "query_string"]
app.config["JWT_QUERY_STRING_NAME"] = "token"
app.config["JWT_QUERY_STRING_VALUE_PREFIX"] = ""  # ?token=xxx 直接可用

db = SQLAlchemy(app)
jwt = JWTManager(app)

CORS(app, resources={r"/api/*": {"origins": "*"}})


# =========================
# Models
# =========================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    real_name = db.Column(db.String(64), default="")
    student_id = db.Column(db.String(64), default="")
    class_info = db.Column(db.String(128), default="")

    is_admin = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(16), default="pending")  # pending/approved/rejected
    created_at = db.Column(db.DateTime, default=utcnow)

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)


class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, default="")
    category = db.Column(db.String(32), default="MISC")
    points = db.Column(db.Integer, default=100)

    flag = db.Column(db.String(256), nullable=False)
    file_path = db.Column(db.String(256), default="")
    created_at = db.Column(db.DateTime, default=utcnow)


class Solve(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenge.id"), index=True)
    solved_at = db.Column(db.DateTime, default=utcnow, index=True)


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenge.id"), index=True)
    submitted_flag = db.Column(db.String(512), default="")
    correct = db.Column(db.Boolean, default=False)
    submitted_at = db.Column(db.DateTime, default=utcnow, index=True)
    ip = db.Column(db.String(64), default="")


class Download(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenge.id"), index=True)
    downloaded_at = db.Column(db.DateTime, default=utcnow, index=True)
    ip = db.Column(db.String(64), default="")


# =========================
# Init DB
# =========================
@app.before_first_request
def init_db():
    db.create_all()


# =========================
# Helpers
# =========================
def require_admin(user_id: int):
    u = User.query.get(user_id)
    if not u or not u.is_admin:
        abort(403)
    return u


def calc_user_score(user_id: int) -> int:
    rows = (
        db.session.query(Challenge.points)
        .join(Solve, Solve.challenge_id == Challenge.id)
        .filter(Solve.user_id == user_id)
        .all()
    )
    return int(sum(r[0] for r in rows))


def user_rank_map():
    users = User.query.filter_by(status="approved").all()
    scored = []
    for u in users:
        scored.append((u.username, calc_user_score(u.id), u.id))
    scored.sort(key=lambda x: (-x[1], x[0].lower()))
    rank = {}
    for i, (_, _, uid) in enumerate(scored, start=1):
        rank[uid] = i
    return rank, scored


def floor_to_interval(dt: datetime, minutes: int):
    dt = dt.replace(second=0, microsecond=0)
    m = (dt.minute // minutes) * minutes
    return dt.replace(minute=m)


def ceil_to_interval(dt: datetime, minutes: int):
    dt = dt.replace(second=0, microsecond=0)
    if dt.minute % minutes == 0:
        return dt
    m = ((dt.minute // minutes) + 1) * minutes
    if m >= 60:
        dt = dt.replace(minute=0) + timedelta(hours=1)
        return dt
    return dt.replace(minute=m)


def make_time_labels(start_local: datetime, end_local: datetime, step_minutes: int):
    # ✅ 输出 “MM-DD HH:MM”，图底部就能像 ByteCTF 那样带日期+时间
    labels = []
    t = start_local
    while t <= end_local:
        labels.append(t.strftime("%m-%d %H:%M"))
        t += timedelta(minutes=step_minutes)
    return labels


def strongest_category_for_user(uid: int):
    # ✅ 统计该用户解题最多的类别
    rows = (
        db.session.query(Challenge.category, db.func.count(Solve.id))
        .join(Solve, Solve.challenge_id == Challenge.id)
        .filter(Solve.user_id == uid)
        .group_by(Challenge.category)
        .order_by(db.func.count(Solve.id).desc(), Challenge.category.asc())
        .all()
    )
    if not rows:
        return "-"
    return rows[0][0] or "-"


def first_blood_count_for_user(uid: int):
    # ✅ 一血：该题最早 solved_at 的 user_id == uid
    # 子查询：每题最早解题时间
    sub = (
        db.session.query(
            Solve.challenge_id.label("cid"),
            db.func.min(Solve.solved_at).label("min_t"),
        )
        .group_by(Solve.challenge_id)
        .subquery()
    )
    rows = (
        db.session.query(Solve.user_id)
        .join(sub, (Solve.challenge_id == sub.c.cid) & (Solve.solved_at == sub.c.min_t))
        .filter(Solve.user_id == uid)
        .all()
    )
    return int(len(rows))


# =========================
# Auth APIs
# =========================
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")
    invitation_code = (data.get("invitation_code") or "").strip().upper()

    real_name = (data.get("real_name") or "").strip()
    student_id = (data.get("student_id") or "").strip()
    class_info = (data.get("class_info") or "").strip()

    if not username or not password or not invitation_code:
        return json_response(False, "请填写所有必填字段", None, 400)

    if len(username) < 3 or len(username) > 20:
        return json_response(False, "用户名长度3-20位", None, 400)

    if User.query.filter_by(username=username).first():
        return json_response(False, "用户名已存在", None, 400)

    user = User(username=username, real_name=real_name, student_id=student_id, class_info=class_info)

    if invitation_code == TEACHER_INVITE:
        user.is_admin = True
        user.status = "approved"
    elif invitation_code == STUDENT_INVITE:
        user.is_admin = False
        user.status = "pending"
    else:
        return json_response(False, "邀请码无效", None, 400)

    if len(password) < 6:
        return json_response(False, "密码长度至少6位", None, 400)

    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    if user.is_admin:
        return json_response(True, "注册成功：管理员已启用", None)
    return json_response(True, "注册成功：等待管理员审核", None)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return json_response(False, "用户名或密码错误", None, 401)

    if user.status != "approved":
        return json_response(False, "账号未审核通过", None, 403)

    token = create_access_token(identity=user.id)
    payload = {
        "token": token,
        "user": {"id": user.id, "username": user.username, "is_admin": bool(user.is_admin)},
    }
    return json_response(True, "登录成功", payload)


@app.route("/api/logout", methods=["POST"])
def api_logout():
    return json_response(True, "ok", None)


# =========================
# Challenge / Submit
# =========================
@app.route("/api/challenges", methods=["GET"])
@jwt_required()
def api_challenges():
    uid = get_jwt_identity()

    challenges = Challenge.query.order_by(Challenge.id.asc()).all()
    solved_ids = set(r[0] for r in db.session.query(Solve.challenge_id).filter_by(user_id=uid).all())

    out = []
    for ch in challenges:
        solvers = (
            db.session.query(User.username)
            .join(Solve, Solve.user_id == User.id)
            .filter(Solve.challenge_id == ch.id)
            .order_by(Solve.solved_at.asc())
            .limit(3)
            .all()
        )
        solvers = [s[0] for s in solvers]

        file_url = f"/download/{ch.file_path}" if ch.file_path else ""

        out.append(
            {
                "id": ch.id,
                "title": ch.title,
                "description": ch.description,
                "category": ch.category,
                "points": ch.points,
                "solvers": solvers,
                "solved": ch.id in solved_ids,
                "file_url": file_url,
            }
        )

    return json_response(True, "ok", out)


@app.route("/api/submit", methods=["POST"])
@jwt_required()
def api_submit():
    uid = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    cid = int(data.get("challenge_id") or 0)
    flag = (data.get("flag") or "").strip()

    ch = Challenge.query.get(cid)
    if not ch:
        return jsonify({"correct": False, "message": "题目不存在"}), 404

    already = Solve.query.filter_by(user_id=uid, challenge_id=cid).first()
    if already:
        return jsonify({"correct": True, "message": "你已解出该题"}), 200

    is_correct = (flag == ch.flag)
    sub = Submission(
        user_id=uid,
        challenge_id=cid,
        submitted_flag=flag,
        correct=is_correct,
        ip=request.headers.get("X-Forwarded-For", request.remote_addr or ""),
    )
    db.session.add(sub)

    if is_correct:
        db.session.add(Solve(user_id=uid, challenge_id=cid))
        db.session.commit()
        return jsonify({"correct": True, "message": "Flag 正确！"}), 200

    db.session.commit()
    return jsonify({"correct": False, "message": "Flag 错误"}), 200


@app.route("/api/user_status", methods=["GET"])
@jwt_required()
def api_user_status():
    uid = get_jwt_identity()
    rank_map, _ = user_rank_map()

    score = calc_user_score(uid)
    total = Challenge.query.count()
    solved = Solve.query.filter_by(user_id=uid).count()
    progress = int((solved / total) * 100) if total else 0

    return json_response(
        True,
        "ok",
        {
            "score": score,
            "rank": rank_map.get(uid, "--"),
            "progress": progress,
        },
    )


# =========================
# Scoreboard + Activity
# =========================
@app.route("/api/scoreboard", methods=["GET"])
def api_scoreboard():
    _, scored = user_rank_map()

    out = []
    for i, (username, score, uid) in enumerate(scored, start=1):
        solved = Solve.query.filter_by(user_id=uid).count()
        last_solve = (
            db.session.query(Solve.solved_at)
            .filter_by(user_id=uid)
            .order_by(Solve.solved_at.desc())
            .first()
        )
        last_solve = last_solve[0] if last_solve else None

        out.append(
            {
                "rank": i,
                "username": username,
                "score": score,
                "solved": solved,
                "last_active": fmt_local(last_solve, with_date=True, with_sec=False) if last_solve else "-",
            }
        )
    return json_response(True, "ok", out)


@app.route("/api/activity", methods=["GET"])
def api_activity():
    rows = (
        db.session.query(Solve.solved_at, User.username, Challenge.title)
        .join(User, User.id == Solve.user_id)
        .join(Challenge, Challenge.id == Solve.challenge_id)
        .order_by(Solve.solved_at.desc())
        .limit(10)
        .all()
    )

    out = []
    for solved_at, username, title in rows:
        out.append(
            {
                "username": username,
                "title": title,
                "time": fmt_local(solved_at, with_date=False, with_sec=True),
            }
        )
    return json_response(True, "ok", out)


# =========================
# Scoreboard Pro（趋势折线）
# =========================
@app.route("/api/scoreboard_pro", methods=["GET"])
def api_scoreboard_pro():
    now_local = to_local(utcnow())

    first = db.session.query(Solve.solved_at).order_by(Solve.solved_at.asc()).first()
    if first and first[0]:
        start_local = to_local(first[0])
    else:
        start_local = now_local - timedelta(hours=1)

    start_local = floor_to_interval(start_local, 5)
    end_local = ceil_to_interval(now_local, 5)

    labels = make_time_labels(start_local, end_local, 5)

    # 取所有 solve + points（时间升序）
    rows = (
        db.session.query(Solve.user_id, Solve.solved_at, Challenge.points)
        .join(Challenge, Challenge.id == Solve.challenge_id)
        .order_by(Solve.solved_at.asc())
        .all()
    )

    # 按用户聚合
    by_user = {}
    for user_id, solved_at, pts in rows:
        by_user.setdefault(user_id, []).append((to_local(solved_at), int(pts)))

    # tick 时间列表
    tick_times = []
    t = start_local
    while t <= end_local:
        tick_times.append(t)
        t += timedelta(minutes=5)

    # 排名用户
    _, scored = user_rank_map()

    users = []
    for i, (username, score, uid) in enumerate(scored, start=1):
        solved_cnt = Solve.query.filter_by(user_id=uid).count()
        last_solve = (
            db.session.query(Solve.solved_at)
            .filter_by(user_id=uid)
            .order_by(Solve.solved_at.desc())
            .first()
        )
        last_solve = last_solve[0] if last_solve else None

        users.append(
            {
                "rank": i,
                "username": username,
                "score": score,
                "solve_count": solved_cnt,
                "strongest_cat": strongest_category_for_user(uid),
                "first_bloods": first_blood_count_for_user(uid),
                "last_update": fmt_local(last_solve, with_date=True, with_sec=False) if last_solve else "-",
            }
        )

    # 趋势只生成前15（避免太多线）
    top_user_ids = [uid for (_, _, uid) in scored[:15]]
    trends = {}

    for uid in top_user_ids:
        seq = []
        total = 0
        lst = by_user.get(uid, [])
        idx = 0
        for tick in tick_times:
            while idx < len(lst) and lst[idx][0] <= tick:
                total += lst[idx][1]
                idx += 1
            seq.append(total)

        u = User.query.get(uid)
        if u:
            trends[u.username] = seq

    return jsonify({"trend_labels": labels, "users": users, "trends": trends})


# =========================
# Download（关键修复）
# =========================
@app.route("/api/record_download", methods=["POST"])
@jwt_required()
def api_record_download():
    uid = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    cid = int(data.get("challenge_id") or 0)

    ch = Challenge.query.get(cid)
    if not ch or not ch.file_path:
        return json_response(False, "该题目无附件", None, 400)

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    existed = Download.query.filter_by(user_id=uid, challenge_id=cid).first()
    if not existed:
        db.session.add(Download(user_id=uid, challenge_id=cid, ip=ip))
        db.session.commit()

    return json_response(True, "ok", None)


@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename):
    user_id = None
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
    except Exception:
        user_id = None

    ch = Challenge.query.filter_by(file_path=filename).first()
    if ch and user_id:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        existed = Download.query.filter_by(user_id=user_id, challenge_id=ch.id).first()
        if not existed:
            db.session.add(Download(user_id=user_id, challenge_id=ch.id, ip=ip))
            db.session.commit()

    safe_path = os.path.normpath(filename).replace("\\", "/")
    if safe_path.startswith(".."):
        abort(403)

    full = os.path.join(ATTACH_DIR, safe_path)
    if not os.path.isfile(full):
        abort(404)

    directory = os.path.dirname(os.path.join(ATTACH_DIR, safe_path))
    base = os.path.basename(safe_path)
    return send_from_directory(directory, base, as_attachment=True)


# =========================
# Admin APIs（含作弊检测）
# =========================
@app.route("/api/admin/cheat_check", methods=["GET"])
@jwt_required()
def api_admin_cheat_check():
    admin_id = get_jwt_identity()
    require_admin(admin_id)

    rows = (
        db.session.query(Solve.user_id, Solve.challenge_id, Solve.solved_at)
        .join(Challenge, Challenge.id == Solve.challenge_id)
        .filter(Challenge.file_path != "")
        .order_by(Solve.solved_at.desc())
        .all()
    )

    out = []
    for uid, cid, solved_at in rows:
        u = User.query.get(uid)
        ch = Challenge.query.get(cid)
        if not u or not ch:
            continue

        downloaded = Download.query.filter_by(user_id=uid, challenge_id=cid).first()
        if not downloaded:
            out.append(
                {
                    "username": u.username,
                    "real_name": u.real_name or "-",
                    "title": ch.title,
                    "category": ch.category,
                    "solved_at": fmt_local(solved_at, with_date=True, with_sec=True),
                    "status": "未下载附件但已解题",
                }
            )

    return json_response(True, "ok", out)


# =========================
# Run
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
