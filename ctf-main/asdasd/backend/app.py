# -*- coding: utf-8 -*-
import os
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import Flask, jsonify, request, send_from_directory, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, verify_jwt_in_request
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
    # ✅ 允许 query string token（给 /download?token=... 做准备）
    JWT_TOKEN_LOCATION=["headers", "query_string"],
    JWT_QUERY_STRING_NAME="token",
)

# ✅ 关键：显式允许 Authorization，避免后台跨域预检失败导致“无数据”
CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"],
)

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
    file_path = db.Column(db.String(256))
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


class DownloadLog(db.Model):
    __tablename__ = "download_log"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenge.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "challenge_id", name="uniq_user_challenge_download"),)


# ============ 工具函数 ============
def json_response(data=None, message="", error=None, status=200):
    payload = {"success": error is None, "message": message}
    if error is not None:
        payload["error"] = error
    if data is not None:
        payload["data"] = data
    return jsonify(payload), status


def get_current_user():
    try:
        verify_jwt_in_request(optional=True)  # ✅ optional=True 避免 OPTIONS/无 token 时抛异常
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
        if u.status != "approved":
            return json_response(error="账号未审核通过", status=403)
        if not u.is_admin:
            return json_response(error="需要管理员权限", status=403)
        return fn(u, *args, **kwargs)
    return wrapper


def calc_user_score(uid: int) -> int:
    total = (
        db.session.query(func.coalesce(func.sum(Challenge.points), 0))
        .join(Solve, Solve.challenge_id == Challenge.id)
        .filter(Solve.user_id == uid)
        .scalar()
    )
    return int(total or 0)


def ensure_frontend_dir():
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


# ============ ✅ 统一处理 OPTIONS 预检（关键） ============
@app.before_request
def handle_options_preflight():
    if request.method == "OPTIONS":
        resp = make_response("", 204)
        return resp


# ============ 前端页面路由 ============
@app.route("/")
def page_root():
    for name in ("login.html", "admin.html", "index.html"):
        p = os.path.join(FRONTEND_DIR, name)
        if os.path.isfile(p):
            return send_from_directory(FRONTEND_DIR, name)
    abort(404)


@app.route("/<path:filename>")
def page_files(filename):
    if filename.startswith("api/"):
        abort(404)
    p = os.path.join(FRONTEND_DIR, filename)
    if os.path.isfile(p):
        return send_from_directory(FRONTEND_DIR, filename)
    p2 = os.path.join(BASE_DIR, filename)
    if os.path.isfile(p2):
        return send_from_directory(BASE_DIR, filename)
    abort(404)


# ============ 下载接口 ============
@app.route("/download/<path:fname>")
def download_file(fname):
    full = os.path.join(STATIC_DIR, fname)
    if not os.path.isfile(full):
        abort(404)

    # ✅ 支持 /download/xxx?token=... 记录下载（解决作弊检测误判的根基础）
    user = get_current_user()
    if user:
        challenge = Challenge.query.filter_by(file_path=fname).first()
        if challenge:
            exists = DownloadLog.query.filter_by(user_id=user.id, challenge_id=challenge.id).first()
            if not exists:
                db.session.add(DownloadLog(user_id=user.id, challenge_id=challenge.id))
                db.session.commit()

    return send_from_directory(STATIC_DIR, fname, as_attachment=True)


@app.route("/api/challenges/<int:cid>/download", methods=["GET"])
@jwt_required()
def api_challenge_download(cid):
    u = get_current_user()
    if not u:
        return json_response(error="未登录", status=401)

    chal = Challenge.query.get(cid)
    if not chal or not chal.file_path:
        return json_response(error="附件不存在", status=404)

    full = os.path.join(STATIC_DIR, chal.file_path)
    if not os.path.isfile(full):
        return json_response(error="附件不存在", status=404)

    exists = DownloadLog.query.filter_by(user_id=u.id, challenge_id=chal.id).first()
    if not exists:
        db.session.add(DownloadLog(user_id=u.id, challenge_id=chal.id))
        db.session.commit()

    return send_from_directory(STATIC_DIR, chal.file_path, as_attachment=True)


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
        "data": {"token": token, "user_id": user.id, "username": user.username, "is_admin": bool(user.is_admin)}
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
    return json_response(message="已退出登录")


@app.route("/api/user_status", methods=["GET"])
@jwt_required()
def api_user_status():
    u = get_current_user()
    if not u:
        return json_response(error="未登录", status=401)

    # 1) 当前积分
    score = calc_user_score(u.id)

    # 2) 排名（按积分降序；同分按最后解题时间/注册时间兜底）
    # 这里用 Python 排一下，数据量小（CTF 场景通常几十/几百人）非常稳妥
    users = User.query.filter_by(status="approved").all()
    score_map = {}
    for uu in users:
        score_map[uu.id] = calc_user_score(uu.id)

    # 找最后解题时间（用于显示 & 排名兜底）
    last_solve = (
        db.session.query(func.max(Solve.created_at))
        .filter(Solve.user_id == u.id)
        .scalar()
    )

    # 排名列表
    sorted_users = sorted(
        users,
        key=lambda uu: (
            -score_map.get(uu.id, 0),
            # 有解题记录的排前；时间越早越靠前（也可反过来，看你想要）
            (db.session.query(func.min(Solve.created_at)).filter(Solve.user_id == uu.id).scalar() or datetime.max),
            uu.created_at or datetime.max,
        ),
    )
    rank = next((i + 1 for i, uu in enumerate(sorted_users) if uu.id == u.id), None)

    # 3) 进度（已解题数 / 总题数）
    total_chals = Challenge.query.count()
    solved_cnt = Solve.query.filter_by(user_id=u.id).count()
    progress = 0
    if total_chals > 0:
        progress = int(round((solved_cnt / float(total_chals)) * 100))

    return json_response(data={
        "username": u.username,
        "is_admin": bool(u.is_admin),
        "score": score,
        "rank": rank if rank is not None else "--",
        "progress": progress,
        # 可选：顺便把最后活跃时间也给前端（你后面可能用得到）
        "last_update": fmt_ts(last_solve) if last_solve else "",
    })



# ============ 题目 & 提交 ============
@app.route("/api/challenges", methods=["GET"])
@jwt_required()
def api_challenges():
    u = get_current_user()
    if not u:
        return json_response(error="未登录", status=401)

    solved_ids = {s.challenge_id for s in Solve.query.filter_by(user_id=u.id).all()}
    downloaded_ids = {d.challenge_id for d in DownloadLog.query.filter_by(user_id=u.id).all()}
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
            "file_name": os.path.basename(c.file_path) if c.file_path else None,
            "solved": c.id in solved_ids,
            "downloaded": c.id in downloaded_ids,
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

    sub = Submission(user_id=u.id, challenge_id=chal.id, submitted_flag=flag, is_correct=False)
    db.session.add(sub)
    db.session.flush()

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


# =========================================================
# ✅✅✅ 新增路由：activity / scoreboard / scoreboard_pro
# （只新增，不改动你其它功能）
# =========================================================
def _fmt_local(dt):
    # 数据库里如果是 UTC，这里转东八区显示
    if not dt:
        return ""
    try:
        return (dt + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(dt)

@app.route("/api/activity", methods=["GET"])
def api_activity():
    rows = (
        db.session.query(Solve, User, Challenge)
        .join(User, User.id == Solve.user_id)
        .join(Challenge, Challenge.id == Solve.challenge_id)
        .order_by(Solve.created_at.desc())
        .limit(30)
        .all()
    )

    out = []
    for s, u, c in rows:
        out.append({
            "username": u.username,
            "title": c.title,               # ✅ 前端用这个显示“解出：xxx”
            "time": _fmt_local(s.created_at) # ✅ 前端用这个显示时间
        })
    return json_response(data=out)



@app.route("/api/scoreboard", methods=["GET"])
def api_scoreboard():
    """
    简版榜单（公开读）
    返回：[{rank, username, score, solve_count}]
    """
    users = User.query.filter_by(status="approved").all()
    score_rows = (
        db.session.query(Solve.user_id, func.coalesce(func.sum(Challenge.points), 0))
        .join(Challenge, Challenge.id == Solve.challenge_id)
        .group_by(Solve.user_id)
        .all()
    )
    score_map = {uid: int(total or 0) for uid, total in score_rows}
    solve_rows = (
        db.session.query(Solve.user_id, func.count(Solve.id))
        .group_by(Solve.user_id)
        .all()
    )
    solve_cnt_map = {uid: int(cnt or 0) for uid, cnt in solve_rows}

    items = []
    for u in users:
        items.append({
            "username": u.username,
            "score": score_map.get(u.id, 0),
            "solve_count": solve_cnt_map.get(u.id, 0),
        })

    items.sort(key=lambda x: (-x["score"], -x["solve_count"], x["username"]))
    out = []
    for i, it in enumerate(items, start=1):
        out.append({
            "rank": i,
            "username": it["username"],
            "score": it["score"],
            "solve_count": it["solve_count"],
        })
    return json_response(data=out)
def fmt_ts(dt):
    """把 DB 里 utcnow 存的时间，按北京时间字符串输出（不改库，只改展示）"""
    if not dt:
        return ""
    try:
        return (dt + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        try:
            return str(dt)
        except Exception:
            return ""


@app.route("/api/scoreboard_pro", methods=["GET"])
def api_scoreboard_pro():
    """
    大屏/位图用（公开读）
    返回：
      {
        "trend_labels": [...],
        "users": [{rank, username, score, solve_count, strongest_cat, first_bloods, last_update, matrix:{cid:state}}],
        "trends": {username:[...scores...]},
        "challenges":[{id,title,points,category}]
      }

    matrix state:
      0 未解
      1 一血
      2 二血
      3 三血
      4 已解(非前三)
    """
    # 题目列表（位图表头）
    challenges = Challenge.query.order_by(Challenge.id.asc()).all()
    chal_list = [{
        "id": c.id,
        "title": c.title,
        "points": int(c.points or 0),
        "category": c.category,
    } for c in challenges]
    chal_ids = [c["id"] for c in chal_list]
    chal_points = {c.id: int(c.points or 0) for c in challenges}
    chal_cat = {c.id: (c.category or "") for c in challenges}

    # 所有已审核用户
    users = User.query.filter_by(status="approved").all()

    # 每题前三血：按 solve.created_at 排序取前三个用户
    # first3_map[challenge_id] = [user_id1, user_id2, user_id3]
    solve_rows = (
        db.session.query(Solve.challenge_id, Solve.user_id, Solve.created_at)
        .order_by(Solve.challenge_id.asc(), Solve.created_at.asc())
        .all()
    )
    first3_map = defaultdict(list)
    # 同时准备 user->solves 方便统计
    user_solved = defaultdict(set)
    user_last_solve_time = defaultdict(lambda: None)

    for cid, uid, t in solve_rows:
        if len(first3_map[cid]) < 3:
            if uid not in first3_map[cid]:
                first3_map[cid].append(uid)
        user_solved[uid].add(cid)
        # last solve time
        cur = user_last_solve_time.get(uid)
        if cur is None or (t and t > cur):
            user_last_solve_time[uid] = t

    # 统计用户分数 / 解题数
    score_rows = (
        db.session.query(Solve.user_id, func.coalesce(func.sum(Challenge.points), 0))
        .join(Challenge, Challenge.id == Solve.challenge_id)
        .group_by(Solve.user_id)
        .all()
    )
    score_map = {uid: int(total or 0) for uid, total in score_rows}

    solve_cnt_rows = (
        db.session.query(Solve.user_id, func.count(Solve.id))
        .group_by(Solve.user_id)
        .all()
    )
    solve_cnt_map = {uid: int(cnt or 0) for uid, cnt in solve_cnt_rows}

    # strongest_cat：按“该用户解出的题目类别累计分”取最高
    cat_score = defaultdict(lambda: defaultdict(int))  # cat_score[uid][cat]+=points
    for cid, uid, _t in solve_rows:
        cat = chal_cat.get(cid, "") or ""
        cat_score[uid][cat] += chal_points.get(cid, 0)

    strongest_cat_map = {}
    for u in users:
        m = cat_score.get(u.id, {})
        if not m:
            strongest_cat_map[u.id] = ""
        else:
            strongest_cat_map[u.id] = sorted(m.items(), key=lambda x: (-x[1], x[0]))[0][0]

    # first_bloods：该用户拿到的一血数量
    first_blood_cnt = defaultdict(int)
    for cid, uids in first3_map.items():
        if len(uids) >= 1:
            first_blood_cnt[uids[0]] += 1

    # 生成 matrix：每个用户对每题的状态
    user_matrix = {}
    for u in users:
        solved_set = user_solved.get(u.id, set())
        mat = {}
        for cid in chal_ids:
            if cid not in solved_set:
                mat[cid] = 0
                continue
            top3 = first3_map.get(cid, [])
            if len(top3) >= 1 and top3[0] == u.id:
                mat[cid] = 1
            elif len(top3) >= 2 and top3[1] == u.id:
                mat[cid] = 2
            elif len(top3) >= 3 and top3[2] == u.id:
                mat[cid] = 3
            else:
                mat[cid] = 4
        user_matrix[u.id] = mat

    # 用户榜单（排序并赋 rank）
    items = []
    for u in users:
        last_t = user_last_solve_time.get(u.id)
        items.append({
            "uid": u.id,
            "username": u.username,
            "score": score_map.get(u.id, 0),
            "solve_count": solve_cnt_map.get(u.id, 0),
            "strongest_cat": strongest_cat_map.get(u.id, "") or "",
            "first_bloods": int(first_blood_cnt.get(u.id, 0)),
            "last_update": last_t.strftime("%Y-%m-%d %H:%M:%S") if last_t else "",
            "matrix": user_matrix.get(u.id, {}),
        })
    items.sort(key=lambda x: (-x["score"], -x["solve_count"], x["username"]))

    users_out = []
    for i, it in enumerate(items, start=1):
        users_out.append({
            "rank": i,
            "username": it["username"],
            "score": it["score"],
            "solve_count": it["solve_count"],
            "strongest_cat": it["strongest_cat"],
            "first_bloods": it["first_bloods"],
            "last_update": it["last_update"],
            "matrix": it["matrix"],
        })

    # 趋势图：按 15 分钟桶，展示最近 24 小时（共 97 个点：含起点）
    now = datetime.utcnow()
    # 以 15 分钟对齐
    minute = (now.minute // 15) * 15
    aligned_now = now.replace(minute=minute, second=0, microsecond=0)
    start = aligned_now - timedelta(hours=24)

    labels = []
    cursor = start
    while cursor <= aligned_now:
        labels.append(cursor.strftime("%m-%d %H:%M"))
        cursor += timedelta(minutes=15)

    # 取最近 24h 内的 solves 用于趋势累加
    recent_solves = (
        db.session.query(Solve.user_id, Solve.created_at, Challenge.points)
        .join(Challenge, Challenge.id == Solve.challenge_id)
        .filter(Solve.created_at >= start)
        .filter(Solve.created_at <= aligned_now + timedelta(minutes=1))
        .order_by(Solve.created_at.asc())
        .all()
    )

    # 为了让曲线从 start 点就有“当时已经拿到的总分”，先算 start 前的基线分
    base_rows = (
        db.session.query(Solve.user_id, func.coalesce(func.sum(Challenge.points), 0))
        .join(Challenge, Challenge.id == Solve.challenge_id)
        .filter(Solve.created_at < start)
        .group_by(Solve.user_id)
        .all()
    )
    base_map = {uid: int(total or 0) for uid, total in base_rows}

    # 初始化趋势数组
    trends = {}
    idx_map = {}  # user_id -> current array
    for u in users:
        trends[u.username] = [0] * len(labels)
        idx_map[u.id] = trends[u.username]
        # 起点为 base
        idx_map[u.id][0] = base_map.get(u.id, 0)

    # 累加：把每次 solve 落到对应 bucket，并从该 bucket 起一直保持累积
    def bucket_index(ts: datetime) -> int:
        if ts <= start:
            return 0
        if ts >= aligned_now:
            return len(labels) - 1
        delta = ts - start
        mins = int(delta.total_seconds() // 60)
        return max(0, min(len(labels) - 1, mins // 15))

    # 先把每个用户在每个桶的增量记下来
    inc = defaultdict(lambda: [0] * len(labels))
    for uid, t, pts in recent_solves:
        if not t:
            continue
        bi = bucket_index(t)
        inc[uid][bi] += int(pts or 0)

    # 生成最终曲线：prefix sum（并带 base）
    for u in users:
        arr = idx_map[u.id]
        base = base_map.get(u.id, 0)
        running = base
        for i in range(len(labels)):
            if i == 0:
                running = base + inc[u.id][i]
                arr[i] = running
            else:
                running += inc[u.id][i]
                arr[i] = running

    payload = {
        "trend_labels": labels,
        "users": users_out,
        "trends": trends,
        "challenges": chal_list,
    }
    return json_response(data=payload)


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


# ✅ 和前端说明一致：最近 500 条
@app.route("/api/admin/submissions", methods=["GET"])
@jwt_required()
@admin_required
def api_admin_submissions(admin_user):
    rows = (
        db.session.query(Submission, User, Challenge)
        .join(User, User.id == Submission.user_id)
        .join(Challenge, Challenge.id == Submission.challenge_id)
        .order_by(Submission.created_at.desc())
        .limit(500)
        .all()
    )
    out = []
    for sub, u, c in rows:
        out.append({
            "username": u.username,
            "real_name": u.real_name or "",
            "challenge_title": c.title,
            "submitted_flag": sub.submitted_flag or "",
            "is_correct": bool(sub.is_correct),
            "created_at": sub.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return json_response(data=out)


@app.route("/api/admin/downloads", methods=["GET"])
@jwt_required()
@admin_required
def api_admin_downloads(admin_user):
    challenges = Challenge.query.order_by(Challenge.id.asc()).all()
    downloads = DownloadLog.query.order_by(DownloadLog.created_at.desc()).all()
    user_map = {u.id: u for u in User.query.all()}

    recent_map = defaultdict(list)
    count_map = defaultdict(int)
    for d in downloads:
        count_map[d.challenge_id] += 1
        if len(recent_map[d.challenge_id]) < 5:
            user = user_map.get(d.user_id)
            recent_map[d.challenge_id].append({
                "username": user.username if user else "-",
                "time": d.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            })

    out = []
    for c in challenges:
        out.append({
            "id": c.id,
            "title": c.title,
            "category": c.category,
            "file_path": c.file_path or "",
            "download_count": count_map.get(c.id, 0),
            "recent_downloads": recent_map.get(c.id, []),
        })
    return json_response(data=out)


@app.route("/api/admin/cheat_check", methods=["GET"])
@jwt_required()
@admin_required
def api_admin_cheat_check(admin_user):
    solves = (
        db.session.query(Solve, User, Challenge)
        .join(User, User.id == Solve.user_id)
        .join(Challenge, Challenge.id == Solve.challenge_id)
        .filter(Challenge.file_path.isnot(None))
        .filter(Challenge.file_path != "")
        .order_by(Solve.created_at.desc())
        .limit(5000)
        .all()
    )

    downloads = {(d.user_id, d.challenge_id) for d in DownloadLog.query.all()}
    records = []
    for s, u, c in solves:
        if (u.id, c.id) in downloads:
            continue
        records.append({
            "username": u.username,
            "real_name": u.real_name or "",
            "challenge_title": c.title,
            "category": c.category,
            "solve_time": s.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "warning": "未下载附件但已解题",
        })
    return json_response(data={"records": records})


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
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)
