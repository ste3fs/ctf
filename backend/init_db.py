# -*- coding: utf-8 -*-
from app import app, db, User, Challenge
from werkzeug.security import generate_password_hash

def init_database():
    with app.app_context():
        print("正在创建数据库表...")
        db.create_all()

        # 默认管理员
        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                password_hash=generate_password_hash("admin123"),
                real_name="系统管理员",
                invitation_code="TEACHER01",
                is_admin=True,
                status="approved"
            )
            db.session.add(admin_user)
            db.session.commit()
            print("✅ 已创建默认管理员账号: admin / admin123")
        else:
            print("管理员账号已存在")

        # 已有题目就不重复插入
        if Challenge.query.count() > 0:
            print("题目已存在，跳过插入")
            return

        # ✅ 关键：与你的模型字段一致（没有 difficulty / file_url，只有 file_path）
        challenges = [
            Challenge(title="MISC签到1", category="MISC", description="解压附件找Flag", points=100,
                      flag="flag{misc1_welcome}", file_path="misc1.zip"),
            Challenge(title="MISC签到2", category="MISC", description="分析附件内容", points=100,
                      flag="flag{misc2_easy}", file_path="misc2.zip"),
            Challenge(title="流量分析1", category="流量分析", description="分析流量包找信息", points=150,
                      flag="flag{ll1_pcap}", file_path="ll1.zip"),
            Challenge(title="逆向入门1", category="REVERSE", description="分析二进制文件", points=200,
                      flag="flag{re1_reverse}", file_path="re1.zip"),
        ]

        db.session.add_all(challenges)
        db.session.commit()
        print(f"✅ 初始化完成：已插入 {len(challenges)} 道题目")

if __name__ == "__main__":
    init_database()
