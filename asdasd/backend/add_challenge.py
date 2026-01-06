import sys
sys.path.insert(0, '.')
from app import app, db, Challenge

def add_challenge(title, desc, category, points, flag, file_path=None):
    with app.app_context():
        c = Challenge(
            title=title,
            description=desc,
            category=category,
            points=points,
            flag=flag,
            file_path=file_path
        )
        db.session.add(c)
        db.session.commit()
        print(f"✅ 添加成功: {title}")

if __name__ == "__main__":
    add_challenge(
        title="新MISC题",
        desc="这是一道新的MISC题目",
        category="MISC",
        points=150,
        flag="flag{new_challenge}",
        file_path="new.zip"
    )