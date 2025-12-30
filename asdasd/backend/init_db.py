from app import app, db, User, Challenge
from werkzeug.security import generate_password_hash


def init_database():
    with app.app_context():
        print("正在创建数据库表...")
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin123'),
                email='admin@sdhgctf.com',
                is_admin=True
            )
            db.session.add(admin)
            print("创建管理员账号: admin / admin123")
        else:
            print("管理员账号已存在")

        if Challenge.query.count() == 0:
            samples = [
                Challenge(title='MISC签到1', category='MISC', description='解压附件找Flag', points=100,
                          difficulty='Easy', flag='flag{misc1_welcome}', file_url='/download/misc1.zip'),
                Challenge(title='MISC签到2', category='MISC', description='分析附件内容', points=100, difficulty='Easy',
                          flag='flag{misc2_easy}', file_url='/download/misc2.zip'),
                Challenge(title='MISC进阶', category='MISC', description='这道题稍微难一点', points=200,
                          difficulty='Medium', flag='flag{misc3_medium}', file_url='/download/misc3.zip'),
                Challenge(title='流量分析1', category='流量分析', description='分析流量包找信息', points=150,
                          difficulty='Medium', flag='flag{ll1_pcap}', file_url='/download/ll1.zip'),
                Challenge(title='流量分析2', category='流量分析', description='更复杂的流量分析', points=200,
                          difficulty='Medium', flag='flag{ll2_pcap}', file_url='/download/ll2.zip'),
                Challenge(title='逆向入门1', category='REVERSE', description='分析二进制文件', points=200,
                          difficulty='Medium', flag='flag{re1_reverse}', file_url='/download/re1.zip'),
                Challenge(title='逆向入门2', category='REVERSE', description='分析更复杂的程序', points=250,
                          difficulty='Medium', flag='flag{re2_reverse}', file_url='/download/re2.zip'),
                Challenge(title='逆向进阶', category='REVERSE', description='高难度逆向题', points=300,
                          difficulty='Hard', flag='flag{re3_hard}', file_url='/download/re3.zip'),
            ]
            db.session.add_all(samples)
            print("创建 {} 道示例题目".format(len(samples)))
        else:
            print("题目已存在，跳过创建")

        db.session.commit()
        print("数据库初始化完成！")
        print("用户数量:", User.query.count())
        print("题目数量:", Challenge.query.count())


if __name__ == '__main__':
    init_database()