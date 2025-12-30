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
                real_name='系统管理员',
                invitation_code='TEACHER01',
                is_admin=True,
                status='approved',
            )
            db.session.add(admin)
            print("创建管理员账号: admin / admin123")
        else:
            print("管理员账号已存在")

        if Challenge.query.count() == 0:
            samples = [
                Challenge(
                    title='MISC签到1',
                    category='MISC',
                    description='解压附件找Flag',
                    points=100,
                    flag='flag{misc1_welcome}',
                    file_path='/static/misc1.zip',
                ),
                Challenge(
                    title='MISC签到2',
                    category='MISC',
                    description='分析附件内容',
                    points=100,
                    flag='flag{misc2_easy}',
                    file_path='/static/misc2.zip',
                ),
                Challenge(
                    title='MISC进阶',
                    category='MISC',
                    description='这道题稍微难一点',
                    points=200,
                    flag='flag{misc3_medium}',
                    file_path='/static/misc3.zip',
                ),
                Challenge(
                    title='流量分析1',
                    category='流量分析',
                    description='分析流量包找信息',
                    points=150,
                    flag='flag{ll1_pcap}',
                    file_path='/static/ll1.zip',
                ),
                Challenge(
                    title='流量分析2',
                    category='流量分析',
                    description='更复杂的流量分析',
                    points=200,
                    flag='flag{ll2_pcap}',
                    file_path='/static/ll2.zip',
                ),
                Challenge(
                    title='逆向入门1',
                    category='REVERSE',
                    description='分析二进制文件',
                    points=200,
                    flag='flag{re1_reverse}',
                    file_path='/static/re1.zip',
                ),
                Challenge(
                    title='逆向入门2',
                    category='REVERSE',
                    description='分析更复杂的程序',
                    points=250,
                    flag='flag{re2_reverse}',
                    file_path='/static/re2.zip',
                ),
                Challenge(
                    title='逆向进阶',
                    category='REVERSE',
                    description='高难度逆向题',
                    points=300,
                    flag='flag{re3_hard}',
                    file_path='/static/re3.zip',
                ),
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
