# -*- coding: utf-8 -*-
from app import app, init_database

# uWSGI 方式不会走 __main__，这里确保初始化
init_database()

application = app
