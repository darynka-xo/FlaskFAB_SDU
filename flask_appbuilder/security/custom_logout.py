from flask_login import logout_user
from flask import request, redirect
from .sqla.models import LoginUserLog
import datetime


def custom_logout_user(user, appbuilder, ps = False):
    login_log = LoginUserLog(user_id=user.id, addr=request.remote_addr)
    if ps:
        login_log.reason = f"Пользователь {user.username} вышел из системы. Причина: Параллельная сесия."
        login_log.status = "logout"
    else:        
        login_log.status = "logout"
        login_log.reason = f"Пользователь {user.username} вышел из системы."
    appbuilder.session.add(login_log)
    appbuilder.session.commit()
    logout_user()


def session_expired_log(user_id, appbuilder, remote_addr):
    login_log = LoginUserLog(user_id=user_id, addr=remote_addr)
    login_log.status = "session expired"
    login_log.reason = f"Отсутствует или просрочена сессия. ID пользователя - {user_id}"
    appbuilder.session.add(login_log)
    appbuilder.session.commit()