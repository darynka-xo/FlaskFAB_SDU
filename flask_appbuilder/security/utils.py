from random import SystemRandom
import flask_login
from flask import current_app, session
import string
from os import urandom

LETTERS_AND_DIGITS = string.ascii_letters + string.digits


def generate_random_string(length=30):
    rand = SystemRandom()
    return "".join(rand.choice(LETTERS_AND_DIGITS) for _ in range(length))


def login_user(user, remember=False, duration=None, force=False, fresh=True):
    """
    Logins user as Flask-login, but set last session unique to user.
    It is used in functionality of preventing parallel sessions.
    """

    is_logged_success = flask_login.login_user(user, remember=remember, duration=duration, force=force, fresh=fresh)
    if is_logged_success:
        # Generate new session token
        user.last_session_unique = session.get("_id", "")+urandom(4).hex()
        session['session_unique'] = user.last_session_unique
        current_app.appbuilder.session.add(user)
        current_app.appbuilder.session.commit()

        # Session should be permanent, cuz it should be able to use PERMANENT_SESSION_LIFETIME
        session.permanent = True


