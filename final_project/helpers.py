# Inspired by cs50 finance problem set to use Flask decorators
import requests

from flask import redirect, render_template, session
from functools import wraps

def login_required(f):
    """ Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/

    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def error(message, code=400):
    """render error message to the user"""
    return render_template("error.html", top=code, bottom=message), code
