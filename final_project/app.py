import os

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, error
import sqlite3

# Configuring application
app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# function Connecting to an SQLite database used microsoft copilot for some usage help as i couldn't connect sqlite3 by myself
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('fashion_butik.db')
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# learned this from finance problem set
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def homepage():
    """Showing the homepage/products"""
    return render_template("homepage.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """register the user"""
    session.clear()
    
    if request.method == "POST":
        if not request.form.get("username"):
            return error("provide username", 400)
        # checking if the username already exists
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username"),))
        rows = cursor.fetchall()
        if len(rows) > 0:
            return error("username already exists")
        
        if not request.form.get("password"):
            return error("provide password", 400)
        
        if not request.form.get("confirmation"):
            return error("provide confirmation", 400)
        
        if request.form.get("password") != request.form.get("confirmation"):
            return error("password and confirmation do not match", 400)
        
        # hashing the password
        hashed_pasword = generate_password_hash(request.form.get("password"))

        cursor.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   request.form.get("username"), hashed_pasword)
        db.commit()
        db.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username"),))
        rows = cursor.fetchall()
        session["user_id"] = rows[0]["id"]

        return redirect("/")
    else:
        return render_template("register.html")

        

@app.route("/login", methods=["GET", "POST"])
def login():
    """logging the user in"""
    # forgeting any user_id
    session.clear()

    # if reached via POST 
    if request.method == "POST":
        # subitting the username
        if not request.form.get("username"):
            return error("provide username", 403)
        # making sure the password was submitted
        elif not request.form.get("password"):
            return error("provide password", 403)
        
        #query database for username
        db = get_db
        cursor = db.cursor
        cursor.execute(
            "SELECT * FROM users WHERE username = ?", (request.form.get("username"),)
        )
        rows = cursor.fetchall()
        # checking the correctness of the epassword and the existance of the username
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return error("invalid username or password", 403)
        
        # remembering the user that logged in 
        session["user_id"] = rows[0]["id"]

        # redirecting the user to the homepage 
        return redirect("/")
    else:
        return render_template("login.html")

if __name__ == '__main__':
    app.run(debug=True)