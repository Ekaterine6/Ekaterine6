import os

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, error

# importing sql for database
import sqlite3

# Configuring application
app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False

# Connecting to an SQLite database 
conn = sqlite3.connect('fashion_butik.db')

# Create a cursor object to interact with the database
cursor = conn.cursor()

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
def index():
    """Show portfolio of bought furniture"""
    return render_template("index.html",)

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

# Insert a record 
cursor.execute('INSERT INTO users (username, hash, cash) VALUES (?, ?, ?)', ('JohnDoe', 'hash_value', 1000)) 
# Commit the transaction 
conn.commit()

