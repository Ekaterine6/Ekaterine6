from flask import Flask, render_template, url_for, request, redirect, session
from werkzeug.security import check_password_hash, generate_password_hash
from final_project import app, db
from final_project import helpers
from datetime import datetime
from sqlalchemy import text

import sqlite3

app.secret_key = 'twothousand'


@app.route('/')
def index():
    return render_template('index.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    """logging the user in"""
    if request.method == "POST":
        # subitting the username
        username = request.form.get("username")
        if not username:
            return helpers.error("provide username", 400)
        # making sure the password was submitted
        password = request.form.get("password")
        if not password:
            return helpers.error("provide password", 400)
        user = db.session.execute(text('SELECT * FROM users WHERE username = :username'), {'username': username}).fetchone()
        
        if user and check_password_hash(user['hash'], password):
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        else:
            return helpers.error('wrong password or username, try again', 400)
 
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get("username")
        print(f"Username: {username}")
        if not username:
            return helpers.error("provide username", 400)
        
        password = request.form.get("password")
        print(f"Password: {password}")
        if not password:
            return helpers.error("provide password", 400)
        
        confirmation = request.form.get("confirmation")
        print(f"Confirmation: {confirmation}")
        if not confirmation:
            return helpers.error("provide confirmation", 400)
        yes_user = db.session.execute(text('SELECT * FROM users WHERE username = :username'), {'username': username}).fetchone()
        if yes_user:
          return helpers.error("Username already exists.", 400)
        
        hashed_password = generate_password_hash(password)
        db.session.execute(text('INSERT INTO users (username, hash) VALUES (:username, :hash)'), {'username': username, 'hash': hashed_password})
        
        user_id = db.session.execute(text('SELECT id  FROM users WHERE username = :username'), {'username': username}).fetchone()[0]
        session['user_id'] = yes_user['id']
        return redirect(url_for('index'))
    
    return render_template('register.html')


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)