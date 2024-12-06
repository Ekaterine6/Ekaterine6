from flask import Flask, render_template, url_for, request, redirect, session
from werkzeug.security import check_password_hash, generate_password_hash
from final_project import helpers
from datetime import datetime
import sqlite3

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.secret_key = 'twothousand'
def get_db_connection():
    connection = sqlite3.connect("instance/database.db")
    connection.row_factory = sqlite3.Row
    return connection


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
        
        conn = get_db_connection() 
        cursor = conn.cursor()
        user = cursor.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
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
        
        if password != confirmation:
            return helpers.error("password and confirmation dont match", 400)
        
        conn = get_db_connection() 
        cursor = conn.cursor()
        yes_user = cursor.execute('SELECT * FROM users WHERE username = :username',(username,)).fetchone()
        if yes_user:
          conn.close()
          return helpers.error("Username already exists.", 400)
        
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, hash) VALUES (?, ?)', (username, hashed_password))
        conn.commit()

        user_id = cursor.execute('SELECT id  FROM users WHERE username = :username', (username,)).fetchone()['id']
        conn.close()
        
        session['user_id'] = user_id
        return redirect(url_for('index'))
    
    return render_template('register.html')


if __name__ == "__main__":
    app.run(debug=True)