from flask import Flask, render_template, flash, url_for, request, redirect, session
from werkzeug.security import check_password_hash, generate_password_hash
from final_project import helpers
from functools import wraps
from datetime import datetime
import sqlite3

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.secret_key = 'twothousand'
def get_db_connection():
    connection = sqlite3.connect("instance/database.db")
    connection.row_factory = sqlite3.Row
    return connection


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


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/homepage')
def homepage():
    return render_template('homepage.html')

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

@app.route('/logout') 
@login_required
def logout(): 
    """Log user out""" 
    # forgetting the user id 
    session.clear() 
    
    return render_template('login.html')

@app.route('/cart') 
@login_required
def cart(): 
    return render_template('cart.html')

@app.route('/sell') 
@login_required
def sell(): 
    return render_template('sell.html')

@app.route('/settings') 
@login_required
def settings(): 
    if request.method == "POST":
        # handling settings form submission
        # extract settings values from the form
        # Save the new settings to the database
        # db = get_db()
        # db.execute("UPDATE settings SET value = ? WHERE key = ?", (new_setting_value, "setting_key")
        # db.commit
        flash("Settings updated successfully")
        return redirect("/settings")
    else:
        return render_template('settings.html')
    

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        # getting cureent password
        user_id = session["user_id"]
        # verify current password
        current_password = request.form.get("current_password")
        if not current_password:
            return helpers.error("must provide password", 403)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        current = cursor.execute("SELECT hash FROM users WHERE id = ?", (user_id,)).fetchone()
        
        if not check_password_hash(current["hash"], current_password):
            conn.close()
            return helpers.error("wrong current password", 403)

        # validate new password and confirmatio
        new_password = request.form.get("new_password")
        if not new_password:
            conn.close()
            return helpers.error("must provide a new password", 403)

        # update passwords in th edatabase
        confirmation_password = request.form.get("confirmation_password")
        if not confirmation_password:
            conn.close()
            return helpers.error("must provide confirmation", 403)

        # checking new pass and confirmation match
        if new_password != confirmation_password:
            return helpers.error("passwords do not match")

        # Hash the password before saving it
        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET hash = ? WHERE id = ?",
                   (hashed_password, user_id))
        conn.commit()
        conn.close()

        flash("Password changed sucessfully!")
        return redirect("settings")
    else:
        return render_template("change_password.html")

@app.route('/history') 
@login_required
def history(): 
    """history of transactions"""
    user_id = session['user_id']
    conn = get_db_connection() 
    cursor = conn.cursor()
    user_id = cursor.execute("SELECT item, amount, purchased, timestamp, date FROM transactions WHERE user_id = ?", (user_id,))
    transactions_sql = cursor.fetchall()
    conn.close()

    return render_template('history.html', transactions=transactions_sql)


if __name__ == "__main__":
    app.run(debug=True)