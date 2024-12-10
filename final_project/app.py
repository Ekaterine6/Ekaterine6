from flask import Flask, render_template, flash, url_for, request, redirect, session, jsonify
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

# i will need this to make sure the user is looged in before letting them see the homepage and actually use the website
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


# pages of my website

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/exterior')
def exterior():
    return render_template('exterior.html')

@app.route('/furniture')
def furniture():
    return render_template('furniture.html')

@app.route('/newin')
def newin():
    return render_template('newin.html')

@app.route('/wallpapers')
def wallpapers():
    return render_template('wallpapers.html')

@app.route('/wordrobe')
def wordrobe():
    return render_template('wordrobe.html')

@app.route('/outdoor')
def outdoor():
    return render_template('outdoor.html')

@app.route('/tools')
def tools():
    return render_template('tools.html')

@app.route('/home')
def home():
    return render_template('home.html')

# Logging the user in 
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

# registering the user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get("username")
        if not username:
            return helpers.error("provide username", 400)
        
        password = request.form.get("password")
        if not password:
            return helpers.error("provide password", 400)
        
        confirmation = request.form.get("confirmation")
        if not confirmation:
            return helpers.error("provide confirmation", 400)
        
        join_date = datetime.now().strftime('%Y-%m-%d') #--ai taught me what Converting a datetime object to a string is
        
        if password != confirmation:
            return helpers.error("password and confirmation dont match", 400)
        
        conn = get_db_connection() 
        cursor = conn.cursor()
        yes_user = cursor.execute('SELECT * FROM users WHERE username = :username',(username,)).fetchone()
        if yes_user:
          conn.close()
          return helpers.error("Username already exists.", 400)
        
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, hash, join_date) VALUES (?, ?, ?)', (username, hashed_password, join_date))
        conn.commit()

        user_id = cursor.execute('SELECT id  FROM users WHERE username = :username', (username,)).fetchone()['id']
        conn.close()
        
        session['user_id'] = user_id
        return redirect(url_for('index'))
    
    return render_template('register.html')

# logging the user out
@app.route('/logout') 
@login_required
def logout(): 
    """Log user out""" 
    # forgetting the user id 
    session.clear() 
    
    return render_template('login.html')


# used internet help to create a flask route for ajax request beacse i didn't know how
@app.route('/adding_items_ajax', methods=['POST'])
@login_required
def adding_items_ajax():
    data = request.get_json()
    product = data['item']
    price = data['amount']
    user_id = session["user_id"]
    timestamp = datetime.now()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO transactions (user_id, item, amount, timestamp) VALUES(?, ?, ?, ?)', 
            (user_id, product, price, timestamp))
    conn.commit()
    conn.close()
    return jsonify(success=True)

# adding items to the cart
@app.route('/cart') 
@login_required
def cart(): 
    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cart_items = cursor.execute('SELECT item, amount FROM transactions WHERE user_id = ? AND purchased IS NULL', (user_id,)).fetchall()
    conn.close()
    return render_template('cart.html', cart_items=cart_items)

# settings where the user can change their password
@app.route('/settings') 
@login_required
def settings(): 
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
    

# profile where the user can customize their bio and see the date they logged in
@app.route('/profile')
@login_required
def profile():
    """user profile"""
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, bio, join_date FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    # i dont know how to let every user choose a picture for their profile so i set a default one
    default_profile_picture = "https://i.pinimg.com/236x/98/be/a8/98bea856261a0d6923f67c09232acec3.jpg"
    
    return render_template('profile.html', user=user, default_profile_picture=default_profile_picture)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """edit profile"""
    user_id = session['user_id']
    if request.method == 'POST':
        bio = request.form['bio']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user_id))
        conn.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    conn = get_db_connection() 
    cursor = conn.cursor() 
    cursor.execute("SELECT username, bio, join_date FROM users WHERE id = ?", (user_id,)) 
    user = cursor.fetchone() 
    conn.close() 
    return render_template('edit_profile.html', user=user)


# here the user can see all the information about their purchased item , the price the date ...
@app.route('/history') 
@login_required
def history(): 
    """history of transactions"""
    user_id = session['user_id']
    conn = get_db_connection() 
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, item, amount, timestamp FROM transactions WHERE user_id = ?", (user_id,))
    transactions_sql = cursor.fetchall()
    conn.close()

    return render_template('history.html', transactions=transactions_sql)


if __name__ == "__main__":
    app.run(debug=True)