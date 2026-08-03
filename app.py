from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import requests
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "gizli_acar_soz_real_layihe"

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def log_action(username, action):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO logs (username, action, timestamp) VALUES (?, ?, ?)", (username, action, time_now))
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error_msg = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            log_action(username, "Registered new account")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error_msg = "This username already exists!"
            
    return render_template('register.html', error=error_msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error_msg = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[0], password):
            session['user'] = username
            log_action(username, "Logged in successfully")
            return redirect(url_for('dashboard'))
        else:
            error_msg = "Invalid username or password!"
            
    return render_template('login.html', error=error_msg)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user'])

@app.route('/scanner', methods=['GET', 'POST'])
def scanner():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    result = None
    target_url = None
    
    if request.method == 'POST':
        target_url = request.form.get('url')
        if not target_url.startswith('http'):
            target_url = 'https://' + target_url
            
        try:
            response = requests.get(target_url, timeout=5)
            status = response.status_code
            
            headers = response.headers
            security_headers = {
                "X-Frame-Options": headers.get("X-Frame-Options", "Not found (Potential vulnerability)"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not found"),
                "Server": headers.get("Server", "Unknown")
            }
            
            result = {
                "status": status,
                "secure": target_url.startswith("https"),
                "headers": security_headers
            }
            log_action(session['user'], f"Scanned URL: {target_url}")
        except Exception as e:
            result = {"error": "Could not connect to the website or invalid URL!"}
            
    return render_template('scanner.html', username=session['user'], result=result, url=target_url)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = session['user']
    success_msg = ""
    error_msg = ""
    
    if request.method == 'POST':
        new_username = request.form.get('username')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (current_user,))
        user_data = cursor.fetchone()
        
        if user_data and check_password_hash(user_data[1], old_password):
            try:
                if new_username and new_username != current_user:
                    cursor.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_data[0]))
                    session['user'] = new_username
                    log_action(new_username, "Changed username")
                    current_user = new_username
                
                if new_password:
                    hashed_new_password = generate_password_hash(new_password)
                    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_new_password, user_data[0]))
                    log_action(current_user, "Updated account password")
                
                conn.commit()
                success_msg = "Your information was successfully updated!"
            except sqlite3.IntegrityError:
                error_msg = "This username is already taken!"
        else:
            error_msg = "You entered your current password incorrectly!"
            
        conn.close()
        
    return render_template('profile.html', username=current_user, success=success_msg, error=error_msg)

@app.route('/logs')
def logs():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, action, timestamp FROM logs ORDER BY id DESC")
    all_logs = cursor.fetchall()
    conn.close()
    
    return render_template('logs.html', username=session['user'], logs=all_logs)

@app.route('/logout')
def logout():
    if 'user' in session:
        log_action(session['user'], "Logged out of system")
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
