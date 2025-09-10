from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from waitress import serve
import sqlite3, os

app = Flask(__name__)
app.secret_key = 'kwetu_secret_key'
DB_NAME = 'factures.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            role TEXT
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS factures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            mois TEXT,
            statut TEXT,
            message TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Création de l’admin si inexistant
    cur.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        hashed_password = generate_password_hash("adminpass")
        cur.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                    ("admin", "kwetu@gmail.com", hashed_password, "admin"))
        conn.commit()

    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        role = 'user'
        try:
            conn = sqlite3.connect(DB_NAME)
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                        (username, email, hashed_password, role))
            conn.commit()
            conn.close()
            return redirect('/login')
        except:
            error = "Ce nom est déjà utilisé."
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("SELECT id, password, role FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2]
            return redirect('/admin' if user[2] == 'admin' else f'/dashboard/{username}')
        else:
            error = "Identifiants incorrects."
    return render_template('login.html', error=error)

@app.route('/dashboard/<username>')
def dashboard(username):
    if 'username' not in session or session['username'] != username:
        return redirect('/login')
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT mois, statut, message FROM factures WHERE user_id=?", (session['user_id'],))
    factures = cur.fetchall()
    conn.close()
    return render_template('dashboard.html', username=username, factures=factures)
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'role' not in session or session['role'] != 'admin':
        return redirect('/login')
    
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE role='user'")
    users = cur.fetchall()

    if request.method == 'POST':
        user_id = request.form['user_id']
        mois = request.form['mois']
        statut = request.form['statut']
        message = request.form['message']
        cur.execute("INSERT INTO factures (user_id, mois, statut, message) VALUES (?, ?, ?, ?)",
                    (user_id, mois, statut, message))
        conn.commit()

    cur.execute('''
        SELECT users.username, mois, statut, message FROM factures
        JOIN users ON factures.user_id = users.id
    ''')
    all_factures = cur.fetchall()
    conn.close()
    
    return render_template('admin.html', users=users, all_factures=all_factures)
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
