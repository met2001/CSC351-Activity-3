import os
import sqlite3
from flask import Flask, request, g, session, redirect, url_for, render_template, flash, send_file, abort
from werkzeug.utils import secure_filename, safe_join
from io import BytesIO
import secrets
import html

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Fixed with more secure token

DATABASE = "lostfound.db"
UPLOAD_FOLDER = "./uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}  # Only extensions allowed
MAX_FILE_SIZE = 20 * 1024 * 1024    # 20MB limit for files

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Authentication service
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()    # Stripping whitespace
        pwd = request.form.get('password', '').strip()      # Stripping whitespace

        db = get_db()
        cur = db.cursor()
        query = "SELECT username, role FROM users WHERE username = ? AND password = ?"   # User input is not sanitized before being added to the query (use parameterized query)
        cur.execute(query, (uname, pwd))
        row = cur.fetchone()
        if row:
            session['user'] = row[0]
            session['role'] = row[1]
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))

# Lost item service (regular users)
@app.route('/lost')
def lost_list():
    if 'user' in session:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, owner, title, description, image, resolved FROM lost_items")
        items = cur.fetchall()
        return render_template('lost_list.html', items=items, user=session.get('user'), role=session.get('role'))
    return render_template('login.html')

@app.route('/lost/new', methods=['GET', 'POST'])
def lost_new():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form.get('title', '')
        desc = request.form.get('description', '')
        image = request.files.get('image')
        filename = None

        if image:
            image.seek(0,2)
            size = image.tell()
            image.seek(0)
            if allowed_file(image.filename) and size <= MAX_FILE_SIZE:   # Changed to check file size and extension
                
                filename = secure_filename(image.filename)   # Fixed improper sanitization
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(path)
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO lost_items (owner, title, description, image) VALUES (?,?,?,?)", (session['user'], html.escape(title), html.escape(desc), filename))   # SQL Injection fixed
        db.commit()
        return redirect(url_for('lost_list'))
    return render_template('lost_new.html')

@app.route('/lost/resolve/<int:item_id>')
def lost_resolve(item_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE lost_items SET resolved = 1 WHERE id = ?", (item_id,)) # SQL injection fixed
    db.commit()
    return redirect(url_for('lost_list'))

# Found item service (staff only)
@app.route('/found')
def found_list():
    if session['role'] == 'staff':
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, posted_by, title, description, image, returned FROM found_items")
        items = cur.fetchall()
        return render_template('found_list.html', items=items, user=session.get('user'), role=session.get('role'))
    return redirect(url_for('index'))   # If the user is not a staff user then they are redirected to the index page

@app.route('/found/new', methods=['GET', 'POST'])
def found_new():
    if session.get('role') != 'staff':
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form.get('title', '')
        desc = request.form.get('description', '')
        image = request.files.get('image')
        filename = None
        if image:
            image.seek(0,2)
            size = image.tell()
            image.seek(0)
            if allowed_file(image.filename) and size <= MAX_FILE_SIZE:
                filename = secure_filename(image.filename)  # Added secure filename  
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(path)
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO found_items (posted_by, title, description, image) VALUES (?,?,?,?)", (session['user'], title, desc, filename))    # SQL injection fixed
        db.commit()
        return redirect(url_for('found_list'))
    return render_template('found_new.html')

@app.route('/found/return/<int:item_id>')
def found_return(item_id):
    if session.get('role') != 'staff':
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    cur.execute(f"UPDATE found_items SET returned = 1 WHERE id = ?", (item_id,))    # Fixed SQL Injection
    db.commit()
    return redirect(url_for('found_list'))

# Search service
@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user' not in session:
        return redirect(url_for('login'))
    results = []
    q = ''
    if request.method == 'POST':
        q = request.form.get('q', '')
        q = html.escape(q)
        db = get_db()
        cur = db.cursor()
        sql = f"SELECT id, title, description FROM found_items WHERE description LIKE ? OR title LIKE ?"
        cur.execute(sql, (f'%{q}%', f'%{q}%'))
        results = cur.fetchall()
    return render_template('search.html', results=results, q=q)

# File access
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    file_path = safe_join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        abort(404)
    return send_file(file_path, as_attachment=False)

if __name__ == '__main__':
    app.run(debug=True)
