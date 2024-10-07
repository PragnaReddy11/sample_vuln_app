import os
from flask import Flask, request, redirect, send_from_directory, render_template, url_for, jsonify
import sqlite3
import python_jwt as jwt 
import datetime
from jwcrypto import jwk

app = Flask(__name__)

# Directory to store uploaded files
UPLOAD_FOLDER = './uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = jwk.JWK.generate(kty='RSA', size=2048)

# Hardcoded secret (bad practice)
ADMIN_PASSWORD = "admin"  # Vulnerability: Hardcoded secret for admin login

# Persistent SQLite connection (rather than in-memory)
def get_db_connection():
    conn = sqlite3.connect('users.db')  # This creates a persistent SQLite database file
    return conn

# Initialize the database and insert initial users
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin')")
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('user1', 'password123')")  # Vulnerability: Weak credentials
    conn.commit()
    conn.close()

init_db()  # Initialize the database when the app starts

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Vulnerability: Hardcoded admin secret
    if password == ADMIN_PASSWORD:
        return render_template('welcome.html', username="Admin")

    # Vulnerability: SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"  # Unsafe query

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(query)  # Vulnerability: SQL Injection - user input directly into the query
        user = c.fetchone()
        conn.close()
        if user:
            return render_template('welcome.html', username=username)
        else:
            return "Invalid credentials"
    except sqlite3.Error as e:
        return f"An error occurred: {e}"

# Vulnerable JWT token generation
@app.route('/test', methods=['GET'])
def test():
    # Vulnerability: Sensitive data exposed in JWT
    username = request.args.get('username')
    password = request.args.get('password')
    if username and password:
        token = jwt.generate_jwt({
            'user': username,
            'role': 'admin',  # Vulnerability: Role escalation
        }, app.config['SECRET_KEY'], 'RS256', datetime.timedelta(minutes=5))
        return jsonify({'token': token})
    
    return 'Could not verify', 401

# Vulnerability: JWT decoding with role escalation
@app.route('/protected', methods=['GET'])
def protected():
    token = request.args.get('token')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    try:
        header, claims = jwt.verify_jwt(token, app.config['SECRET_KEY'], ['RS256'])  # Vulnerability: Token manipulation
        return jsonify({'header': header, 'claims': claims})
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 403

# File upload functionality
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    filename = file.filename
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return f'File {filename} uploaded successfully!'

# Vulnerability: Command Injection
@app.route('/run', methods=['GET'])
def run_command():
    command = request.args.get('command')
    os.system(command)  # Vulnerability: Command injection
    return f"Executed: {command}"

# Vulnerable search functionality with command injection
@app.route('/search', methods=['POST'])
def search():
    query = request.form['query']

    # Vulnerability: Directory traversal
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], query)

    # Vulnerability: File exposure
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                file_content = f.read()
            return f"Search Results:<br><pre>{file_content}</pre>"
        except Exception as e:
            return f"Error reading file: {str(e)}"
    else:
        return "File not found"

# Vulnerability: XSS when rendering files without sanitization
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    # Set host to 0.0.0.0 to make the app externally accessible on your local network
    app.run(debug=True, host='0.0.0.0', port=5001)
