#!/usr/bin/env python3
import os
import sqlite3
import datetime
import logging
from flask import Flask, request, jsonify, render_template, g, redirect, url_for, session, flash, send_file
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['DATABASE'] = os.path.join(app.root_path, 'payzone.db')
app.config['SECRET_KEY'] = 'your_secret_key_here'  # CHANGE THIS for production!

# Configure logging (the log file will be created in the same directory as this script)
logging.basicConfig(
    filename='payzone.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()
    # Create tables if they do not exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS puzzles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            box_number TEXT UNIQUE NOT NULL,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            solved INTEGER DEFAULT 0,
            solved_by TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_name TEXT UNIQUE NOT NULL,
            score INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shopkeepers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            team_name TEXT
        )
    ''')
    db.commit()

def add_sample_data():
    db = get_db()
    cursor = db.cursor()
    # Sample puzzles
    puzzles = [
        ('BOX001', 'What is 2+2?', '4'),
        ('BOX002', 'Name the capital of France.', 'Paris'),
        ('BOX003', 'What color do you get by mixing red and white?', 'Pink'),
        ('BOX004', 'How many days are there in a week?', '7'),
        ('BOX005', 'What is the opposite of cold?', 'Hot'),
    ]
    for box_number, question, answer in puzzles:
        try:
            cursor.execute(
                'INSERT INTO puzzles (box_number, question, answer) VALUES (?, ?, ?)',
                (box_number, question, answer)
            )
        except sqlite3.IntegrityError:
            # Puzzle already exists
            pass

    # Teams: Only "Team A" and "Team B" (admin is not a team)
    teams = ['Team A', 'Team B']
    for team in teams:
        try:
            cursor.execute(
                'INSERT INTO teams (team_name, score) VALUES (?, ?)',
                (team, 0)
            )
        except sqlite3.IntegrityError:
            pass

    # Shopkeepers: shopkeeperA (Team A), shopkeeperB (Team B), and admin (no team)
    shopkeepers = [
        ('shopkeeperA', 'passwordA', 'Team A'),
        ('shopkeeperB', 'passwordB', 'Team B'),
        ('admin', 'adminpassword', None)
    ]
    for username, password, team in shopkeepers:
        password_hash = generate_password_hash(password)
        try:
            cursor.execute(
                'INSERT INTO shopkeepers (username, password_hash, team_name) VALUES (?, ?, ?)',
                (username, password_hash, team)
            )
        except sqlite3.IntegrityError:
            pass

    db.commit()

# --- Session-based authentication decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
         if 'username' not in session:
             flash("Please log in first.")
             return redirect(url_for('login'))
         return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
         if 'username' not in session or session.get('username') != 'admin':
              flash("Admin access required.")
              return redirect(url_for('login'))
         return f(*args, **kwargs)
    return decorated_function

# --- Login and logout routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
         username = request.form.get('username')
         password = request.form.get('password')
         db = get_db()
         cursor = db.cursor()
         cursor.execute('SELECT password_hash FROM shopkeepers WHERE username = ?', (username,))
         row = cursor.fetchone()
         if row and check_password_hash(row['password_hash'], password):
              session['username'] = username
              flash("Logged in successfully.")
              return redirect(url_for('home'))
         else:
              flash("Invalid credentials.")
              return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Logged out.")
    return redirect(url_for('login'))

# --- Home page (default after login) ---
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# --- Shopkeeper puzzle interface ---
@app.route('/')
@login_required
def index():
    # Prevent admin from accessing the puzzle interface
    if session.get('username') == 'admin':
        flash("Admin cannot access the puzzle interface.")
        return redirect(url_for('home'))
    return render_template('index.html')

# --- Public display page (no login required) ---
@app.route('/display')
def display():
    return render_template('display.html')

# --- Team settings page (for both shopkeepers and admin) ---
@app.route('/team-settings', methods=['GET', 'POST'])
@login_required
def team_settings():
    db = get_db()
    cursor = db.cursor()
    username = session.get('username')
    if username == 'admin':
        # Admin view: list all teams with options to change names
        cursor.execute("SELECT * FROM teams")
        teams = cursor.fetchall()
        return render_template('team_settings_admin.html', teams=teams)
    else:
        # Shopkeeper view: show their own team name
        cursor.execute("SELECT team_name FROM shopkeepers WHERE username = ?", (username,))
        row = cursor.fetchone()
        current_team = row['team_name'] if row and row['team_name'] else ""
        return render_template('team_settings.html', current_team=current_team)

@app.route('/team-settings/update', methods=['POST'])
@login_required
def update_team_settings():
    db = get_db()
    cursor = db.cursor()
    username = session.get('username')
    new_team_name = request.form.get('team_name').strip()
    if username == 'admin':
        # Admin update: expects old_team_name and new team name
        old_team_name = request.form.get('old_team_name').strip()
        try:
            cursor.execute("UPDATE teams SET team_name = ? WHERE team_name = ?", (new_team_name, old_team_name))
            db.commit()
            flash("Team name updated from {} to {}.".format(old_team_name, new_team_name))
        except Exception:
            flash("Error updating team name.")
        return redirect(url_for('team_settings'))
    else:
        # Shopkeeper update: update shopkeepers table and teams table if applicable
        cursor.execute("SELECT team_name FROM shopkeepers WHERE username = ?", (username,))
        row = cursor.fetchone()
        old_team = row['team_name'] if row and row['team_name'] else ""
        try:
            cursor.execute("UPDATE shopkeepers SET team_name = ? WHERE username = ?", (new_team_name, username))
            if old_team:
                cursor.execute("UPDATE teams SET team_name = ? WHERE team_name = ?", (new_team_name, old_team))
            else:
                cursor.execute("INSERT INTO teams (team_name, score) VALUES (?, ?)", (new_team_name, 0))
            db.commit()
            flash("Your team name has been updated.")
        except Exception:
            flash("Error updating your team name.")
        return redirect(url_for('team_settings'))

# --- Puzzle submission endpoint ---
@app.route('/api/puzzle/<box_number>', methods=['GET'])
@login_required
def get_puzzle(box_number):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM puzzles WHERE box_number = ?', (box_number,))
    puzzle = cursor.fetchone()
    if not puzzle:
        return jsonify({'error': 'Puzzle not found'}), 404
    if puzzle['solved']:
        return jsonify({'error': 'Puzzle already solved'}), 400
    return jsonify({
        'box_number': puzzle['box_number'],
        'question': puzzle['question'],
        'start_time': datetime.datetime.utcnow().isoformat() + 'Z',
        'duration': 90
    })

@app.route('/api/submit', methods=['POST'])
@login_required
def submit_answer():
    if session.get('username') == 'admin':
        return jsonify({'error': 'Admin cannot submit puzzle answers'}), 400
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON data'}), 400
    box_number = data.get('box_number')
    answer = data.get('answer')
    if not box_number or not answer:
        return jsonify({'error': 'Missing box_number or answer'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM puzzles WHERE box_number = ?', (box_number,))
    puzzle = cursor.fetchone()
    if not puzzle:
        return jsonify({'error': 'Puzzle not found'}), 404
    if puzzle['solved']:
        return jsonify({'error': 'Puzzle has already been attempted'}), 400

    correct_answer = puzzle['answer'].strip().lower()
    submitted_answer = answer.strip().lower()
    result = (submitted_answer == correct_answer)

    username = session.get('username')
    cursor.execute('SELECT team_name FROM shopkeepers WHERE username = ?', (username,))
    shopkeeper = cursor.fetchone()
    team_name = shopkeeper['team_name'] if shopkeeper and shopkeeper['team_name'] else None
    if team_name:
        cursor.execute('UPDATE puzzles SET solved = 1, solved_by = ? WHERE box_number = ?', (team_name, box_number))
        if result:
            cursor.execute('UPDATE teams SET score = score + 1 WHERE team_name = ?', (team_name,))
            logging.info("Team {} solved puzzle {}.".format(team_name, box_number))
        else:
            logging.info("Team {} attempted puzzle {} but answer was incorrect.".format(team_name, box_number))
    else:
        cursor.execute('UPDATE puzzles SET solved = 1 WHERE box_number = ?', (box_number,))
    db.commit()

    return jsonify({'result': result, 'team': team_name})

@app.route('/api/scoreboard', methods=['GET'])
@login_required
def scoreboard():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT team_name, score FROM teams')
    teams = cursor.fetchall()
    scoreboard = [{'team_name': row['team_name'], 'score': row['score']} for row in teams]
    return jsonify(scoreboard)

# --- Public scoreboard endpoint (for display page) ---
@app.route('/api/public/scoreboard', methods=['GET'])
def public_scoreboard():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT team_name, score FROM teams')
    teams = cursor.fetchall()
    scoreboard = [{'team_name': row['team_name'], 'score': row['score']} for row in teams]
    return jsonify(scoreboard)

@app.route('/api/sync', methods=['POST'])
@login_required
def sync_submissions():
    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({'error': 'Invalid data format, expected a list'}), 400
    results = []
    for submission in data:
        box_number = submission.get('box_number')
        answer = submission.get('answer')
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM puzzles WHERE box_number = ?', (box_number,))
        puzzle = cursor.fetchone()
        if not puzzle or puzzle['solved']:
            results.append({'box_number': box_number, 'status': 'skipped'})
            continue

        correct_answer = puzzle['answer'].strip().lower()
        submitted_answer = answer.strip().lower()
        result = (submitted_answer == correct_answer)

        username = session.get('username')
        cursor.execute('SELECT team_name FROM shopkeepers WHERE username = ?', (username,))
        shopkeeper = cursor.fetchone()
        team_name = shopkeeper['team_name'] if shopkeeper and shopkeeper['team_name'] else None
        if team_name:
            cursor.execute('UPDATE puzzles SET solved = 1, solved_by = ? WHERE box_number = ?', (team_name, box_number))
            if result:
                cursor.execute('UPDATE teams SET score = score + 1 WHERE team_name = ?', (team_name,))
                logging.info("Team {} solved puzzle {} via sync.".format(team_name, box_number))
            else:
                logging.info("Team {} attempted puzzle {} via sync but answer was incorrect.".format(team_name, box_number))
        else:
            cursor.execute('UPDATE puzzles SET solved = 1 WHERE box_number = ?', (box_number,))
        db.commit()
        results.append({'box_number': box_number, 'status': 'submitted', 'result': result})
    return jsonify(results)

# --- Admin endpoints for puzzles management ---
@app.route('/admin/puzzle_list', methods=['GET'])
@login_required
@admin_required
def puzzle_list():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM puzzles')
    puzzles = cursor.fetchall()
    puzzles_list = [dict(p) for p in puzzles]
    return jsonify(puzzles_list)

@app.route('/admin/delete-puzzle', methods=['POST'])
@login_required
@admin_required
def delete_puzzle():
    data = request.get_json()
    box_number = data.get('box_number')
    if not box_number:
        return jsonify({'error': 'Missing box_number'}), 400
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM puzzles WHERE box_number = ?', (box_number,))
    db.commit()
    logging.info("Puzzle {} deleted by admin.".format(box_number))
    return jsonify({'message': "Puzzle {} deleted.".format(box_number)})

@app.route('/admin/edit-puzzle', methods=['POST'])
@login_required
@admin_required
def edit_puzzle():
    data = request.get_json()
    box_number = data.get('box_number')
    new_question = data.get('question')
    new_answer = data.get('answer')
    if not box_number or not new_question or not new_answer:
        return jsonify({'error': 'Missing fields'}), 400
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE puzzles SET question = ?, answer = ? WHERE box_number = ?', (new_question, new_answer, box_number))
    db.commit()
    logging.info("Puzzle {} edited by admin.".format(box_number))
    return jsonify({'message': 'Puzzle updated successfully.'})
  
@app.route('/admin/add-puzzle', methods=['POST'])
@login_required
@admin_required
def add_puzzle():
    data = request.get_json()
    box_number = data.get('box_number')
    question = data.get('question')
    answer = data.get('answer')
    
    # Check if any required field is missing
    if not box_number or not question or not answer:
        return jsonify({'error': 'Missing box_number, question, or answer'}), 400

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            'INSERT INTO puzzles (box_number, question, answer) VALUES (?, ?, ?)',
            (box_number, question, answer)
        )
        db.commit()
        logging.info("Puzzle {} added.".format(box_number))
        return jsonify({'message': 'Puzzle added successfully.'})
    except sqlite3.IntegrityError as e:
        logging.error("Integrity error adding puzzle: {}".format(e))
        return jsonify({'error': 'Puzzle already exists or integrity error occurred.'}), 400
    except Exception as e:
        logging.error("Error adding puzzle: {}".format(e))
        return jsonify({'error': 'Error adding puzzle.'}), 500

# --- Endpoint to reset the game (admin only) ---
@app.route('/admin/reset', methods=['POST'])
@login_required
@admin_required
def admin_reset():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE puzzles SET solved = 0, solved_by = NULL")
    cursor.execute("UPDATE teams SET score = 0")
    db.commit()
    logging.info("Game reset by admin.")
    return jsonify({'message': 'Game has been reset.'})

# --- Logs download endpoint for admin ---
@app.route('/admin/logs', methods=['GET'])
@login_required
@admin_required
def admin_logs():
    log_file = os.path.join(app.root_path, 'payzone.log')
    if os.path.exists(log_file):
        return send_file(log_file, as_attachment=True)
    else:
        return jsonify({'error': 'Log file not found.'}), 404

# --- Admin dashboard ---
@app.route('/admin', endpoint='admin')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin.html')

if __name__ == '__main__':
    # Initialize the database and add sample data if the database file does not exist.
    if not os.path.exists(app.config['DATABASE']):
        with app.app_context():
            init_db()
            add_sample_data()
    # Run the application on all available interfaces on port 5000.
    # (On a Raspberry Pi, you can access the app via http://<your_pi_ip>:5000/)
    app.run(host="0.0.0.0", port=5000, debug=True)
