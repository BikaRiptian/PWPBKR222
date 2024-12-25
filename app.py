from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os

load_dotenv()  # Memuat variabel lingkungan dari file .env

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    role = db.Column(db.String(50), nullable=False, default='user')
    password = db.Column(db.String(150), nullable=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, role=role, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('dashboard.html', users=users)

@app.route('/add', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, role=role, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except:
            flash('Error adding user. Username or email might already exist.', 'danger')

    return render_template('add_user.html')

@app.route('/delete/<int:id>')
def delete_user(id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    user_to_delete = User.query.get_or_404(id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except:
        flash('Error deleting user.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update_user(id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get_or_404(id)

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']

        if username:
            user.username = username
        if email:
            user.email = email
        if role:
            user.role = role
        if password:
            user.password = generate_password_hash(password, method='sha256')

        try:
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except:
            flash('Error updating user.', 'danger')

    return render_template('update.html', user=user)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
