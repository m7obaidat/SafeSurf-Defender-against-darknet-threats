from flask import render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from app import app, db
from models import User
from datetime import datetime, timedelta

def is_localhost():
    return request.remote_addr in ['127.0.0.1', 'localhost']

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin'))
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = False

        if is_localhost():
            is_admin = request.form.get('is_admin') == 'on'
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    show_admin_option = is_localhost()
    return render_template('register.html', show_admin_option=show_admin_option)

@app.route('/dashboard')
@login_required
def dashboard():
    total_users = User.query.count()
    return render_template('dashboard.html', total_users=total_users)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin or not is_localhost():
        flash('Access denied. Admin privileges required and must be accessed from localhost.')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/traffic-data')
@login_required
def get_traffic_data():
    try:
        # Assuming your NoSQL data looks something like this:
        # { timestamp: ISODate("..."), visits: number }
        traffic_data = db.traffic.find({
            'timestamp': {
                '$gte': datetime.now() - timedelta(days=7)  # Last 7 days
            }
        }).sort('timestamp', 1)  # Sort by timestamp ascending

        data = {
            'labels': [],
            'values': []
        }

        for record in traffic_data:
            data['labels'].append(record['timestamp'].strftime('%Y-%m-%d %H:%M'))
            data['values'].append(record['visits'])

        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 