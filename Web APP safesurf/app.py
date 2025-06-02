import os
import json
import uuid
import redis
import boto3
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
from flask import jsonify
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.tree import DecisionTreeClassifier
from imblearn.over_sampling import SMOTE
import joblib
from fpdf import FPDF
import io
from PIL import Image, ImageDraw
import matplotlib
# Force matplotlib to not use any Xwindows backend
matplotlib.use('Agg', force=True)
import matplotlib.pyplot as plt
# Disable interactive mode
plt.ioff()

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Config
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or str(uuid.uuid4())
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Redis Connection Handler
class RedisHandler:
    def __init__(self, host, port, username, password, max_retries=3, retry_delay=5):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._redis = None
        self._pubsub = None
        self.connected = False
        self.should_stop = False

    def connect(self):
        for attempt in range(self.max_retries):
            try:
                if self._redis is None:
                    self._redis = redis.Redis(
                        host=self.host,
                        port=self.port,
                        username=self.username,
                        password=self.password,
                        decode_responses=True,
                        socket_timeout=5,
                        socket_connect_timeout=5
                    )
                self._redis.ping()
                self.connected = True
                print(f"Redis connected successfully on attempt {attempt + 1}")
                return True
            except (redis.ConnectionError, redis.TimeoutError) as e:
                print(f"Redis connection attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                self._redis = None
        return False

    def get(self, key):
        try:
            if not self.connected and not self.connect():
                return None
            return self._redis.get(key)
        except Exception as e:
            print(f"Redis get error: {str(e)}")
            self.connected = False
            return None

    def set(self, key, value):
        try:
            if not self.connected and not self.connect():
                return False
            return self._redis.set(key, value)
        except Exception as e:
            print(f"Redis set error: {str(e)}")
            self.connected = False
            return False

    def start_pubsub(self):
        def pubsub_listener():
            while not self.should_stop:
                try:
                    if not self.connected and not self.connect():
                        print("Redis not connected. Retrying in 5 seconds...")
                        time.sleep(5)
                        continue

                    if self._pubsub is None:
                        self._pubsub = self._redis.pubsub()
                        self._pubsub.subscribe('traffic_updates')

                    message = self._pubsub.get_message(timeout=1)
                    if message and message['type'] == 'message':
                        try:
                            flow_data = json.loads(message['data'])
                            self.handle_traffic_update(flow_data)
                        except json.JSONDecodeError as e:
                            print(f"Error decoding message: {str(e)}")
                            continue

                except (redis.ConnectionError, redis.TimeoutError) as e:
                    print(f"Redis pubsub error: {str(e)}")
                    self.connected = False
                    self._pubsub = None
                    time.sleep(5)
                except Exception as e:
                    print(f"Unexpected error in pubsub listener: {str(e)}")
                    time.sleep(5)

        thread = threading.Thread(target=pubsub_listener, daemon=True)
        thread.start()
        return thread

    def handle_traffic_update(self, flow_data):
        try:
            # Fetch current stats from the JSON file
            stats = load_or_initialize_stats()

            # Update stats based on incoming data
            label = flow_data.get("Label", "Unknown")
            label_2 = flow_data.get("Label_2", "")

            if label == "Darknet":
                stats['darknet_count'] += 1
            else:
                stats['normal_count'] += 1

            if label_2 in stats['layer2_counters']:
                stats['layer2_counters'][label_2] += 1

            # Manage flow history
            if len(stats['flows']) > 500000:
                stats['flows'] = []

            # Append the flow data
            stats['flows'].append({
                "src": flow_data.get("Src IP", "Unknown"),
                "dst": flow_data.get("Dst IP", "Unknown"),
                "timestamp": flow_data.get("Timestamp", "Unknown"),
                "srcP": flow_data.get('Src Port', "Unknown"),
                "dstP": flow_data.get('Dst Port', "Unknown"),
                "label": label,
                "label_2": label_2,
                "label_3": flow_data.get("Label_3", "Unknown")
            })

            # Save updated stats
            with open('traffic_stats.json', 'w') as f:
                json.dump(stats, f)

            # Emit update to connected clients
            socketio.emit('traffic_update', {
                "normal_count": stats['normal_count'],
                "darknet_count": stats['darknet_count'],
                "total_traffic": stats['normal_count'] + stats['darknet_count'],
                "layer2_counters": stats['layer2_counters'],
                **flow_data
            })

        except Exception as e:
            print(f"Error handling traffic update: {str(e)}")

    def stop(self):
        self.should_stop = True
        if self._pubsub:
            try:
                self._pubsub.unsubscribe()
                self._pubsub.close()
            except:
                pass
        if self._redis:
            try:
                self._redis.close()
            except:
                pass

# Initialize Redis handler
redis_handler = RedisHandler(
    host='<Redis IP>',
    port=<port>,
    username='username',
    password='password'
)

# AWS Configuration
aws_access_key = 'aws_access_key'
aws_secret_key = 'aws_secret_key'
topic_arn = 'topic_arn'

# Initialize SNS client
sns_client = boto3.client(
    'sns',
    region_name='us-east-1',
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key
)

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None
        }

# ML Model Status
class MLModel(db.Model):
    __tablename__ = 'ml_models'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    model_path = db.Column(db.String(200), nullable=False)
    accuracy = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    metrics = db.Column(db.Text)  # Store classification report as JSON

# Create tables and initialize admin user
def check_and_update_schema():
    with app.app_context():
        inspector = db.inspect(db.engine)
        
        # Check User table columns
        if 'users' in inspector.get_table_names():
            existing_columns = {column['name'] for column in inspector.get_columns('users')}
            required_columns = {'id', 'username', 'email', 'password_hash', 'is_admin', 'created_at', 'last_login'}
            
            if not required_columns.issubset(existing_columns):
                print("Updating database schema - missing columns:", required_columns - existing_columns)
                # Create backup of users table
                users_backup = User.query.all()
                db.session.close()
                
                # Recreate tables with new schema
                db.drop_all()
                db.create_all()
                
                # Restore users from backup
                for user in users_backup:
                    db.session.add(user)
                try:
                    db.session.commit()
                    print("Database schema updated successfully!")
                except Exception as e:
                    print(f"Error updating database schema: {e}")
                    db.session.rollback()
            else:
                print("Database schema is up to date")

def init_db():
    with app.app_context():
        # Check if database exists and has required tables
        inspector = db.inspect(db.engine)
        existing_tables = inspector.get_table_names()
        required_tables = {'users', 'ml_models'}
        
        if not required_tables.issubset(existing_tables):
            print("Initializing database - missing tables:", required_tables - set(existing_tables))
            # Create all tables
            db.create_all()
            
            # Check if admin user exists
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                print("Creating admin user")
                admin = User(
                    username='admin',
                    email='admin@safesurf.com',
                    is_admin=True,
                    created_at=datetime.utcnow()
                )
                admin.set_password('admin')
                db.session.add(admin)
                
                try:
                    db.session.commit()
                    print("Admin user created successfully!")
                except Exception as e:
                    print(f"Error creating admin user: {e}")
                    db.session.rollback()
        else:
            print("Database already initialized with all required tables")

# Initialize and update database
init_db()
check_and_update_schema()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

def is_localhost():
    return request.remote_addr in ['127.0.0.1', '::1']

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Update last login time
            user.last_login = datetime.utcnow()
            try:
                db.session.commit()
                login_user(user)
                return redirect(url_for('admin' if user.is_admin else 'dashboard'))
            except Exception as e:
                db.session.rollback()
                flash('Error updating login time')
        flash('Invalid username or password')
    return render_template('login.html')

def check_password_policy(password):
    """
    Check if password meets security requirements:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets requirements"

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not current_user.is_admin:
        flash('Access denied. Only administrators can create new accounts.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        # Validate password
        is_valid, message = check_password_policy(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('register'))

        try:
            user = User(username=username, email=email, is_admin=is_admin)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'error')
            return redirect(url_for('register'))

    return render_template('register.html', show_admin_option=True)

@app.route('/dashboard')
@login_required
def dashboard():
    stats = load_or_initialize_stats()  # Fetch the stats from the JSON file
    return render_template('dashboard.html',
                           normal_count=stats['normal_count'],
                           darknet_count=stats['darknet_count'],
                           Tor=stats['layer2_counters']['Tor'],
                           VPN=stats['layer2_counters']['VPN'],
                           I2P=stats['layer2_counters']['I2P'],
                           Freenet=stats['layer2_counters']['Freenet'],
                           Zeronet=stats['layer2_counters']['Zeronet'],
                           )

@app.route("/log")
@login_required
def log():
    return render_template("log.html")

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin.html', users=users, now=datetime.utcnow())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/whitelist', methods=['GET', 'POST'])
@login_required
def whitelist():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        description = request.form.get('description')
        expiry_date = request.form.get('expiry_date')

        raw_data = redis_handler.get('whitelist')
        if raw_data is None:
            # Initialize a new dictionary
            Prive_data = {
                ip_address: {
                    'description': description,
                    'expiry_date': expiry_date
                }
            }
        else:
            # Load existing data and update
            try:
                Prive_data = json.loads(raw_data)
                Prive_data[ip_address] = {
                    'description': description,
                    'expiry_date': expiry_date
                }
            except json.JSONDecodeError:
                return jsonify({'success': False, 'message': 'Error parsing whitelist data'})

        # Save back to Redis
        if redis_handler.set('whitelist', json.dumps(Prive_data)):
            return jsonify({'success': True, 'message': 'IP address successfully added to whitelist!'})
        return jsonify({'success': False, 'message': 'Failed to save to Redis'})

    return render_template('whitelist.html')

@app.route('/view_whitelist')
@login_required
def view_whitelist():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
        
    whitelist_data = redis_handler.get('whitelist')
    whitelist_entries = []
    
    if whitelist_data:
        try:
            whitelist_dict = json.loads(whitelist_data)
            for ip, data in whitelist_dict.items():
                entry = data.copy()
                entry['ip_address'] = ip
                whitelist_entries.append(entry)
        except json.JSONDecodeError:
            flash('Error loading whitelist data')
    
    return render_template('whitelist.html', whitelist_entries=whitelist_entries, show_table=True)

@app.route('/blacklist', methods=['GET', 'POST'])
@login_required
def blacklist():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    block_icmp = False
    raw_data = redis_handler.get('blacklist')
    if raw_data:
        try:
            blacklist_data = json.loads(raw_data)
            block_icmp = blacklist_data.get('block_icmp', False)
        except Exception:
            blacklist_data = {'ips': {}, 'ports': {}, 'block_icmp': False}
    else:
        blacklist_data = {'ips': {}, 'ports': {}, 'block_icmp': False}

    if request.method == 'POST':
        entry_type = request.form.get('entry_type')  # 'ip' or 'port'
        value = request.form.get('value')
        description = request.form.get('description')
        expiry_date = request.form.get('expiry_date')

        # Add entry to appropriate section
        if entry_type == 'ip':
            blacklist_data['ips'][value] = {
                'description': description,
                'expiry_date': expiry_date,
                'added_date': datetime.now().isoformat()
            }
        else:  # port
            blacklist_data['ports'][value] = {
                'description': description,
                'expiry_date': expiry_date,
                'added_date': datetime.now().isoformat()
            }

        # Save back to Redis
        redis_handler.set('blacklist', json.dumps(blacklist_data))
        
        # Log the addition
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': entry_type,
            'value': value,
            'action': 'added',
            'description': description,
            'user': current_user.username
        }
        blacklist_logs = json.loads(redis_handler.get('blacklist_logs') or '[]')
        blacklist_logs.append(log_entry)
        redis_handler.set('blacklist_logs', json.dumps(blacklist_logs))
        
        return jsonify({'success': True, 'message': f'{entry_type.capitalize()} successfully added to blacklist!'})

    return render_template('blacklist.html', block_icmp=block_icmp)

@app.route('/view_blacklist')
@login_required
def view_blacklist():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    blacklist_data = redis_handler.get('blacklist')
    ip_entries = []
    port_entries = []
    block_icmp = False
    if blacklist_data:
        try:
            blacklist_dict = json.loads(blacklist_data)
            block_icmp = blacklist_dict.get('block_icmp', False)
            # Process IP entries
            for ip, data in blacklist_dict.get('ips', {}).items():
                entry = data.copy()
                entry['value'] = ip
                entry['type'] = 'IP'
                ip_entries.append(entry)
            # Process Port entries
            for port, data in blacklist_dict.get('ports', {}).items():
                entry = data.copy()
                entry['value'] = port
                entry['type'] = 'Port'
                port_entries.append(entry)
        except json.JSONDecodeError:
            flash('Error loading blacklist data')
    return render_template('blacklist.html', 
                         ip_entries=ip_entries, 
                         port_entries=port_entries, 
                         show_table=True,
                         block_icmp=block_icmp,
                         now=datetime.now().strftime('%Y-%m-%d'))

@app.route('/delete_blacklist/<entry_type>/<value>', methods=['POST'])
@login_required
def delete_blacklist(entry_type, value):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'})
    
    try:
        # Get current blacklist
        blacklist_data = redis_handler.get('blacklist')
        if blacklist_data:
            blacklist = json.loads(blacklist_data)
            
            # Remove the entry if it exists
            section = 'ips' if entry_type == 'ip' else 'ports'
            if value in blacklist[section]:
                description = blacklist[section][value].get('description', '')
                del blacklist[section][value]
                # Save updated blacklist back to Redis
                redis_handler.set('blacklist', json.dumps(blacklist))
                
                # Log the deletion
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'type': entry_type,
                    'value': value,
                    'action': 'removed',
                    'description': description,
                    'user': current_user.username
                }
                blacklist_logs = json.loads(redis_handler.get('blacklist_logs') or '[]')
                blacklist_logs.append(log_entry)
                redis_handler.set('blacklist_logs', json.dumps(blacklist_logs))
                
                return jsonify({'success': True, 'message': f'{entry_type.upper()} {value} removed from blacklist'})
            else:
                return jsonify({'success': False, 'message': f'{entry_type.upper()} not found in blacklist'})
        else:
            return jsonify({'success': False, 'message': 'Blacklist is empty'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/view_blacklist_logs')
@login_required
def view_blacklist_logs():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    logs_data = redis_handler.get('blacklist_logs')
    logs = []
    
    if logs_data:
        try:
            logs = json.loads(logs_data)
            # Sort logs by timestamp, newest first
            logs.sort(key=lambda x: x['timestamp'], reverse=True)
        except json.JSONDecodeError:
            flash('Error loading blacklist logs')
    
    return render_template('blacklist_logs.html', logs=logs)

@app.route('/clear_blacklist_logs', methods=['POST'])
@login_required
def clear_blacklist_logs():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        redis_handler.set('blacklist_logs', '[]')
        return jsonify({'success': True, 'message': 'Blacklist logs cleared successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/blacklist/rules', methods=['GET'])
@login_required
def get_blacklist_rules():
    """Get all blacklist rules in JSON format"""
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
        
    try:
        blacklist_data = redis_handler.get('blacklist')
        if blacklist_data:
            blacklist = json.loads(blacklist_data)
            
            # Format the data for better readability
            formatted_rules = {
                'ip_rules': [],
                'port_rules': [],
                'icmp_policy': blacklist.get('block_icmp', False)
            }
            
            # Process IP rules
            for ip, data in blacklist.get('ips', {}).items():
                rule = {
                    'ip': ip,
                    'description': data.get('description', ''),
                    'added_date': data.get('added_date', ''),
                    'expiry_date': data.get('expiry_date', '')
                }
                formatted_rules['ip_rules'].append(rule)
            
            # Process Port rules
            for port, data in blacklist.get('ports', {}).items():
                rule = {
                    'port': port,
                    'description': data.get('description', ''),
                    'added_date': data.get('added_date', ''),
                    'expiry_date': data.get('expiry_date', '')
                }
                formatted_rules['port_rules'].append(rule)
            
            return jsonify(formatted_rules)
        else:
            return jsonify({
                'message': 'No blacklist rules found',
                'ip_rules': [],
                'port_rules': [],
                'icmp_policy': False
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.cli.command('show-blacklist')
def show_blacklist_cli():
    """Command line function to show all blacklist rules"""
    try:
        blacklist_data = redis_handler.get('blacklist')
        if blacklist_data:
            blacklist = json.loads(blacklist_data)
            
            print("\n=== Blacklisted IP Addresses ===")
            for ip, data in blacklist.get('ips', {}).items():
                print(f"\nIP: {ip}")
                print(f"Description: {data.get('description', 'N/A')}")
                print(f"Added Date: {data.get('added_date', 'N/A')}")
                print(f"Expiry Date: {data.get('expiry_date', 'N/A')}")
            
            print("\n=== Blacklisted Ports ===")
            for port, data in blacklist.get('ports', {}).items():
                print(f"\nPort: {port}")
                print(f"Description: {data.get('description', 'N/A')}")
                print(f"Added Date: {data.get('added_date', 'N/A')}")
                print(f"Expiry Date: {data.get('expiry_date', 'N/A')}")
        else:
            print("No blacklist rules found")
            
    except Exception as e:
        print(f"Error: {str(e)}")

@app.route('/send_mail', methods=['GET', 'POST'])
@login_required
def send_mail():
    if request.method == 'POST':
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        try:
            # Get current traffic stats
            stats = load_or_initialize_stats()
            
            # Append traffic stats to message
            message += f"\n\nTraffic Statistics:\n"
            message += f"Normal Traffic: {stats['normal_count']}\n"
            message += f"Darknet Traffic: {stats['darknet_count']}\n"
            message += f"Layer 2 Details:\n"
            for layer, count in stats['layer2_counters'].items():
                message += f"- {layer}: {count}\n"
            
            # Send email using SNS
            response = sns_client.publish(
                TopicArn=topic_arn,
                Subject=subject,
                Message=message
            )
            
            # Store the sent mail in Redis
            sent_mail = {
                'subject': subject,
                'sent_date': datetime.now().isoformat(),
                'status': 'Sent'
            }
            
            sent_mails = json.loads(redis_handler.get('sent_mails') or '[]')
            sent_mails.append(sent_mail)
            redis_handler.set('sent_mails', json.dumps(sent_mails))
            
            return jsonify({'success': True, 'message': 'Mail sent successfully!'})
            
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})
            
    return render_template('Send_mail.html')

@app.route('/view_sent_mails')
@login_required
def view_sent_mails():
    try:
        sent_mails = json.loads(redis_handler.get('sent_mails') or '[]')
        return render_template('Send_mail.html', sent_mails=sent_mails, show_table=True)
    except Exception as e:
        flash(f'Error loading sent mails: {str(e)}')
        return render_template('Send_mail.html', sent_mails=[], show_table=False)

@app.route('/clear_sent_mails', methods=['POST'])
@login_required
def clear_sent_mails():
    try:
        redis_handler.set('sent_mails', '[]')
        return jsonify({'success': True, 'message': 'Sent mails cleared successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/delete_whitelist/<ip>', methods=['POST'])
@login_required
def delete_whitelist(ip):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'})
    
    try:
        # Get current whitelist
        whitelist_data = redis_handler.get('whitelist')
        if whitelist_data:
            whitelist = json.loads(whitelist_data)
            
            # Remove the IP if it exists
            if ip in whitelist:
                del whitelist[ip]
                # Save updated whitelist back to Redis
                redis_handler.set('whitelist', json.dumps(whitelist))
                return jsonify({'success': True, 'message': f'IP {ip} removed from whitelist'})
            else:
                return jsonify({'success': False, 'message': 'IP not found in whitelist'})
        else:
            return jsonify({'success': False, 'message': 'Whitelist is empty'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# JSON Stats
def load_or_initialize_stats():
    stats_file = 'traffic_stats.json'
    
    if os.path.exists(stats_file):
        try:
            with open(stats_file, 'r') as f:
                data = f.read().strip()
                if not data:  # Check if the file is empty
                    raise ValueError("Empty JSON file")
                return json.loads(data)
        except (json.JSONDecodeError, ValueError) as e:
            # If there's a JSONDecodeError or an empty file, reset the stats
            print(f"Error reading JSON file: {e}. Initializing default stats.")
            return initialize_default_stats()
    else:
        return initialize_default_stats()

def initialize_default_stats():
    if os.path.exists('traffic_stats.json'):
        try:
            with open('traffic_stats.json', 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError):
            # If there's an error reading the file, create new stats
            pass
    
    stats = {
        'normal_count': 0,
        'darknet_count': 0,
        'layer2_counters': {
            "Tor": 0, "VPN": 0, "I2P": 0, "Freenet": 0, "Zeronet": 0
        },
        'flows': [],
        'unique_ips': 0,
        'suspicious_ips': 0,
        'total_threats': 0,
        'blocked_attempts': 0,
        'security_alerts': 0,
        'recent_incidents': 0,
        'high_priority_incidents': 0,
        'medium_priority_incidents': 0,
        'low_priority_incidents': 0
    }
    
    try:
        with open('traffic_stats.json', 'w') as f:
            json.dump(stats, f)
    except Exception as e:
        print(f"Error saving default stats: {str(e)}")
    
    return stats

@app.route('/test_redis')
def test_redis():
    if redis_handler.connect():
        return "Redis is connected successfully"
    return "Failed to connect to Redis"

@socketio.on('get_traffic_stats')
def handle_get_traffic_stats():
    stats = load_or_initialize_stats()  # Load the stats from the JSON file
    emit('traffic_update', {
         'normal_count': stats['normal_count'],
         'darknet_count': stats['darknet_count'],
         'total_traffic': stats['normal_count'] + stats['darknet_count'],
         'layer2_counters': stats['layer2_counters']
    })

@app.route('/get_all_logs')
@login_required
def get_all_logs():
    stats = load_or_initialize_stats()  # Fetch stats from the JSON file
    logs = stats.get('flows', [])
    return json.dumps(logs)  # Return the logs as JSON

@app.route('/ml/train', methods=['GET', 'POST'])
@login_required
def train_model():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            # Emit initial progress
            print("Starting training process...")  # Debug print
            socketio.emit('training_progress', {'message': 'Initializing training process...'}, namespace='/')
            
            # Initialize DataFrame for Redis data
            redis_df = None
            
            try:
                # Get all keys from Redis
                socketio.emit('training_progress', {'message': 'Checking Redis for new data...'}, namespace='/')
                all_keys = redis_handler.get('*')
                data = []
                
                # Get data from Redis
                for key in all_keys:
                    if redis_handler.type(key) == 'string':
                        try:
                            flow_data = json.loads(redis_handler.get(key))
                            flow_data = {key: value for key, value in flow_data.items() if key not in ['Label_2', 'Label_3']}
                            data.append(flow_data)
                        except json.JSONDecodeError:
                            continue
                
                if data:
                    print(f"Found {len(data)} records in Redis")  # Debug print
                    socketio.emit('training_progress', 
                                {'message': f'Converting {len(data)} Redis records to DataFrame...'}, 
                                namespace='/')
                    redis_df = pd.DataFrame(data)
            except Exception as redis_error:
                print(f"Redis error: {str(redis_error)}")  # Debug print
                socketio.emit('training_progress', 
                            {'message': 'Could not connect to Redis. Proceeding with existing dataset...'}, 
                            namespace='/')
            
            # Load existing dataset
            socketio.emit('training_progress', {'message': 'Loading existing dataset...'}, namespace='/')
            df = pd.read_csv('SafeSurf Dataset Layer 1.csv')
            initial_rows = len(df)
            
            # Combine with Redis data if available
            if redis_df is not None and not redis_df.empty:
                socketio.emit('training_progress', {'message': 'Combining Redis data with existing dataset...'}, namespace='/')
                df = pd.concat([df, redis_df], ignore_index=True)
                socketio.emit('training_progress', 
                            {'message': f'Combined dataset: {len(df)} records (Added {len(df) - initial_rows} new records)'}, 
                            namespace='/')
            else:
                socketio.emit('training_progress', 
                            {'message': f'Proceeding with existing dataset: {initial_rows} records'}, 
                            namespace='/')
            
            socketio.emit('training_progress', {'message': 'Preprocessing data...'}, namespace='/')
            
            # Data preprocessing
            df.dropna(axis=0, inplace=True)
            zeros = (df == 0).sum()
            rows = df.shape[0]
            columns_to_drop = df.columns[(df == 0).sum() == rows]
            df = df.drop(columns=columns_to_drop)
            
            socketio.emit('training_progress', {'message': 'Filtering IP addresses...'}, namespace='/')
            
            # Filter IPs and ports
            filter_ips = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '0.0.0.32']
            private_ips = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', 
                          '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', 
                          '172.28.', '172.29.', '172.30.', '172.31.']
            port_53 = 53
            
            df = df[~(
                (df['Label'] == 'Darknet') & (
                    ((df['Src IP'].isin(filter_ips)) | (df['Dst IP'].isin(filter_ips))) |
                    ((df['Src IP'].str.startswith(tuple(private_ips))) & (df['Dst IP'].str.startswith(tuple(private_ips)))) |
                    ((df['Src IP'] == '1.1.1.1') & (df['Dst IP'] == '1.1.1.1')) |
                    ((df['Src IP'] == '0.0.0.32') & (df['Dst IP'] == '0.0.0.32')) |
                    ((df['Dst Port'] == port_53))
                )
            )]
            
            socketio.emit('training_progress', {'message': 'Preparing features...'}, namespace='/')
            df.drop(columns=['Dst IP', 'Src IP', 'Timestamp'], axis=1, inplace=True)
            
            # Custom keys for Layer 1
            custom_keys_layer1 = ['Src Port', 'Fwd IAT Min', 'Fwd PSH Flags', 'Fwd Header Len',
                'Idle Max', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std',
                'FIN Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Pkt Size Avg',
                'Fwd Seg Size Avg', 'Bwd Pkts/b Avg', 'Init Fwd Win Byts',
                'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
                'Idle Mean', 'Idle Std', 'Fwd IAT Max', 'Fwd IAT Mean', 'Pkt Len Min',
                'Flow IAT Min', 'Dst Port', 'Flow Duration', 'Tot Fwd Pkts',
                'TotLen Fwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd IAT Tot',
                'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
                'Bwd Pkt Len Std', 'Fwd Pkt Len Mean', 'Idle Min', 'Flow IAT Max',
                'Flow IAT Mean', 'PSH Flag Cnt', 'Bwd IAT Tot', 'Pkt Len Var',
                'Bwd Seg Size Avg', 'Bwd Pkt Len Mean', 'ACK Flag Cnt', 'Protocol',
                'Bwd IAT Std', 'Flow IAT Std', 'Tot Bwd Pkts', 'Bwd Pkts/s',
                'SYN Flag Cnt', 'Bwd Header Len', 'RST Flag Cnt', 'TotLen Bwd Pkts',
                'Bwd IAT Max', 'Flow Pkts/s', 'Bwd IAT Min', 'Fwd Pkts/s', 'Active Max',
                'Active Mean', 'Fwd IAT Std', 'Active Std', 'Bwd Blk Rate Avg',
                'Fwd Pkts/b Avg', 'Active Min', 'Down/Up Ratio', 'Subflow Bwd Pkts',
                'Fwd Byts/b Avg', 'Bwd IAT Mean', 'Subflow Bwd Byts',
                'Subflow Fwd Pkts', 'Bwd Byts/b Avg', 'Subflow Fwd Byts', 'Flow Byts/s',
                'Fwd Blk Rate Avg','Label']
            
            # Ensure all required columns are present
            missing_cols = set(custom_keys_layer1) - set(df.columns)
            if missing_cols:
                for col in missing_cols:
                    df[col] = 0
            
            # Reorder columns to match custom_keys_layer1
            df = df[custom_keys_layer1]
            socketio.emit('training_progress', {'message': 'Preparing training data...'}, namespace='/')
            X = df.drop(columns=['Label'], axis=1)
            y = df['Label']
            
            socketio.emit('training_progress', {'message': 'Applying SMOTE for data balancing...'}, namespace='/')
            smote = SMOTE()
            X_resampled, y_resampled = smote.fit_resample(X, y)
            
            socketio.emit('training_progress', {'message': 'Splitting data...'}, namespace='/')
            X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, train_size=0.8, random_state=2)
            
            socketio.emit('training_progress', {'message': 'Training model...'}, namespace='/')
            dt = DecisionTreeClassifier()
            dt.fit(X_train, y_train)
            
            socketio.emit('training_progress', {'message': 'Evaluating model...'}, namespace='/')
            y_pred = dt.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred, output_dict=True)
            
            socketio.emit('training_progress', {'message': 'Saving model...'}, namespace='/')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            model_path = f'temp_model_{timestamp}.pkl'
            joblib.dump(dt, model_path)
            
            ml_model = MLModel(
                model_path=model_path,
                accuracy=accuracy,
                metrics=json.dumps(report, indent=2)
            )
            db.session.add(ml_model)
            db.session.commit()
            
            socketio.emit('training_complete', {
                'message': f'Training complete! Accuracy: {accuracy:.2f}',
                'redirect': url_for('ml_dashboard')
            }, namespace='/')
            
            return jsonify({'success': True})
            
        except Exception as e:
            print(f"Training error: {str(e)}")  # Debug print
            socketio.emit('training_error', {'error': str(e)}, namespace='/')
            return jsonify({'error': str(e)})
    
    return render_template('ml_train.html')

@app.route('/ml/dashboard')
@login_required
def ml_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    models = MLModel.query.order_by(MLModel.timestamp.desc()).all()
    # Parse metrics JSON for each model
    for model in models:
        try:
            model.metrics_dict = json.loads(model.metrics) if model.metrics else {}
        except Exception:
            model.metrics_dict = {}
    return render_template('ml_dashboard.html', models=models)

@app.route('/ml/approve/<int:model_id>')
@login_required
def approve_model(model_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    model = MLModel.query.get_or_404(model_id)
    
    if model.status == 'pending':
        try:
            # Create models directory if it doesn't exist
            if not os.path.exists('models'):
                os.makedirs('models')
            
            # If there's an existing approved model, archive it
            new_path = 'decision_tree_model_layer1.pkl'
            if os.path.exists(new_path):
                # Generate archive name with timestamp
                archive_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                archive_path = os.path.join('models', f'archived_model_{archive_timestamp}.pkl')
                os.rename(new_path, archive_path)
                print(f"Archived previous model to: {archive_path}")
            
            # Move the new model to the main location
            os.rename(model.model_path, new_path)
            
            # Update model status
            model.status = 'approved'
            model.model_path = new_path
            db.session.commit()
            
            flash('Model approved and deployed successfully! Previous model has been archived.')
        except Exception as e:
            flash(f'Error approving model: {str(e)}')
    
    return redirect(url_for('ml_dashboard'))

@app.route('/ml/reject/<int:model_id>')
@login_required
def reject_model(model_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    model = MLModel.query.get_or_404(model_id)
    
    if model.status == 'pending':
        try:
            # Delete the temporary model file
            if os.path.exists(model.model_path):
                os.remove(model.model_path)
            
            # Update model status
            model.status = 'rejected'
            db.session.commit()
            
            flash('Model rejected and deleted successfully!')
        except Exception as e:
            flash(f'Error rejecting model: {str(e)}')
    
    return redirect(url_for('ml_dashboard'))

@app.route('/ml/download/<int:model_id>')
@login_required
def download_model(model_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    model = MLModel.query.get_or_404(model_id)
    
    if os.path.exists(model.model_path):
        return send_file(
            model.model_path,
            as_attachment=True,
            download_name=f'model_{model_id}.pkl'
        )
    
    flash('Model file not found!')
    return redirect(url_for('ml_dashboard'))

@app.route('/ml/archived_models')
@login_required
def archived_models():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    # Get list of archived models
    archived_models = []
    if os.path.exists('models'):
        for file in os.listdir('models'):
            if file.startswith('archived_model_') and file.endswith('.pkl'):
                # Extract timestamp from filename
                timestamp_str = file.replace('archived_model_', '').replace('.pkl', '')
                try:
                    timestamp = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                    archived_models.append({
                        'filename': file,
                        'timestamp': timestamp,
                        'path': os.path.join('models', file)
                    })
                except ValueError:
                    continue
    
    # Sort by timestamp, newest first
    archived_models.sort(key=lambda x: x['timestamp'], reverse=True)
    return render_template('archived_models.html', models=archived_models)

@app.route('/ml/download_archived/<path:filename>')
@login_required
def download_archived_model(filename):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    # Ensure the filename is safe and within the models directory
    if '..' in filename or filename.startswith('/'):
        flash('Invalid file path!')
        return redirect(url_for('archived_models'))
    
    file_path = os.path.join('models', os.path.basename(filename))
    if os.path.exists(file_path) and file_path.endswith('.pkl'):
        return send_file(
            file_path,
            as_attachment=True,
            download_name=os.path.basename(filename)
        )
    
    flash('Model file not found!')
    return redirect(url_for('archived_models'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    user = User.query.get_or_404(user_id)
    
    # Prevent self-deletion
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot delete your own account'})
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    user = User.query.get_or_404(user_id)
    data = request.json
    
    try:
        if 'username' in data:
            # Check if username is taken by another user
            existing_user = User.query.filter_by(username=data['username']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'success': False, 'message': 'Username already taken'})
            user.username = data['username']
            
        if 'email' in data:
            # Check if email is taken by another user
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'success': False, 'message': 'Email already taken'})
            user.email = data['email']
            
        if 'password' in data and data['password']:
            user.set_password(data['password'])
            
        if 'is_admin' in data:
            # Prevent removing admin status from self
            if user.id == current_user.id and not data['is_admin']:
                return jsonify({'success': False, 'message': 'Cannot remove your own admin status'})
            user.is_admin = data['is_admin']
            
        db.session.commit()
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        data = request.json
        user = User.query.get(current_user.id)
        
        # Check if username is changed and available
        if data['username'] != user.username:
            if User.query.filter_by(username=data['username']).first():
                return jsonify({'success': False, 'message': 'Username already taken'})
            user.username = data['username']
        
        # Check if email is changed and available
        if data['email'] != user.email:
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'success': False, 'message': 'Email already taken'})
            user.email = data['email']
        
        # Update password if provided
        if data['password']:
            # Validate new password
            is_valid, message = check_password_policy(data['password'])
            if not is_valid:
                return jsonify({'success': False, 'message': message})
            user.set_password(data['password'])
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Profile updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

class PDF(FPDF):
    def __init__(self):
        super().__init__()
        # Define colors
        self.dark_bg = (33, 37, 41)  # Dark background color
        self.text_white = (255, 255, 255)  # White text
        self.text_gray = (173, 181, 189)  # Gray text
        self.accent_red = (235, 22, 22)  # Red accent color
        # Set font family to Arial Unicode MS or fallback to Arial
        self.add_font('CustomFont', '', 'arial.ttf', uni=True)
        
    def header(self):
        # Set dark background
        self.set_fill_color(*self.dark_bg)
        self.rect(0, 0, 220, 297, 'F')  # Fill entire page with dark background
        
        # Add title
        self.set_font('Arial', 'B', 14)  # Normal font size
        self.set_text_color(*self.accent_red)
        self.cell(0, 10, 'SafeSurf Report', 0, 1, 'L')
        
        # Add separator line
        self.set_draw_color(*self.accent_red)
        self.line(10, 20, 200, 20)
        
        # Add generation date
        self.set_font('Arial', 'I', 10)
        self.set_text_color(*self.text_gray)
        self.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'R')
        
        # Line break
        self.ln(10)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Add separator line
        self.set_draw_color(*self.accent_red)
        self.line(10, self.get_y(), 200, self.get_y())
        # Page number
        self.set_font('Arial', 'I', 8)
        self.set_text_color(*self.text_gray)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

    def chapter_title(self, title):
        # Add stylish chapter title
        self.set_font('Arial', 'B', 16)
        self.set_text_color(*self.accent_red)
        # Add red accent bar
        self.set_fill_color(*self.accent_red)
        self.rect(10, self.get_y(), 3, 10, 'F')
        # Add title text
        self.set_x(15)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(4)

    def chapter_body(self, content):
        self.set_text_color(*self.text_white)
        self.set_font('Arial', '', 12)
        self.multi_cell(0, 10, content)
        self.ln()

    def add_stat_box(self, title, value, x, y, w=40, h=20):
        # Save current position
        original_y = self.get_y()
        original_x = self.get_x()
        
        # Draw stat box
        self.set_xy(x, y)
        self.set_fill_color(*self.dark_bg)
        self.set_draw_color(*self.accent_red)
        self.rect(x, y, w, h, 'DF')
        
        # Add title
        self.set_xy(x, y + 2)
        self.set_font('Arial', '', 8)
        self.set_text_color(*self.text_gray)
        self.cell(w, 8, title, 0, 1, 'C')
        
        # Add value
        self.set_xy(x, y + 10)
        self.set_font('Arial', 'B', 12)
        self.set_text_color(*self.text_white)
        self.cell(w, 8, str(value), 0, 1, 'C')
        
        # Restore position
        self.set_xy(original_x, original_y)

    def add_stats_section(self, stats, start_y):
        # Add statistics in a grid layout
        stats_layout = [
            ('Normal Traffic', stats['normal_count']),
            ('Darknet Traffic', stats['darknet_count']),
            ('Total Traffic', stats['normal_count'] + stats['darknet_count']),
            ('Threats', stats.get('total_threats', 0)),
            ('Alerts', stats.get('security_alerts', 0))
        ]
        
        x_start = 10
        y = start_y
        x_spacing = 45
        y_spacing = 25
        
        for i, (title, value) in enumerate(stats_layout):
            x = x_start + (i % 4) * x_spacing
            if i > 0 and i % 4 == 0:
                y += y_spacing
            self.add_stat_box(title, value, x, y)
        
        return y + y_spacing  # Return the Y position after the stats section


@app.route('/admin/generate_report', methods=['POST'])
@login_required
def generate_report():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403

    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        try:
            start_date = datetime.strptime(data['startDate'], '%Y-%m-%d')
            end_date = datetime.strptime(data['endDate'], '%Y-%m-%d')
        except (KeyError, ValueError) as e:
            return jsonify({'error': 'Invalid date format'}), 400

        if end_date < start_date:
            return jsonify({'error': 'End date must be after start date'}), 400

        # Create PDF
        pdf = PDF()
        pdf.alias_nb_pages()
        pdf.add_page()

        # Load stats once
        stats = load_or_initialize_stats()

        # Add date range info
        pdf.set_font('Arial', '', 12)
        pdf.set_text_color(*pdf.text_gray)
        pdf.cell(0, 10, f'Report Period: {start_date.strftime("%Y-%m-%d")} to {end_date.strftime("%Y-%m-%d")}', 0, 1)
        pdf.ln(10)

        # Traffic Overview Section
        pdf.chapter_title('Traffic Overview')
        stats_layout = [
            ('Normal Traffic', stats['normal_count']),
            ('Darknet Traffic', stats['darknet_count']),
            ('Total Traffic', stats['normal_count'] + stats['darknet_count'])
        ]
        
        x_start = 10
        y = pdf.get_y() + 5
        x_spacing = 60
        
        for i, (title, value) in enumerate(stats_layout):
            x = x_start + i * x_spacing
            pdf.add_stat_box(title, value, x, y)
        
        pdf.ln(30)

        # Blacklist Statistics Section
        pdf.chapter_title('Blacklist Statistics')
        try:
            blacklist_data = redis_handler.get('blacklist')
            if blacklist_data:
                blacklist = json.loads(blacklist_data)
                
                # Count active and expired entries
                now = datetime.now()
                ip_stats = {'active': 0, 'expired': 0}
                port_stats = {'active': 0, 'expired': 0}
                
                for ip, data in blacklist.get('ips', {}).items():
                    if data.get('expiry_date'):
                        expiry = datetime.strptime(data['expiry_date'], '%Y-%m-%d')
                        if expiry > now:
                            ip_stats['active'] += 1
                        else:
                            ip_stats['expired'] += 1
                    else:
                        ip_stats['active'] += 1
                
                for port, data in blacklist.get('ports', {}).items():
                    if data.get('expiry_date'):
                        expiry = datetime.strptime(data['expiry_date'], '%Y-%m-%d')
                        if expiry > now:
                            port_stats['active'] += 1
                        else:
                            port_stats['expired'] += 1
                    else:
                        port_stats['active'] += 1
                
                blacklist_stats = [
                    ('Active IPs', ip_stats['active']),
                    ('Expired IPs', ip_stats['expired']),
                    ('Active Ports', port_stats['active']),
                    ('Expired Ports', port_stats['expired'])
                ]
                
                y = pdf.get_y() + 5
                for i, (title, value) in enumerate(blacklist_stats):
                    x = x_start + (i % 2) * x_spacing
                    if i > 0 and i % 2 == 0:
                        y += 25
                    pdf.add_stat_box(title, value, x, y)
                
                pdf.ln(50)
            else:
                pdf.set_text_color(*pdf.text_gray)
                pdf.set_font('Arial', 'I', 11)
                pdf.cell(0, 10, 'No blacklist data available', 0, 1, 'L')
        except Exception as e:
            print(f"Error processing blacklist stats: {str(e)}")
            pdf.set_text_color(*pdf.text_gray)
            pdf.set_font('Arial', 'I', 11)
            pdf.cell(0, 10, 'Error loading blacklist statistics', 0, 1, 'L')

        # Network Activity Section
        pdf.chapter_title('Network Activity')
        layer2_stats = [
            ('Tor', stats['layer2_counters']['Tor']),
            ('VPN', stats['layer2_counters']['VPN']),
            ('I2P', stats['layer2_counters']['I2P']),
            ('Freenet', stats['layer2_counters']['Freenet']),
            ('Zeronet', stats['layer2_counters']['Zeronet'])
        ]
        
        y = pdf.get_y() + 5
        for i, (title, value) in enumerate(layer2_stats):
            x = x_start + (i % 3) * x_spacing
            if i > 0 and i % 3 == 0:
                y += 25
            pdf.add_stat_box(title, value, x, y)
        
        pdf.ln(50)

        # Save PDF to memory
        try:
            pdf_output = io.BytesIO()
            pdf.output(pdf_output)
            pdf_output.seek(0)

            if pdf_output.getbuffer().nbytes == 0:
                raise ValueError("Generated PDF is empty")

            return send_file(
                pdf_output,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'safesurf_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            )
        except Exception as e:
            print(f"Error saving PDF: {str(e)}")
            return jsonify({'error': 'Error saving PDF file'}), 500

    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return jsonify({'error': 'Failed to generate report'}), 500

@app.route('/get_blacklist_stats')
@login_required
def get_blacklist_stats():
    try:
        blacklist_data = redis_handler.get('blacklist')
        if not blacklist_data:
            return jsonify({
                'ip_stats': {'total': 0, 'active': 0, 'expired': 0},
                'port_stats': {'total': 0, 'active': 0, 'expired': 0}
            })

        blacklist = json.loads(blacklist_data)
        now = datetime.now()
        
        # Initialize stats
        ip_stats = {'total': 0, 'active': 0, 'expired': 0}
        port_stats = {'total': 0, 'active': 0, 'expired': 0}
        
        # Process IP statistics
        for ip, data in blacklist.get('ips', {}).items():
            ip_stats['total'] += 1
            if data.get('expiry_date'):
                expiry = datetime.strptime(data['expiry_date'], '%Y-%m-%d')
                if expiry > now:
                    ip_stats['active'] += 1
                else:
                    ip_stats['expired'] += 1
            else:
                ip_stats['active'] += 1
        
        # Process Port statistics
        for port, data in blacklist.get('ports', {}).items():
            port_stats['total'] += 1
            if data.get('expiry_date'):
                expiry = datetime.strptime(data['expiry_date'], '%Y-%m-%d')
                if expiry > now:
                    port_stats['active'] += 1
                else:
                    port_stats['expired'] += 1
            else:
                port_stats['active'] += 1
        
        return jsonify({
            'ip_stats': ip_stats,
            'port_stats': port_stats
        })
    except Exception as e:
        print(f"Error getting blacklist stats: {str(e)}")
        return jsonify({'error': 'Failed to load blacklist statistics'}), 500

@app.route('/ml/delete/<int:model_id>', methods=['POST'])
@login_required
def delete_model(model_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'})
    model = MLModel.query.get_or_404(model_id)
    try:
        # Delete the model file if it exists
        if model.model_path and os.path.exists(model.model_path):
            os.remove(model.model_path)
        db.session.delete(model)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Model deleted successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/blacklist/icmp_status', methods=['GET'])
@login_required
def get_icmp_status():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied.'}), 403
    raw_data = redis_handler.get('blacklist')
    block_icmp = False
    if raw_data:
        try:
            blacklist_data = json.loads(raw_data)
            block_icmp = blacklist_data.get('block_icmp', False)
        except Exception:
            pass
    return jsonify({'success': True, 'block_icmp': block_icmp})

@app.route('/blacklist/toggle_icmp', methods=['POST'])
@login_required
def toggle_icmp():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied.'}), 403
    print("ICMP policy update received:", request.get_json())
    data = request.get_json()
    block_icmp = bool(data.get('block_icmp'))
    raw_data = redis_handler.get('blacklist')
    if raw_data:
        try:
            blacklist_data = json.loads(raw_data)
        except Exception:
            blacklist_data = {'ips': {}, 'ports': {}}
    else:
        blacklist_data = {'ips': {}, 'ports': {}}
    blacklist_data['block_icmp'] = block_icmp
    redis_handler.set('blacklist', json.dumps(blacklist_data))
    return jsonify({'success': True, 'block_icmp': block_icmp})

@app.route('/blacklist/set_icmp_policy', methods=['POST'])
@login_required
def set_icmp_policy():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('blacklist'))
    policy = request.form.get('icmp_policy')
    block_icmp = (policy == 'block')
    raw_data = redis_handler.get('blacklist')
    if raw_data:
        try:
            blacklist_data = json.loads(raw_data)
        except Exception:
            blacklist_data = {'ips': {}, 'ports': {}}
    else:
        blacklist_data = {'ips': {}, 'ports': {}}
    blacklist_data['block_icmp'] = block_icmp
    redis_handler.set('blacklist', json.dumps(blacklist_data))
    # Log the ICMP policy change
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': 'icmp_policy',
        'value': 'block' if block_icmp else 'allow',
        'action': 'policy_changed',
        'description': f'ICMP policy set to {"Blocked" if block_icmp else "Allowed"}',
        'user': current_user.username
    }
    blacklist_logs = json.loads(redis_handler.get('blacklist_logs') or '[]')
    blacklist_logs.append(log_entry)
    redis_handler.set('blacklist_logs', json.dumps(blacklist_logs))
    flash('ICMP policy updated successfully!', 'success')
    return redirect(url_for('view_blacklist'))

# Start Redis listener when the app starts
def start_redis_listener():
    redis_handler.start_pubsub()

# Run the listener when the Flask app starts
if __name__ == '__main__':
    start_redis_listener()  # Start the listener for real-time updates
    socketio.run(app, host='127.0.0.1', port=5000)  # Use socketio.run to run the Flask app
