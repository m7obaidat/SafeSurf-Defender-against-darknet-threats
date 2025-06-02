# SafeSurf - IoT Network Security Monitoring System

SafeSurf is an advanced network security monitoring system specifically designed for IoT environments. It provides comprehensive real-time traffic analysis, darknet detection, and machine learning capabilities to identify and prevent potential security threats.

##  Key Features

### Real-time Monitoring & Analysis
- Live network traffic monitoring and analysis
- Real-time visualization of traffic patterns
- Interactive dashboard with dynamic updates
- Socket.IO integration for instant data updates
- Layer 2 protocol analysis (VPN, Tor, I2P, Freenet, Zeronet)
- Layer 3 behavior analysis 

### Security Features
- Darknet traffic detection and classification
- IP and port blacklisting with expiration dates
- ICMP traffic control with policy management
- Whitelist management for trusted IPs
- Comprehensive blacklist logging system
- Export functionality for security rules

### Machine Learning Integration
- Decision Tree Classifier for traffic classification
- Model training through web interface
- Model versioning and archiving system
- Performance metrics and accuracy tracking
- Automated model deployment
- Model metrics storage and visualization
- Training data preprocessing and validation

### User Management
- Role-based access control (Admin/Regular users)
- Secure password policies
- User activity logging
- Profile management
- Session handling
- User creation and deletion
- Admin privileges management

### Reporting & Notifications
- PDF report generation with traffic statistics
- Customizable date ranges for reports
- AWS SNS integration for email alerts
- Detailed security metrics and trends
- Export functionality for logs and rules
- Blacklist activity logs
- System performance reports

## 🛠️ Technical Stack

### Backend
- Python 3.8+
- Flask web framework
- Flask-SQLAlchemy for database management
- Flask-Login for authentication
- Flask-SocketIO for real-time updates
- Redis for caching and pub/sub
- AWS SNS for notifications
- SQLite for data persistence

### Frontend
- HTML5/CSS3
- Bootstrap 5
- JavaScript/jQuery
- Chart.js for visualizations
- Font Awesome icons
- Real-time updates with Socket.IO

### Machine Learning
- scikit-learn
- pandas
- numpy
- SMOTE for data balancing
- joblib for model persistence
- Model versioning system
- Performance metrics tracking

## 📋 Prerequisites

- Python 3.8 or higher
- Redis server
- AWS account (for SNS notifications)
- SQLite database
- Git

## 🚀 Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd safesurf
```

2. Create and activate virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
# Windows
set FLASK_SECRET_KEY=<your-secret-key>
set AWS_ACCESS_KEY_ID=<your-aws-access-key>
set AWS_SECRET_ACCESS_KEY=<your-aws-secret-key>

# Linux/Mac
export FLASK_SECRET_KEY=<your-secret-key>
export AWS_ACCESS_KEY_ID=<your-aws-access-key>
export AWS_SECRET_ACCESS_KEY=<your-aws-secret-key>
```

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

## ⚙️ Configuration

### Redis Configuration
Update the Redis connection details in `app.py`:
```python
redis_handler = RedisHandler(
    host='your-redis-host',
    port=6379,
    username='your-username',
    password='your-password'
)
```

### AWS SNS Configuration
Update AWS credentials and SNS topic ARN in `app.py`:
```python
aws_access_key = 'your-access-key'
aws_secret_key = 'your-secret-key'
topic_arn = 'your-sns-topic-arn'
```

## 🏃‍♂️ Running the Application

1. Start the application:
```bash
python app.py
```

2. Access the web interface:
- Open browser and navigate to `http://127.0.0.1:5000`
- Default admin credentials:
  - Username: admin
  - Password: admin

## Machine Learning Model

### Model Training
1. Access the ML dashboard through admin interface
2. Upload training dataset (CSV format)
3. Configure training parameters
4. Train and evaluate model
5. Approve or reject model deployment
6. View model metrics and performance
7. Archive previous model versions

### Model Features
- Decision Tree classification
- SMOTE for handling imbalanced data
- Feature selection and preprocessing
- Model versioning and archiving
- Performance metrics tracking
- Model comparison tools
- Automated model deployment

## Security Implementation

### Authentication
- Password hashing with Werkzeug
- Session management with Flask-Login
- Role-based access control
- Secure password policies
- User activity tracking
- Session timeout handling

### Network Security
- IP address validation
- Port scanning prevention
- ICMP traffic control with policy management
- Blacklist/Whitelist management
- Real-time threat detection
- Comprehensive logging system
- Export functionality for security rules

## Monitoring & Alerts

### Real-time Monitoring
- Traffic statistics
- Darknet detection
- Layer 2 protocol analysis
- User activity tracking
- System performance metrics
- Blacklist activity monitoring
- ICMP policy status tracking

### Alert System
- Email notifications via AWS SNS
- Customizable alert thresholds
- Alert history and logging
- Alert severity levels
- Alert acknowledgment system
- Blacklist change notifications
- Security policy updates

## Report Generation

### PDF Reports
- Traffic statistics
- Security metrics
- Blacklist/Whitelist summary
- User activity logs
- System performance data
- ICMP policy status
- Model performance metrics

### Export Options
- JSON format for rules
- CSV format for logs
- PDF format for reports
- Custom date ranges
- Filtered data export
- Blacklist activity logs
- Model metrics export

## Support

For support and queries:
- Create an issue in the repository
- Contact the development team
- Check the documentation
- Join the community forum

## Acknowledgments

- Flask framework and its extensions
- Redis for real-time data handling
- AWS for notification services
- scikit-learn for ML capabilities
- Bootstrap for UI components
- SMOTE for data balancing
- Socket.IO for real-time updates
