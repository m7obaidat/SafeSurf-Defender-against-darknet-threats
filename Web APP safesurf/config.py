import os
import uuid
from pymongo import MongoClient

class Config:
    # Database configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or str(uuid.uuid4())
    
    # NoSQL database config
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB = os.environ.get('MONGO_DB', 'your_database_name') 