from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from pymongo import MongoClient
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()

# Initialize MongoDB connection
mongo_client = MongoClient(Config.MONGO_URI)
mongo_db = mongo_client[Config.MONGO_DB] 