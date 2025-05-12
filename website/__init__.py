from flask import Flask
from flask_mail import Mail
from flask_login import LoginManager
from .extensions import db, bcrypt, migrate
from .models import Admin, Professor, Student, Section, AttendanceSheet, ProfRequest
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize the Flask-Mail extension
mail = Mail()

def create_website():
    # Create Flask application instance
    app = Flask(__name__)

    # Keep the SECRET_KEY hardcoded as per your preference
    app.config["SECRET_KEY"] = os.getenv('SECRET_KEY', 'annemarie')  # Default fallback if not found

    # Database URI
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'mysql+pymysql://root:2108@localhost:3306/attendance_db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Email configuration from environment variables
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')  # Default to Gmail SMTP
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))  # Default port for TLS
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'  # Ensure boolean conversion
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Fetch email username from environment
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Fetch email password from environment

    # Check if email credentials are missing and warn
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        raise ValueError("MAIL_USERNAME and MAIL_PASSWORD must be set in the environment variables.")

    # Initialize extensions
    mail.init_app(app)
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)

    # Optional: Redirect user to login page if not authenticated
    login_manager.login_view = 'auth.prof_login'

    # Define the user loader function for Professor model
    @login_manager.user_loader
    def load_professor(professor_id):
        return Professor.query.get(int(professor_id))

    # Register blueprints
    from website.auth import auth
    from .views import views
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(views)

    return app
