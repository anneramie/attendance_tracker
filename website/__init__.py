from flask import Flask
from flask_login import LoginManager
from .extensions import db, bcrypt, migrate
from .models import Admin, Professor, Student, Section, AttendanceSheet, ProfRequest
import os
from dotenv import load_dotenv
import pdfkit

path_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'  # Adjust path if different
pdf_config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)



# Load environment variables from .env file
load_dotenv()

def create_website():
    # Create Flask application instance
    app = Flask(__name__)

    # SECRET_KEY
    app.config["SECRET_KEY"] = os.getenv('SECRET_KEY', 'annemarie')  # Default fallback

    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'mysql+pymysql://root:2108@localhost:3306/attendance_db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.prof_login'

    # User loader function
    @login_manager.user_loader
    def load_professor(professor_id):
        return Professor.query.get(int(professor_id))

    # Register blueprints
    from website.auth import auth
    from .views import views
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(views)

    return app
