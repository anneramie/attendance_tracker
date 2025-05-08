from flask import Flask
from .extensions import db, bcrypt  # Import correctly
from .models import Admin, Professor, Student, Section, AttendanceSheet, ProfRequest
from flask_mail import Mail
from flask_login import LoginManager
from .extensions import db, bcrypt, migrate  # now includes migrate

mail = Mail()

def create_website():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = 'annemarie'
    app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:2108@localhost:3306/attendance_db"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'annemariepandino@gmail.com'
    app.config['MAIL_PASSWORD'] = 'ANDAY2108'

    # Initialize extensions
    mail.init_app(app)
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)  # ✅ This initializes Flask-Migrate

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
