from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate  # <-- Make sure this line exists

db = SQLAlchemy()
bcrypt = Bcrypt()
migrate = Migrate()  # <-- And this line too
