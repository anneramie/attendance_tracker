from .extensions import db, bcrypt

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed password

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Professor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
class Section(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    students = db.relationship('Student', backref='section', lazy=True, cascade="all, delete")

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    attendance = db.Column(db.Text, nullable=True)
class AttendanceSheet(db.Model):
    __tablename__ = "attendance_sheet"
    
    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.Integer, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    status = db.Column(
        db.Enum('P', 'A', 'E', name='attendance_status'), nullable=False
    )  # Enum for clarity and constraints

    student = db.relationship('Student', backref='attendance_records')

    def __repr__(self):
        return f"<Attendance {self.student.name} - Day {self.day}: {self.status}>"
class ProfRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    professor_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f'<ProfRequest {self.professor_name} - {self.email}>'
class SectionAccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    professor_id = db.Column(db.Integer, db.ForeignKey('professor.id'), nullable=False)
    section_id = db.Column(db.Integer, db.ForeignKey('section.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')  # pending, approved, denied

    professor = db.relationship('Professor', backref='section_requests')
    section = db.relationship('Section', backref='access_requests')
