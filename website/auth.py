from flask import Blueprint, render_template, redirect, flash, request, url_for, session, jsonify, make_response
from werkzeug.security import check_password_hash
from website.models import Admin,Professor, Student,Section,AttendanceSheet,ProfRequest,SectionAccessRequest
from .extensions import db, bcrypt
auth = Blueprint('auth', __name__)
from .extensions import db
import random
import string
from . import auth
import pdfkit
from flask import Response
import pdfkit
from io import BytesIO
from flask import send_file



path_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'  # Adjust if needed
pdf_config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)








from flask import Blueprint

from flask import Flask, render_template
auth = Blueprint('auth', __name__)

app = Flask(__name__)
app.secret_key = 'annemarie'



@auth.route('/', methods=['GET', 'POST'])  # Login route
def home():
    
    return render_template('index.html')

@auth.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')

        existing_user = Admin.query.filter_by(email=email).first()

        if existing_user and bcrypt.check_password_hash(existing_user.password, password):
            session.permanent = True  
            session['user_id'] = existing_user.id  # Set admin ID in the session
            session.pop('professor_id', None)  # Clear the professor session if it's set
            flash("Login successful!", "success")

            return redirect(url_for('views.admin_homepage'))  # Correct redirection to admin homepage

        flash('Invalid email or password.', 'danger')

    return render_template('admin_login.html')  # Render login page



@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    email = ""
    admin_name = ""
    
    if request.method == 'POST':
        admin_name = request.form.get('admin_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        

        # DEBUG: Print received data
        print(f"Received: {admin_name}, {email}, {password}")

        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template('admin_create_account.html', email=email, admin_name=admin_name)

        # ❌ Check if email already exists
        existing_user = Admin.query.filter_by(email=email).first()
        if existing_user:
            flash("Email is already registered.", "danger")
            return render_template('admin_create_account.html', email=email, admin_name=admin_name)

        # ✅ Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # ✅ Insert into database
        new_admin = Admin(
            admin_name=admin_name,
            email=email,
            password=hashed_password,
        )

        try:
            db.session.add(new_admin)
            db.session.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for('auth.admin_login'))  # Redirect to login page
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {str(e)}", "danger")

    return render_template('admin_create_account.html', email=email, admin_name=admin_name)





from flask import redirect, url_for

from flask import redirect, url_for, request

@auth.route('/create_section', methods=['GET', 'POST'])
def create_section():
    if request.method == 'GET':
        return render_template('create_section.html')  

    # Handle JSON and Form Submission
    if request.is_json:
        data = request.json  # Handle AJAX request
    else:
        data = request.form  # Handle normal form submission

    section_name = data.get("name")
    students = data.get("students", [])

    if not section_name:
        return jsonify({"success": False, "message": "Invalid input"}), 400

    try:
        new_section = Section(name=section_name)  
        db.session.add(new_section)
        db.session.commit()

        section_id = new_section.id  

        for student in students:
            new_student = Student(name=student["name"], section_id=section_id)
            db.session.add(new_student)

        db.session.commit()

        # Handle AJAX or form submission differently
        if request.is_json:
            return jsonify({"success": True, "message": "Section added successfully"})
        else:
            return redirect(url_for('auth.section_list'))  # Redirect on form submission

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


from sqlalchemy import text  # Import text

@auth.route('/sections')
def section_list():
    result = db.session.execute(text("SELECT id, name FROM section"))  
    sections = [{"id": row[0], "name": row[1]} for row in result]  # ✅ Store id and name
    return render_template('section_list.html', sections=sections)








@auth.route('/prof_request', methods=['GET', 'POST'])
def prof_request():
    if request.method == 'POST':
        name = request.form.get('professor_name')
        email = request.form.get('email')

        # Basic validation
        if not name or not email:
            flash('All fields are required!', category='error')
            return redirect('/prof_request')

        # Check if email already exists
        existing_professor = ProfRequest.query.filter_by(email=email).first()
        if existing_professor:
            flash('This email is already associated with an account. Please try another email.', category='error')
            return redirect('/prof_request')

        try:
            # Create new professor request
            new_request = ProfRequest(
                professor_name=name,
                email=email,
            )
            db.session.add(new_request)
            db.session.commit()
            flash('Request sent successfully. Please wait for admin approval.', category='success')
            return redirect('/prof_login')

        except Exception as e:
            print(f"Error: {e}")
            db.session.rollback()
            flash(f'Error processing your request: {str(e)}', category='error')
            return redirect(url_for('auth.prof_login'))


    return render_template('prof_request.html')



    
@auth.route('/admin_request_list')
def admin_request_list():
    result = db.session.execute(text("SELECT id, professor_name, email FROM prof_request"))
    prof_requests = [{"id": row[0], "professor_name": row[1]} for row in result]
    return render_template('admin_request_list.html', prof_requests=prof_requests)

@auth.route('/professor_details/<int:prof_request_id>')
def show_professor_details(prof_request_id):
    # Get the professor's details from the database using the prof_request_id
    professor = ProfRequest.query.get_or_404(prof_request_id)
    
    # Pass the professor's details to the template
    return render_template('professor_details.html', professor=professor)

def generate_username(name):
    base = ''.join(name.lower().split())
    suffix = ''.join(random.choices(string.digits, k=4))
    return f"{base}{suffix}"
    
def generate_random_password(length=10):
    characters = string.ascii_letters + string.digits  # A-Z, a-z, 0-9
    return ''.join(random.choice(characters) for _ in range(length))








@auth.route('/prof_login', methods=['GET', 'POST'])
def prof_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        professor = Professor.query.filter_by(username=username).first()

        if professor and professor.check_password(password):
            session.permanent = True
            session['professor_id'] = professor.id  # Set professor ID in the session
            session.pop('user_id', None)  # Clear the admin session if it's set
            flash("Login successful!", "success")
            return redirect(url_for('views.prof_homepage'))  # Correct redirection to professor homepage

        flash('Invalid username or password.', 'danger')

    return render_template('prof_login.html')  # Render login page


@auth.route('/add', methods=['GET'])
def manage():
    return render_template('manage.html', searched=False, can_request=True)  # always show request button

    return render_template('manage.html', section=section, searched=searched)
@auth.route('/add_section', methods=['POST'])
def add_section():
    section_name = request.form.get('section_name')
    description = request.form.get('section_description', '')

    # Check if it already exists
    existing = Section.query.filter_by(name=section_name).first()
    if existing:
        flash('Section already exists!', 'warning')
        return redirect(url_for('auth.manage'))

    # Create and add new section
    new_section = Section(name=section_name, description=description)
    db.session.add(new_section)
    db.session.commit()

    flash('Section added successfully!', 'success')
    return redirect(url_for('auth.manage'))
@auth.route('/search_section_by_name', methods=['POST'])
def search_section():
    search_term = request.form.get('section_name', '').strip()

    if not search_term:
        flash('Please enter a section name.', 'warning')
        return redirect(url_for('auth.manage'))

    matching_sections = Section.query.filter(Section.name.ilike(f"%{search_term}%")).all()

    return render_template('manage.html', sections=matching_sections, searched=True, can_request=True)

@auth.route('/request_section_access', methods=['POST'])
def request_section_access():
    if 'professor_id' not in session:
        flash('You must be logged in to request access.', 'warning')
        return redirect(url_for('auth.prof_login'))  # or wherever your login page is

    professor_id = session['professor_id']
    section_id = request.form.get('section_ids')

    if not section_id:
        flash('Invalid section request.', 'danger')
        return redirect(url_for('auth.manage'))

    existing = SectionAccessRequest.query.filter_by(
        professor_id=professor_id,
        section_id=section_id
    ).first()

    if existing:
        flash('You have already requested access to this section.', 'info')
        return redirect(url_for('auth.manage'))

    new_request = SectionAccessRequest(
        professor_id=professor_id,
        section_id=section_id,
        status='pending'
    )
    db.session.add(new_request)
    db.session.commit()

    flash('Access request submitted.', 'success')
    return redirect(url_for('auth.manage'))
@auth.route('/section_access_requests')
def section_access_requests():
    requests = SectionAccessRequest.query.filter_by(status='pending').all()
    return render_template('section_access_requests.html', requests=requests)

@auth.route('/approve_access/<int:request_id>', methods=['POST'])
def approve_access(request_id):
    req = SectionAccessRequest.query.get_or_404(request_id)
    req.status = 'approved'
    db.session.commit()
    flash('Access request approved.', 'success')
    return redirect(url_for('auth.section_access_requests'))



@auth.route('/reject_access/<int:request_id>', methods=['POST'])
def reject_access(request_id):
    req = SectionAccessRequest.query.get_or_404(request_id)
    req.status = 'rejected'
    db.session.commit()
    flash('Access request rejected.', 'info')
    return redirect(url_for('auth.section_access_requests'))

@auth.route('/sections-handled')
def sections_handled():
    # Get the professor's ID from session
    professor_id = session.get('professor_id')
    if not professor_id:
        flash("Please log in to access your sections.", "danger")
        return redirect(url_for('auth.prof_login'))

    # Query all sections handled by the professor where the access request is approved
    sections = db.session.query(Section).join(SectionAccessRequest).filter(
        SectionAccessRequest.professor_id == professor_id, 
        SectionAccessRequest.status == 'approved'
    ).all()

    # If no sections are found, show a message
    if not sections:
        flash("You have not been granted access to any sections yet.", "info")

    return render_template('sections_handled.html', sections=sections)




@auth.route('/professors')
def professors_page():
    professors = Professor.query.all()
    return render_template('professors.html', professors=professors)

@auth.route('/professor_info/<int:professor_id>')
def professor_info(professor_id):
    professor = Professor.query.get_or_404(professor_id)

    # Get sections they handle via access requests
    sections = db.session.query(Section).join(SectionAccessRequest).filter(
        SectionAccessRequest.professor_id == professor_id,
        SectionAccessRequest.status == 'approved'
    ).all()

    # Serialize data for JSON
    return jsonify({
        'username': professor.username,
        'email': getattr(professor, 'email', 'N/A'),  # Adjust if email is in another model
        'sections': [s.name for s in sections]
    })



@auth.route('/admin_logout', methods=['GET', 'POST'])
def admin_logout():
    if request.method == 'POST':
        session.pop('user_id', None)  # Clear admin session
        flash('You have been logged out as an admin.', 'info')
        return redirect(url_for('auth.admin_login'))  # Redirect to admin login page
    return render_template('logout.html')  # Just a placeholder for GET requests

@auth.route('/professor_logout', methods=['GET', 'POST'])
def professor_logout():
    if request.method == 'POST':
        session.pop('professor_id', None)  # Clear professor session
        flash('You have been logged out as a professor.', 'info')
        return redirect(url_for('auth.prof_login'))  # Redirect to professor login page
    return render_template('logout.html')  # Just a placeholder for GET requests
from flask_mail import Message




@auth.route('/generate/<int:prof_request_id>')
def generate(prof_request_id):
    prof_request = ProfRequest.query.get_or_404(prof_request_id)

    # Use the professor's name and email directly from the ProfRequest table
    username = generate_username(prof_request.professor_name)
    raw_password = generate_random_password()

    # Create a new professor with the generated username
    new_prof = Professor(username=username)
    new_prof.set_password(raw_password)  # Properly hash the password

    # Add the new professor to the database
    db.session.add(new_prof)

    # Delete the prof_request entry since it has been processed
    db.session.delete(prof_request)

    # Commit the transaction to save changes
    db.session.commit()


    # Render the template to show the generated credentials
    return render_template('generate.html', 
                           username=username, 
                           password=raw_password,
                           professor_name=prof_request.professor_name, 
                           email=prof_request.email)









@auth.route('/attendance/<int:section_id>', methods=['GET', 'POST'])
def show_attendance_sheet(section_id):
    from flask import current_app as app

    professor_id = session.get('professor_id')
    if not professor_id:
        flash("Please log in as a professor to access attendance.", "danger")
        return redirect(url_for('auth.prof_login'))

    # Check access to section
    access = SectionAccessRequest.query.filter_by(
        professor_id=professor_id,
        section_id=section_id,
        status='approved'
    ).first()

    if not access:
        flash("You do not have access to this section's attendance sheet.", "danger")
        return redirect(url_for('auth.sections_handled'))

    students = Student.query.filter_by(section_id=section_id).all()
    section = Section.query.get_or_404(section_id)

    if request.method == 'POST':
        data = request.get_json()
        if not data or 'attendance' not in data or not isinstance(data['attendance'], list):
            return jsonify({'message': 'Invalid data format!'}), 400

        try:
            for entry in data['attendance']:
                student_id = entry.get('student_id')
                day = entry.get('day')
                status = entry.get('status')

                if not student_id or not day or status not in ['P', 'A', 'E']:
                    continue

                # Check if record exists for this professor
                record = AttendanceSheet.query.filter_by(
                    student_id=student_id,
                    day=day,
                    professor_id=professor_id  # ✅ important
                ).first()

                if record:
                    record.status = status
                else:
                    new_record = AttendanceSheet(
                        student_id=student_id,
                        day=day,
                        status=status,
                        professor_id=professor_id  # ✅ store who took it
                    )
                    db.session.add(new_record)

            db.session.commit()
            return jsonify({'message': 'Attendance saved successfully!'}), 200

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error saving attendance: {e}")
            return jsonify({'message': f"Error saving attendance: {e}"}), 500

    # GET: Load attendance per professor only
    attendance_data = {
        (a.student_id, a.day): a.status
        for a in AttendanceSheet.query.join(Student)
        .filter(Student.section_id == section_id, AttendanceSheet.professor_id == professor_id)
        .all()
    }

    return render_template(
        'attendance_sheet.html',
        section_id=section_id,
        section_name=section.name,
        students=students,
        attendance_data=attendance_data
    )
@auth.route('/download_attendance/<int:section_id>', methods=['GET'])
def download_attendance(section_id):
    # Get all students in the section
    students = Student.query.filter_by(section_id=section_id).all()
    attendance_records = AttendanceSheet.query.join(Student).filter(Student.section_id == section_id).all()

    # Organize attendance data
    attendance_data = {}
    all_days = set()

    for record in attendance_records:
        sid = record.student_id
        day = record.day
        status = record.status
        all_days.add(day)
        if sid not in attendance_data:
            attendance_data[sid] = {}
        attendance_data[sid][day] = status

    # Ensure all students have an entry, even if empty
    for student in students:
        attendance_data.setdefault(student.id, {})

    # Sort the days
    sorted_days = sorted(all_days)

    # Compute present counts
    present_counts = {
        sid: sum(1 for status in days.values() if status == 'P')
        for sid, days in attendance_data.items()
    }

    # Get professor (optional)
    professor_id = session.get('professor_id')
    professor = Professor.query.get(professor_id) if professor_id else None

    # Render template
    rendered = render_template(
        'attendance_pdf.html',
        students=students,
        attendance_data=attendance_data,
        days=sorted_days,
        section_id=section_id,
        professor=professor,
        present_counts=present_counts  # ✅ REQUIRED
    )

    # PDF generation
    config = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe')
    pdf = pdfkit.from_string(rendered, False, configuration=config)

    # Return PDF as response
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=attendance_section_{section_id}.pdf'
    return response
@auth.route('/view_final_attendance/<int:section_id>', methods=['GET'])
def view_final_attendance(section_id):
    professor_id = session.get('professor_id')
    admin_id = session.get('admin_id')

    if not professor_id and not admin_id:
        flash("You must be logged in to view attendance.", "danger")
        return redirect(url_for('auth.prof_login'))

    students = Student.query.filter_by(section_id=section_id).all()

    if admin_id:
        attendance_records = (
            AttendanceSheet.query
            .join(Student)
            .filter(Student.section_id == section_id)
            .all()
        )
    else:
        access = SectionAccessRequest.query.filter_by(
            professor_id=professor_id,
            section_id=section_id,
            status='approved'
        ).first()

        if not access:
            flash("You do not have access to view this section's attendance.", "danger")
            return redirect(url_for('auth.sections_handled'))

        attendance_records = (
            AttendanceSheet.query
            .join(Student)
            .filter(
                Student.section_id == section_id,
                AttendanceSheet.professor_id == professor_id
            )
            .all()
        )

    attendance_by_prof = {}
    all_days = set()

    for record in attendance_records:
        sid = record.student_id
        day = record.day
        status = record.status
        prof = Professor.query.get(record.professor_id)
        prof_name = prof.username if prof else "Unknown"  # Changed to prof.username

        if prof_name not in attendance_by_prof:
            attendance_by_prof[prof_name] = {}

        if sid not in attendance_by_prof[prof_name]:
            attendance_by_prof[prof_name][sid] = {}

        attendance_by_prof[prof_name][sid][day] = status
        all_days.add(day)

    return render_template(
    'view_attendance.html', 
    students=students, 
    attendance_by_prof=attendance_by_prof, 
    all_days=sorted(all_days),
    section_id=section_id  # Make sure to pass section_id here
)
