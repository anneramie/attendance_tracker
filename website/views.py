from flask import Blueprint, render_template, session, redirect, url_for, flash

views = Blueprint('views', __name__)  # ✅ Ensure this matches in url_for()
@views.route('/admin_homepage', methods=['GET', 'POST'])
def admin_homepage():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('auth.admin_login'))  # Redirect to admin login if not logged in

    return render_template('admin_homepage.html')  # Admin homepage

@views.route('/prof_homepage', methods=['GET', 'POST'])
def prof_homepage():
    if 'professor_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('auth.prof_login'))  # Redirect to professor login if not logged in

    return render_template('prof_homepage.html')  # Professor homepage





