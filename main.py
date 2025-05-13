from website import create_website, db
from website.models import Admin, Professor, Student, Section, AttendanceSheet

app = create_website()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create all tables in the database
        print("✅ Tables created!")
    
    # Make the app accessible on the network by setting host to '0.0.0.0'
    app.run(debug=True, host='0.0.0.0', port=5000)
