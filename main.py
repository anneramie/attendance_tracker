from website import create_website, db
from website.models import Admin, Professor, Student, Section, AttendanceSheet

app = create_website()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("✅ Tables created!")
    app.run(debug=True)
