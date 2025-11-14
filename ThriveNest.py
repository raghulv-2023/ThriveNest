import os
import random
import secrets
import smtplib
import csv
import datetime
import io
from io import StringIO
from datetime import timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from bs4 import BeautifulSoup
import requests
from googlesearch import search
from markupsafe import Markup
from flask_apscheduler import APScheduler
import pytz


# If you're fetching scraped content or answers from a module
from web_scraper import fetch_web_answer
from flask_session import Session


# Optional: if using data processing libraries for advanced stats
import statistics


# Load environment variables from key.env located next to this file (works regardless of CWD)
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'key.env')
load_dotenv(env_path)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///thrivenest.db'
db = SQLAlchemy(app)

app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', 'sqlalchemy', etc.
Session(app)


# Configure Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Email configuration
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

# Read ADMIN_EMAIL safely and give a clear error if it's missing.
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
if ADMIN_EMAIL:
    ADMIN_EMAIL = ADMIN_EMAIL.strip().lower()
else:
    raise RuntimeError(
        "Required environment variable ADMIN_EMAIL is not set.\n"
        "Please add ADMIN_EMAIL to your environment or to key.env and restart the application."
    )

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")  # Should be stored securely

class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config())
app.config['SCHEDULER_API_ENABLED'] = True
app.config['SCHEDULER_TIMEZONE'] = 'Asia/Kolkata'


# ---------------------------
# DATABASE MODELS
# ---------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    fullname = db.Column(db.String(150), nullable=False)
    gender = db.Column(db.String(10))
    dob_day = db.Column(db.Integer, nullable=False)
    dob_month = db.Column(db.Integer, nullable=False)
    dob_year = db.Column(db.Integer, nullable=False)
    phone = db.Column(db.String(50))
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='elder')  # 'elder'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    # Medical details
    details_completed = db.Column(db.Boolean, default=False)
    weight = db.Column(db.Float)
    height = db.Column(db.Float)
    allergies = db.Column(db.String(250))
    chronic_conditions = db.Column(db.String(250))
    # Emergency contact
    emergency_contact_name = db.Column(db.String(100))
    emergency_contact_email = db.Column(db.String(150))
    emergency_relationship = db.Column(db.String(50))
    helper_preference = db.Column(db.String(10))  # "male" or "female"
    assigned_professional = db.Column(db.String(150))  # e.g., "Name (Health Advisor)"
    default_sos_message = db.Column(db.Text)


class HealthData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    date = db.Column(db.Date)
    weight = db.Column(db.Float)
    bp = db.Column(db.String(10))
    sugar = db.Column(db.Float)

class Medicine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100), nullable=False)
    dosage = db.Column(db.String(50))
    # Store reminder time (daily) as a time field
    reminder_time = db.Column(db.Time, nullable=False)



# ---------------------------
# NEW: CHAT FEATURE MODELS & ROUTES
# ---------------------------
# Extend the existing User model by adding two new columns:
if not hasattr(User, 'chat_nickname'):
    chat_nickname_column = db.Column('chat_nickname', db.String(50), unique=True)
    setattr(User, 'chat_nickname', chat_nickname_column)
    
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sender_nickname = db.Column(db.String(50), nullable=False)
    # For DM messages, store the receiver's user id; if None, it's a public message
    receiver_id = db.Column(db.Integer, nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(pytz.timezone("Asia/Kolkata")))
    
class AdminUser(UserMixin):
    def __init__(self, email):
        self.email = email
        self.role = 'admin'
    def get_id(self):
        return "admin"

# Wrapper classes for Health Advisors and Doctors
class AdvisorUser(UserMixin):
    def __init__(self, advisor):
        self.advisor = advisor
        self.role = 'med'
    def get_id(self):
        return "A" + str(self.advisor.id)

class DoctorUser(UserMixin):
    def __init__(self, doctor):
        self.doctor = doctor
        self.role = 'doctor'
    def get_id(self):
        return "D" + str(self.doctor.id)

class HealthAdvisor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Appointment model
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    advisor_id = db.Column(db.Integer)  # HealthAdvisor id who set the appointment
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'))
    problem_description = db.Column(db.String(500))
    status = db.Column(db.String(20), default="Pending")  # Pending, Accepted, Rejected, Scheduled
    appointment_datetime = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ---------------------------
# Flask-Login user_loader
# ---------------------------
@login_manager.user_loader
def load_user(user_id):
    if user_id == "admin":
        return AdminUser(ADMIN_EMAIL)
    if user_id.startswith("A"):
        advisor_id = int(user_id[1:])
        advisor = HealthAdvisor.query.get(advisor_id)
        if advisor:
            return AdvisorUser(advisor)
    if user_id.startswith("D"):
        doctor_id = int(user_id[1:])
        doctor = Doctor.query.get(doctor_id)
        if doctor:
            return DoctorUser(doctor)
    try:
        uid = int(user_id)
        return User.query.get(uid)
    except (ValueError, TypeError):
        return None

# ---------------------------
# HELPER FUNCTIONS
# ---------------------------
def send_otp(email, otp):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = email
        msg['Subject'] = "Your OTP for Signup"
        body = f"Your OTP is: {otp}. This OTP is valid for 5 minutes."
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send OTP: {e}")
        return False

def send_password_reset_otp(email, otp):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = email
        msg['Subject'] = "Your OTP for Password Reset"
        body = f"Your OTP for Password Reset is: {otp}. This OTP is valid for 5 minutes."
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send password reset OTP: {e}")
        return False

# ---------------------------
# ROUTES
# ---------------------------
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about.html')
def about():
    return render_template('about.html')

@app.route('/report', methods=['GET', 'POST'])
def report():
    if request.method == 'POST':
        subject = request.form['subject']
        description = request.form['description']
        flash("Report submitted. Thank you for your feedback!")
        return redirect(url_for('home'))
    return render_template('report.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password_input = request.form['password']
        # Admin check
        if email == ADMIN_EMAIL:
            if password_input == ADMIN_PASSWORD:
                admin_user = AdminUser(ADMIN_EMAIL)
                login_user(admin_user)
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Invalid admin credentials.", "login_error")
                return render_template('login.html')
        # Check for elder user
        user = User.query.filter_by(email=email).first()
        if user:
            if not check_password_hash(user.password, password_input):
                flash("Wrong password.", "login_error")
                return render_template('login.html')
            login_user(user)
            if user.role == 'elder':
                if not user.details_completed:
                    return redirect(url_for('details'))
                return redirect(url_for('dashboard'))
            else:
                flash("User role undefined.", "login_error")
                return render_template('login.html')
        # Check for Health Advisor
        advisor = HealthAdvisor.query.filter_by(email=email).first()
        if advisor:
            if not check_password_hash(advisor.password, password_input):
                flash("Wrong password.", "login_error")
                return render_template('login.html')
            login_user(AdvisorUser(advisor))
            return redirect(url_for('med_dashboard'))
        # Check for Doctor
        doctor = Doctor.query.filter_by(email=email).first()
        if doctor:
            if not check_password_hash(doctor.password, password_input):
                flash("Wrong password.", "login_error")
                return render_template('login.html')
            login_user(DoctorUser(doctor))
            return redirect(url_for('doc_dashboard'))
        flash("Unregistered email.", "login_error")
        return render_template('login.html')
    return render_template('login.html')

@app.route('/forgot_password.html', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        step = request.form.get('step', 'send_otp')
        if step == 'send_otp':
            email = request.form['email'].strip().lower()
            user = None
            if email == ADMIN_EMAIL:
                user = AdminUser(ADMIN_EMAIL)
            else:
                user = User.query.filter_by(email=email).first()
            if not user:
                flash("Email not found.", "forgot_error")
                return render_template('forgot_password.html')
            otp = str(secrets.randbelow(1000000)).zfill(6)
            session['reset_email'] = email
            session['reset_otp'] = otp
            session['reset_otp_timestamp'] = datetime.datetime.now(pytz.timezone("Asia/Kolkata")).isoformat()
            if send_password_reset_otp(email, otp):
                flash("OTP sent to your email.", "forgot_info")
                return render_template('forgot_password.html', otp_sent=True, email=email)
            else:
                flash("Failed to send OTP.", "forgot_error")
                return render_template('forgot_password.html')
        elif step == 'verify_otp':
            entered_otp = request.form.get('otp_input')
            stored_otp = session.get('reset_otp')
            if not stored_otp:
                flash("No OTP generated. Please try again.", "forgot_error")
                return render_template('forgot_password.html')
            if entered_otp != stored_otp:
                flash("OTP verification failed.", "forgot_error")
                return render_template('forgot_password.html', otp_sent=True, email=session.get('reset_email'))
            else:
                flash("OTP verified successfully.", "forgot_info")
                return render_template('forgot_password.html', otp_verified=True, email=session.get('reset_email'))
        elif step == 'reset_password':
            email = session.get('reset_email')
            if not email:
                flash("Session expired. Please try again.", "forgot_error")
                return redirect(url_for('forgot_password'))
            newpass = request.form.get('newpass')
            repass = request.form.get('repass')
            if not newpass or newpass != repass:
                flash("Passwords do not match or are empty.", "forgot_error")
                return render_template('forgot_password.html', otp_verified=True, email=email)
            if email == ADMIN_EMAIL:
                flash("Admin password reset is not allowed via this form.", "forgot_error")
                return redirect(url_for('forgot_password'))
            else:
                user = User.query.filter_by(email=email).first()
                if not user:
                    flash("User not found.", "forgot_error")
                    return redirect(url_for('forgot_password'))
                user.password = generate_password_hash(newpass)
                db.session.commit()
            session.pop('reset_otp', None)
            session.pop('reset_otp_timestamp', None)
            session.pop('reset_email', None)
            flash("Password reset successfully! Please log in.", "forgot_success")
            return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        step = request.form.get('step', 'send_otp')
        if step == 'send_otp':
            email = request.form['email'].strip().lower()
            if email == ADMIN_EMAIL:
                flash("This email is reserved for the admin.", "signup_error")
                return render_template('signup.html')
            if User.query.filter_by(email=email).first():
                flash("Email already exists.", "signup_error")
                return render_template('signup.html')
            otp = str(secrets.randbelow(1000000)).zfill(6)
            session['temp_email'] = email
            session['signup_otp'] = otp
            session['signup_otp_timestamp'] = datetime.datetime.now(pytz.timezone("Asia/Kolkata")).isoformat()
            if send_otp(email, otp):
                flash("OTP sent to your email.", "signup_info")
                return render_template('signup.html', otp_sent=True, email=email)
            else:
                flash("Failed to send OTP.", "signup_error")
                return render_template('signup.html')
        elif step == 'verify_otp':
            entered_otp = request.form.get('otp_input')
            stored_otp = session.get('signup_otp')
            if not stored_otp:
                flash("No OTP generated. Please try again.", "signup_error")
                return render_template('signup.html')
            if entered_otp != stored_otp:
                flash("OTP verification failed.", "signup_error")
                return render_template('signup.html', otp_sent=True, email=session.get('temp_email'))
            else:
                flash("OTP verified successfully.", "signup_info")
                return render_template('signup.html', otp_verified=True, email=session.get('temp_email'))
        elif step == 'complete_signup':
            email = session.get('temp_email')
            if not email:
                flash("Session expired. Please try again.", "signup_error")
                return redirect(url_for('signup'))
            fullname = request.form.get('fullname')
            gender = request.form.get('gender')
            try:
                dob_day = int(request.form.get('dobDay'))
                dob_month = int(request.form.get('dobMonth'))
                dob_year = int(request.form.get('dobYear'))
            except (TypeError, ValueError):
                flash("Invalid Date of Birth.", "signup_error")
                return render_template('signup.html', otp_verified=True, email=email)
            phone = request.form.get('phone')
            password_input = request.form.get('password')
            confirm_password = request.form.get('confirmPassword')
            if password_input != confirm_password:
                flash("Passwords do not match.", "signup_error")
                return render_template('signup.html', otp_verified=True, email=email)
            hashed_password = generate_password_hash(password_input)
            new_user = User(
                email=email,
                fullname=fullname,
                gender=gender,
                dob_day=dob_day,
                dob_month=dob_month,
                dob_year=dob_year,
                phone=phone,
                password=hashed_password,
                role='elder'
            )
            db.session.add(new_user)
            db.session.commit()
            session.pop('signup_otp', None)
            session.pop('signup_otp_timestamp', None)
            session.pop('temp_email', None)
            flash("Signup successful! Please log in.", "signup_success")
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('home'))

# ---------------------------
# ADMIN DASHBOARD & ACTIONS
# ---------------------------
@app.route('/admin.html')
@login_required
def admin_dashboard():
    if not current_user.is_authenticated or current_user.get_id() != "admin":
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('login'))
    health_advisors = HealthAdvisor.query.all()
    doctors = Doctor.query.all()
    return render_template('admin.html', health_advisors=health_advisors, doctors=doctors)

@app.route('/create_health_advisor', methods=['POST'])
@login_required
def create_health_advisor():
    if not current_user.is_authenticated or current_user.get_id() != "admin":
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('login'))
    name = request.form.get('name')
    gender = request.form.get('gender')
    email = request.form.get('email').strip().lower()
    password_input = request.form.get('password')
    if email == ADMIN_EMAIL:
        flash("Admin email cannot be used for Health Advisor.", "admin_error")
        return redirect(url_for('admin_dashboard'))
    if HealthAdvisor.query.filter_by(email=email).first() or Doctor.query.filter_by(email=email).first():
        flash("This email already exists for a Health Advisor or a Doctor.", "admin_error")
        return redirect(url_for('admin_dashboard'))
    if not name or not gender or not email or not password_input:
        flash("All fields are required for creating a Health Advisor.", "admin_error")
        return redirect(url_for('admin_dashboard'))
    hashed_password = generate_password_hash(password_input)
    new_advisor = HealthAdvisor(name=name, gender=gender, email=email, password=hashed_password)
    db.session.add(new_advisor)
    db.session.commit()
    flash("Health Advisor created successfully!", "admin_success")
    return redirect(url_for('admin_dashboard'))

@app.route('/create_doctor', methods=['POST'])
@login_required
def create_doctor():
    if not current_user.is_authenticated or current_user.get_id() != "admin":
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('login'))
    name = request.form.get('name')
    gender = request.form.get('gender')
    email = request.form.get('email').strip().lower()
    password_input = request.form.get('password')
    specialization = request.form.get('specialization')
    if email == ADMIN_EMAIL:
        flash("Admin email cannot be used for Doctor.", "admin_error")
        return redirect(url_for('admin_dashboard'))
    if Doctor.query.filter_by(email=email).first() or HealthAdvisor.query.filter_by(email=email).first():
        flash("This email already exists for a Doctor or a Health Advisor.", "admin_error")
        return redirect(url_for('admin_dashboard'))
    if not name or not gender or not email or not password_input or not specialization:
        flash("All fields are required for creating a Doctor.", "admin_error")
        return redirect(url_for('admin_dashboard'))
    hashed_password = generate_password_hash(password_input)
    new_doctor = Doctor(name=name, gender=gender, email=email, password=hashed_password, specialization=specialization)
    db.session.add(new_doctor)
    db.session.commit()
    flash("Doctor created successfully!", "admin_success")
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_health_advisor/<int:advisor_id>', methods=['POST'])
@login_required
def delete_health_advisor(advisor_id):
    if not current_user.is_authenticated or current_user.get_id() != "admin":
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('login'))
    advisor = HealthAdvisor.query.get(advisor_id)
    if not advisor:
        flash("Health Advisor not found.", "admin_error")
    else:
        db.session.delete(advisor)
        db.session.commit()
        flash("Health Advisor deleted successfully.", "admin_success")
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_doctor/<int:doctor_id>', methods=['POST'])
@login_required
def delete_doctor(doctor_id):
    if not current_user.is_authenticated or current_user.get_id() != "admin":
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('login'))
    doctor = Doctor.query.get(doctor_id)
    if not doctor:
        flash("Doctor not found.", "admin_error")
    else:
        db.session.delete(doctor)
        db.session.commit()
        flash("Doctor deleted successfully.", "admin_success")
    return redirect(url_for('admin_dashboard'))

# ---------------------------
# USER DASHBOARD / DETAILS / CHANGE PASSWORD
# ---------------------------
@app.route('/dashboard.html')
@login_required
def dashboard():
    if not current_user.is_authenticated:
        flash("Please log in.", "login_error")
        return redirect(url_for('login'))
    user = User.query.get(current_user.get_id())
    if user and user.role == 'elder':
        # Retrieve appointments requested by the logged in patient.
        appointments = Appointment.query.filter_by(patient_id=user.id).all()
        # Fetch the list of all doctors to display doctor details in the dashboard.
        doctors = Doctor.query.all()
        return render_template('dashboard.html', user=user, appointments=appointments, doctors=doctors)
    flash("Unauthorized access.", "login_error")
    return redirect(url_for('login'))


@app.route('/medicines', methods=['GET', 'POST'])
@login_required
def manage_medicines():
    # Only allow elder users to manage medicine reminders
    user = User.query.get(current_user.get_id())
    if user.role != 'elder':
        flash("Unauthorized access.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        medicine_id = request.form.get('medicine_id')
        name = request.form.get('name')
        dosage = request.form.get('dosage')
        reminder_time_str = request.form.get('reminder_time')  # expected in HH:MM format

        try:
            reminder_time = datetime.datetime.strptime(reminder_time_str, "%H:%M").time()
        except Exception as e:
            flash("Invalid time format. Please use HH:MM (24-hour format).", "error")
            return redirect(url_for('manage_medicines'))

        if medicine_id:
            med = Medicine.query.get(medicine_id)
            if med and med.user_id == user.id:
                med.name = name
                med.dosage = dosage
                med.reminder_time = reminder_time
            else:
                flash("Medicine not found.", "error")
        else:
            new_med = Medicine(user_id=user.id, name=name, dosage=dosage, reminder_time=reminder_time)
            db.session.add(new_med)
        db.session.commit()
        flash("Medicine details saved.", "success")
        return redirect(url_for('manage_medicines'))

    # GET: List the medicines for the logged-in user
    medicines = Medicine.query.filter_by(user_id=user.id).all()
    return render_template('medicines.html', medicines=medicines)

def check_medicine_reminders():
    with app.app_context():
        tz = pytz.timezone("Asia/Kolkata")
        current_time = datetime.datetime.now(tz).time()
        medicines = Medicine.query.all()
        for med in medicines:
            if current_time.hour == med.reminder_time.hour and current_time.minute == med.reminder_time.minute:
                user = User.query.get(med.user_id)
                if user:
                    subject = f"Medicine Reminder: {med.name}"
                    body = (
                        f"Hi {user.fullname},\n\n"
                        f"This is a reminder to take your medicine: {med.name}.\n"
                        f"Dosage: {med.dosage if med.dosage else 'N/A'}.\n"
                        f"Scheduled Time: {med.reminder_time.strftime('%H:%M')} IST.\n\n"
                        "Regards,\nThriveNest"
                    )
                    try:
                        with smtplib.SMTP('smtp.gmail.com', 587) as server:
                            server.starttls()
                            server.login(EMAIL_USER, EMAIL_PASS)
                            msg = MIMEMultipart()
                            msg['From'] = EMAIL_USER
                            msg['To'] = user.email
                            msg['Subject'] = subject
                            msg.attach(MIMEText(body, 'plain'))
                            server.send_message(msg)
                        print(f"Reminder sent to {user.email} for {med.name}")
                    except Exception as e:
                        print(f"Failed to send reminder to {user.email}: {e}")


scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()
scheduler.add_job(
    id='Medicine Reminder',
    func=check_medicine_reminders,
    trigger='interval',
    minutes=1,
    timezone='Asia/Kolkata'
)


@app.route('/set_nickname', methods=['GET', 'POST'])
@login_required
def set_nickname():
    user = User.query.get(current_user.get_id())
    if request.method == 'POST':
        nickname = request.form.get('nickname').strip()
        if not nickname:
            flash("Nickname cannot be empty.", "error")
            return render_template('set_nickname.html', user=user)
        # Check if nickname already exists (for any user except current)
        existing = User.query.filter(User.chat_nickname==nickname, User.id != user.id).first()
        if existing:
            flash("Nickname already taken. Choose another.", "error")
            return render_template('set_nickname.html', user=user)
        user.chat_nickname = nickname
        db.session.commit()
        flash("Nickname set successfully!", "success")
        return redirect(url_for('chatroom'))
    return render_template('set_nickname.html', user=user)

@app.route('/chatroom', methods=['GET', 'POST'])
@login_required
def chatroom():
    user = User.query.get(current_user.get_id())
    if not user.chat_nickname:
        flash("Please set your chat nickname first.", "info")
        return redirect(url_for('set_nickname'))

    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        dm_receiver_nickname = request.form.get('dm_receiver', '').strip()
        receiver_id = None

        if dm_receiver_nickname:
            receiver = User.query.filter_by(chat_nickname=dm_receiver_nickname).first()
            if not receiver:
                flash("No user found with that nickname.", "error")
                return redirect(url_for('chatroom'))
            receiver_id = receiver.id

        if content:
            msg = Message(
                sender_id=user.id,
                sender_nickname=user.chat_nickname,
                receiver_id=receiver_id,
                content=content
            )
            db.session.add(msg)
            db.session.commit()
            flash("Message sent.", "success")
        else:
            flash("Message content cannot be empty.", "error")
        return redirect(url_for('chatroom'))

    # Retrieve messages that are either public or direct messages involving the user.
    all_messages = Message.query.filter(
        (Message.receiver_id == None) | 
        (Message.sender_id == user.id) | 
        (Message.receiver_id == user.id)
    ).order_by(Message.timestamp.asc()).all()

    # Separate public messages and group DM messages by partner.
    public_messages = [msg for msg in all_messages if msg.receiver_id is None]
    dm_messages = {}
    for msg in all_messages:
        if msg.receiver_id is not None:
            # Identify the conversation partner.
            partner_id = msg.receiver_id if msg.sender_id == user.id else msg.sender_id
            partner = User.query.get(partner_id)
            partner_nickname = partner.chat_nickname if partner else "Unknown"
            dm_messages.setdefault(partner_nickname, []).append(msg)

    # Get a list of all other users (excluding self) with a chat nickname.
    other_users = User.query.filter(User.id != user.id, User.chat_nickname != None).all()

    return render_template(
        'chatroom.html',
        user=user,
        public_messages=public_messages,
        dm_messages=dm_messages,
        other_users=other_users
    )



@app.route('/mental_health_resources')
@login_required
def mental_health_resources():
    # Map moods to numeric values for the chart.
    mood_map = {"Angry": 1, "Sad": 2, "Anxious": 3, "Calm": 4, "Happy": 5}
    # Sort mood_entries by timestamp.
    sorted_entries = sorted(mood_entries, key=lambda x: x['timestamp'])
    labels = [entry['timestamp'] for entry in sorted_entries]
    data = [mood_map.get(entry['mood'], 0) for entry in sorted_entries]
    return render_template('mental_health_resources.html', labels=labels, data=data)


# Mood tracker entries (Feature 3)
mood_entries = []


@app.route('/save_mood', methods=['POST'])
def save_mood():
    mood = request.form.get('mood')
    timestamp=datetime.datetime.now(pytz.timezone("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M')
    if mood:
        mood_entries.append({'mood': mood, 'timestamp': timestamp})
        flash('Mood saved successfully!', 'success')
    else:
        flash('Please select a mood before submitting.', 'error')
    return redirect(url_for('mental_health_resources'))


@app.route('/get_symptom_response', methods=['POST'])
def get_symptom_response():
    data = request.get_json()
    symptom = data.get('symptom', '')
    if not symptom:
        return jsonify({"reply": "Please enter a symptom."})
    try:
        search_url = f"https://en.wikipedia.org/wiki/{symptom.replace(' ', '_')}"
        response = requests.get(search_url)
        if response.status_code != 200:
            return jsonify({"reply": f"Sorry, I couldn't find reliable information on '{symptom}'."})
        soup = BeautifulSoup(response.text, 'html.parser')
        paragraphs = soup.select("p")
        for p in paragraphs:
            text = p.get_text().strip()
            if len(text) > 100:
                return jsonify({"reply": text})
        return jsonify({"reply": f"Couldn't extract detailed info about '{symptom}'."})
    except Exception as e:
        print(e)
        return jsonify({"reply": "An error occurred while fetching data."})

def fetch_google_answer(query):
    try:
        for url in search(query, num_results=5):
            if 'wikipedia.org' not in url:
                response = requests.get(url, timeout=5)
                soup = BeautifulSoup(response.text, 'html.parser')
                paragraphs = soup.find_all('p')
                for p in paragraphs:
                    text = p.get_text().strip()
                    if len(text) > 100:
                        return text
        return "Sorry, I couldn't find a relevant answer online."
    except Exception as e:
        return f"An error occurred while searching: {e}"

def fetch_web_answer(query):
    try:
        urls = list(search(query, num_results=5))
        for url in urls:
            if "wikipedia" in url:
                continue
            try:
                response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                soup = BeautifulSoup(response.text, 'html.parser')
                paragraphs = soup.find_all('p')
                for p in paragraphs:
                    text = p.get_text().strip()
                    if len(text) > 100 and query.lower().split()[0] in text.lower():
                        return text
                for p in paragraphs:
                    text = p.get_text().strip()
                    if len(text) > 100:
                        return text
            except Exception as inner_error:
                continue
        return "Sorry, I couldn't find a reliable answer for your question."
    except Exception as e:
        return f"An error occurred while fetching answer: {e}"

@app.route("/personal_health_trends", methods=["GET"])
@login_required
def personal_health_trends():
    start = request.args.get('start')
    end = request.args.get('end')
    
    query = HealthData.query.filter_by(user_id=current_user.id)
    if start:
        query = query.filter(HealthData.date >= datetime.datetime.strptime(start, '%Y-%m-%d').date())
    if end:
        query = query.filter(HealthData.date <= datetime.datetime.strptime(end, '%Y-%m-%d').date())

    records = query.order_by(HealthData.date).all()
    labels = [record.date.strftime('%Y-%m-%d') for record in records]
    weight_data = [record.weight for record in records]
    sugar_data = [record.sugar for record in records]

    return render_template("personal_health_trends.html",
        chart_labels=labels,
        weight_data=weight_data,
        sugar_data=sugar_data,
        start_date=start,
        end_date=end
    )

@app.route("/submit_health_data", methods=["POST"])
@login_required
def submit_health_data():
    date = request.form["date"]
    weight = request.form.get("weight") or None
    bp = request.form.get("bp") or None
    sugar = request.form.get("sugar") or None

    new_entry = HealthData(
        user_id=current_user.id,
        date=datetime.datetime.strptime(date, '%Y-%m-%d'),
        weight=float(weight) if weight else None,
        bp=bp,
        sugar=float(sugar) if sugar else None
    )
    db.session.add(new_entry)
    db.session.commit()
    flash("Health data saved successfully!", "success")
    return redirect(url_for("personal_health_trends"))

@app.route("/upload_health_report", methods=["POST"])
@login_required
def upload_health_report():
    file = request.files["file"]
    if file and file.filename.endswith(".csv"):
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        reader = csv.DictReader(stream)
        for row in reader:
            try:
                entry = HealthData(
                    user_id=current_user.id,
                    date=datetime.datetime.strptime(row["date"], "%Y-%m-%d").date(),
                    weight=float(row["weight"]) if row.get("weight") else None,
                    bp=row.get("bp"),
                    sugar=float(row["sugar"]) if row.get("sugar") else None
                )
                db.session.add(entry)
            except Exception as e:
                print("Skipping invalid row:", row, str(e))
        db.session.commit()
        flash("CSV uploaded successfully.", "success")
    else:
        flash("Please upload a valid CSV file.", "danger")
    return redirect(url_for("personal_health_trends"))

@app.route("/export_health_data")
@login_required
def export_health_data():
    data = HealthData.query.filter_by(user_id=current_user.id).order_by(HealthData.date).all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["date", "weight", "bp", "sugar"])
    for row in data:
        cw.writerow([
            row.date.strftime("%Y-%m-%d"),
            row.weight or "",
            row.bp or "",
            row.sugar or ""
        ])
    output = io.BytesIO()
    output.write(si.getvalue().encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="text/csv", download_name="health_data.csv", as_attachment=True)


@app.route('/details', methods=['GET', 'POST'])
@login_required
def details():
    # Elder users fill their medical details on first login.
    user = User.query.get(current_user.get_id())
    if not user or user.role != 'elder':
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            user.weight = float(request.form.get('weight'))
        except (TypeError, ValueError):
            user.weight = None
        try:
            user.height = float(request.form.get('height'))
        except (TypeError, ValueError):
            user.height = None
        user.allergies = request.form.get('allergies')
        user.chronic_conditions = request.form.get('chronic_conditions')
        user.emergency_contact_name = request.form.get('contact_name')
        user.emergency_contact_email = request.form.get('contact_email')
        user.emergency_relationship = request.form.get('relationship')
        user.helper_preference = request.form.get('helper_preference')
        # Automatically assign a Health Advisor based on helper preference.
        preferred_advisors = HealthAdvisor.query.filter_by(gender=user.helper_preference.capitalize()).all()
        if preferred_advisors:
            assigned = random.choice(preferred_advisors)
            user.assigned_professional = f"{assigned.name} (Health Advisor)"
        else:
            flash("No Health Advisor available matching your preference at the moment.", "info")
            user.assigned_professional = None
        user.details_completed = True
        db.session.commit()
        flash("Medical details updated successfully.", "success")
        return redirect(url_for('dashboard'))
    return render_template('details.html', user=user)

@app.route('/update_details', methods=['GET', 'POST'])
@login_required
def update_details():
    user = User.query.get(current_user.get_id())
    if not user or user.role != 'elder':
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user.fullname = request.form.get('fullname')
        user.gender = request.form.get('gender')
        try:
            user.dob_day = int(request.form.get('dobDay'))
            user.dob_month = int(request.form.get('dobMonth'))
            user.dob_year = int(request.form.get('dobYear'))
        except (TypeError, ValueError):
            flash("Invalid Date of Birth.", "update_error")
            return render_template('update_details.html', user=user)
        user.phone = request.form.get('phone')
        try:
            user.weight = float(request.form.get('weight')) if request.form.get('weight') else None
        except ValueError:
            user.weight = None
        try:
            user.height = float(request.form.get('height')) if request.form.get('height') else None
        except ValueError:
            user.height = None
        user.allergies = request.form.get('allergies')
        user.chronic_conditions = request.form.get('chronic_conditions')
        user.emergency_contact_name = request.form.get('contact_name')
        user.emergency_contact_email = request.form.get('contact_email')
        user.emergency_relationship = request.form.get('relationship')
        user.helper_preference = request.form.get('helper_preference')
        preferred_advisors = HealthAdvisor.query.filter_by(gender=user.helper_preference.capitalize()).all()
        if preferred_advisors:
            assigned = random.choice(preferred_advisors)
            user.assigned_professional = f"{assigned.name} (Health Advisor)"
        else:
            flash("No Health Advisor available matching your preference at the moment.", "info")
            user.assigned_professional = None
        db.session.commit()
        flash("Profile details updated successfully.", "success")
        return redirect(url_for('dashboard'))
    return render_template('update_details.html', user=user)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = User.query.get(current_user.get_id())
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('dashboard'))
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash("Your account has been deleted.", "success")
    return redirect(url_for('home'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    # Works for all user types
    if hasattr(current_user, 'advisor'):
        pwd_obj = current_user.advisor
    elif hasattr(current_user, 'doctor'):
        pwd_obj = current_user.doctor
    else:
        pwd_obj = User.query.get(current_user.get_id())
    if not pwd_obj:
        flash("User not found.", "error")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        current_pass = request.form.get('current_password')
        new_pass = request.form.get('new_password')
        confirm_pass = request.form.get('confirm_password')
        if not check_password_hash(pwd_obj.password, current_pass):
            flash("Current password is incorrect.", "error")
            return render_template('change_password.html')
        if new_pass != confirm_pass:
            flash("New passwords do not match.", "error")
            return render_template('change_password.html')
        pwd_obj.password = generate_password_hash(new_pass)
        db.session.commit()
        flash("Password updated successfully.", "success")
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

@app.route('/advisor_chat', methods=['POST'])
@login_required
def advisor_chat():
    # Ensure the current user is an advisor.
    if not hasattr(current_user, 'advisor'):
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))
    advisor = current_user.advisor

    # Get the partner (patient) identifier and message content from the form.
    partner = request.form.get('partner')
    content = request.form.get('content', '').strip()
    if not partner or not content:
        flash("Missing chat partner or message content.", "error")
        return redirect(url_for('med_dashboard'))
    
    # Find the patient by either chat_nickname or fullname.
    patient = User.query.filter(
        (User.chat_nickname == partner) | (User.fullname == partner)
    ).first()
    if not patient:
        flash("Patient not found.", "error")
        return redirect(url_for('med_dashboard'))

    # Create and save the message with timezone-aware datetime.
    msg = Message(
        sender_id=advisor.id,
        sender_nickname=advisor.name,
        receiver_id=patient.id,
        content=content,
        timestamp=datetime.datetime.now(pytz.timezone("Asia/Kolkata"))
    )
    db.session.add(msg)
    db.session.commit()
    flash("Message sent to patient.", "success")
    return redirect(url_for('med_dashboard', selected_partner=partner))

# ---------------------------
# USER CHATROOM ROUTE
# ---------------------------
@app.route('/user_chatroom', methods=['GET', 'POST'])
@login_required
def user_chatroom():
    # Ensure this route is for a normal user (not admin/advisor/doctor)
    user = User.query.get(current_user.get_id())
    if user.role != 'elder':
        flash("This page is for regular users only.", "error")
        return redirect(url_for('dashboard'))
    
    # Retrieve the advisor assigned to the user based on their assigned professional.
    advisor = None
    if user.assigned_professional:
        advisor_name = user.assigned_professional.split(" (")[0]
        advisor = HealthAdvisor.query.filter_by(name=advisor_name).first()
    if not advisor:
        advisor = HealthAdvisor.query.first()
    
    # Query messages between this user and the advisor.
    messages = Message.query.filter(
        ((Message.sender_id == user.id) & (Message.receiver_id == advisor.id)) |
        ((Message.sender_id == advisor.id) & (Message.receiver_id == user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'chat':
            content = request.form.get('content', '').strip()
            if content:
                # Save chat message from user to advisor using the user's real fullname.
                msg = Message(
                    sender_id=user.id,
                    sender_nickname=user.fullname,
                    receiver_id=advisor.id,
                    content=content,
                    timestamp=datetime.datetime.now(pytz.timezone("Asia/Kolkata"))
                )
                db.session.add(msg)
                db.session.commit()
                flash("Message sent.", "success")
            else:
                flash("Message content cannot be empty.", "error")
        elif action == 'appointment':
            doctor_id = request.form.get('doctor_id')
            problem_description = request.form.get('problem_description', '').strip()
            if not doctor_id or not problem_description:
                flash("Please fill all appointment fields.", "error")
            else:
                # Create an appointment request with status "Requested"
                new_appt = Appointment(
                    patient_id=user.id,
                    advisor_id=advisor.id,
                    doctor_id=int(doctor_id),
                    problem_description=problem_description,
                    status="Requested",
                    created_at=datetime.datetime.now(pytz.timezone("Asia/Kolkata"))
                )
                db.session.add(new_appt)
                db.session.commit()
                flash("Appointment request sent.", "success")
        return redirect(url_for('user_chatroom'))
    
    # Get list of doctors for appointment request.
    doctors = Doctor.query.all()
    return render_template("user_chatroom.html", user=user, advisor=advisor, messages=messages, doctors=doctors)

# ---------------------------
# HEALTH ADVISOR DASHBOARD & APPOINTMENT FEATURES
# ---------------------------
@app.route('/med_dashboard', methods=['GET', 'POST'])
@login_required
def med_dashboard():
    # Ensure the current user is a health advisor.
    if not hasattr(current_user, 'advisor'):
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('login'))
    advisor = current_user.advisor

    if request.method == 'POST':
        # --- Handle creation of new appointment request ---
        if 'create_appointment' in request.form:
            try:
                patient_id = int(request.form.get('patient_id'))
            except (TypeError, ValueError):
                flash("Invalid patient selected.", "error")
                return redirect(url_for('med_dashboard'))
            doctor_id = request.form.get('doctor_id')
            problem_description = request.form.get('problem_description', '').strip()
            new_appt = Appointment(
                patient_id=patient_id,
                advisor_id=advisor.id,
                doctor_id=int(doctor_id) if doctor_id else None,
                problem_description=problem_description,
                status="Requested",   # Only a doctor can later approve and set the appointment time
                appointment_datetime=None,
                created_at=datetime.datetime.now(pytz.timezone("Asia/Kolkata"))
            )
            db.session.add(new_appt)
            db.session.commit()
            flash("New appointment request created successfully.", "success")
            return redirect(url_for('med_dashboard'))
        
        # --- Handle editing an existing appointment request ---
        elif 'appointment_id' in request.form:
            appointment_id = request.form.get('appointment_id')
            appt = Appointment.query.get(appointment_id)
            # Only allow edits if the appointment is still in the "Requested" state.
            if not appt or appt.status != "Requested":
                flash("Appointment cannot be edited.", "error")
                return redirect(url_for('med_dashboard'))
            appt.doctor_id = int(request.form.get('doctor_id'))
            appt.problem_description = request.form.get('problem_description')
            db.session.commit()
            flash("Appointment request updated successfully.", "success")
            return redirect(url_for('med_dashboard'))

    # --- GET Request: Retrieve data to display on the advisor dashboard ---
    assigned_patients = User.query.filter_by(assigned_professional=f"{advisor.name} (Health Advisor)").all()
    doctors = Doctor.query.all()
    appointments = Appointment.query.filter_by(advisor_id=advisor.id).all()

    # Build chat data: group messages between the advisor and each assigned patient.
    chat_data = {}
    for patient in assigned_patients:
        messages = Message.query.filter(
            ((Message.sender_id == patient.id) & (Message.receiver_id == advisor.id)) |
            ((Message.sender_id == advisor.id) & (Message.receiver_id == patient.id))
        ).order_by(Message.timestamp.asc()).all()
        if messages:
            # Use the real fullname of the patient (ignoring any chat nickname).
            key = patient.fullname
            chat_data[key] = messages

    return render_template("med_dashboard.html",
                           advisor=advisor,
                           users=assigned_patients,
                           doctors=doctors,
                           appointments=appointments,
                           chat_data=chat_data,
                           selected_partner=request.form.get("partner"))

   
@app.route('/delete_appointment/<int:appointment_id>', methods=['POST'])
@login_required
def delete_appointment(appointment_id):
    if not hasattr(current_user, 'advisor'):
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('login'))
    appt = Appointment.query.get(appointment_id)
    if not appt or appt.status != "Pending":
        flash("Appointment cannot be deleted.", "error")
    else:
        db.session.delete(appt)
        db.session.commit()
        flash("Appointment deleted.", "success")
    return redirect(url_for('med_dashboard'))

# ---------------------------
# DOCTOR DASHBOARD & APPOINTMENT RESPONSE
# ---------------------------
@app.route('/doc_dashboard.html')
@login_required
def doc_dashboard():
    if not hasattr(current_user, 'doctor'):
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('login'))
    
    doctor = current_user.doctor
    
    # Get pending and accepted appointments separately
    pending_appointments = Appointment.query.filter(
    Appointment.doctor_id == doctor.id,
    Appointment.status.in_(["Pending", "Requested"])
    ).all()

    approved_appointments = Appointment.query.filter_by(doctor_id=doctor.id, status="Accepted").all()
    
    # Build a dictionary of advisors for display purposes
    advisor_dict = {advisor.id: advisor for advisor in HealthAdvisor.query.all()}
    
    return render_template(
        'doc_dashboard.html',
        doctor=doctor,
        appointments=pending_appointments,
        approved_appointments=approved_appointments,
        advisors=advisor_dict
    )

@app.route('/respond_appointment/<int:appointment_id>', methods=['POST'])
@login_required
def respond_appointment(appointment_id):
    if not hasattr(current_user, 'doctor'):
        flash("Unauthorized access.", "login_error")
        return redirect(url_for('login'))
    doctor = current_user.doctor
    appt = Appointment.query.get(appointment_id)
    if not appt:
        flash("Appointment not found.", "error")
        return redirect(url_for('doc_dashboard'))
    action = request.form.get('action')
    if action == 'accept':
        appt_date_str = request.form.get('appointment_datetime')
        if appt_date_str:
            try:
                appt.appointment_datetime = datetime.datetime.strptime(appt_date_str, "%Y-%m-%dT%H:%M")
            except ValueError:
                flash("Invalid date/time format.", "error")
                return redirect(url_for('doc_dashboard'))
        appt.status = "Accepted"
        flash("Appointment accepted.", "success")
    elif action == 'reject':
        appt.status = "Rejected"
        flash("Appointment rejected.", "info")
    db.session.commit()
    return redirect(url_for('doc_dashboard'))

@app.route('/sos', methods=['GET', 'POST'])
@login_required
def sos():
    user = current_user
    if request.method == 'POST':
        user.emergency_contact_name = request.form['emergency_contact_name']
        user.emergency_contact_email = request.form['emergency_contact_email']
        user.emergency_relationship = request.form['emergency_relationship']
        user.default_sos_message = request.form['default_sos_message']
        db.session.commit()
        flash("SOS information updated successfully.", "success")
        return redirect(url_for('sos'))
    return render_template('sos.html', user=user)

@app.route('/send_sos', methods=['POST'])
@login_required
def send_sos():
    user = current_user
    sos_message = request.form.get('sos_message') or user.default_sos_message or "This is an emergency. Please help me!"

    subject = "Emergency SOS Alert"
    body = f"""
     SOS ALERT 

    {user.fullname} IS IN AN EMERGENCY !!!
    Message: {sos_message}
    """

    recipients = []
    if user.emergency_contact_email:
        recipients.append(user.emergency_contact_email)

   

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USER, EMAIL_PASS)
            for recipient in recipients:
                smtp.sendmail(EMAIL_USER, recipient, f"Subject: {subject}\n\n{body}")
        flash("SOS email sent successfully.", "success")
    except Exception as e:
        print("Error sending SOS:", e)
        flash("Failed to send SOS email.", "danger")

    return redirect(url_for('dashboard'))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
