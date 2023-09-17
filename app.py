from flask import Flask,request,render_template,redirect,session,flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask import url_for
import bcrypt
import secrets
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.secret_key = 'secret_key'

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Gmail SMTP server
app.config['MAIL_PORT'] = 587 # Port for TLS
app.config['MAIL_USE_TLS'] = True  # Use TLS (True for Gmail)
app.config['MAIL_USE_SSL'] = False # Do not use SSL
app.config['MAIL_USERNAME'] = 'joelflix0917@gmail.com'
app.config['MAIL_PASSWORD'] = 'brzfqmhwvyhccuat'

mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self,email,password,name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

class ResetTokenModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False)
    expiration_time = db.Column(db.DateTime, nullable=False)

def generate_unique_token():
    return secrets.token_urlsafe(32)

def verify_reset_token(token):
    # Query the database for the reset token
    reset_token = ResetTokenModel.query.filter_by(token=token).first()

    if reset_token:
        # Check if the token has not expired
        if reset_token.expiration_time > datetime.datetime.now():
            return True

    return False 

# Initialize the login attempts session variable
def initialize_login_attempts():
    if 'login_attempts' not in session:
        session['login_attempts'] = 0
        session['last_failed_login'] = 0

with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        # handle request
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Check if any of the fields are empty
        if not name or not email or not password:
            return render_template('register.html', error='Please fill in all fields.')

        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            return render_template('register.html', error='Email already exists. Please use a different email instead.')
        
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters.')
        
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Account created successfully. You can now log in.', 'success')
            return redirect('/login')
        except IntegrityError:
            db.session.rollback()
            return render_template('register.html', error='An error occurred while creating your account. Please try again.')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    initialize_login_attempts()  # Initialize login attempts here
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            session['login_attempts'] = 0  # Reset login attempts on successful login
            return redirect('/dashboard')
        elif user is None:
            return render_template('login.html', error='User not found. Please <a href="/register">register</a>.')
        else:
            session['login_attempts'] += 1  # Increment login attempts

            if session['login_attempts'] == 3:
                return render_template('suspended.html')
            
            if session['login_attempts'] >= 6:
                session['login_attempts'] = 0
                msg = Message('Account Locked', sender='joelflix0917@gmail.com', recipients=[user.email])  
                msg.html = render_template('locked_email.html', name=user.name)
                mail.send(msg)
                return render_template('locked.html')
            
            return render_template('login.html', error='Invalid Username or Password.')

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        session['email'] = email
        # Check if the email exists in the database
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a unique reset token
            reset_token = generate_unique_token()
            # Set the expiration time (e.g., 24 hours from now)
            expiration_time = datetime.datetime.now() + datetime.timedelta(hours=24)
            # Create a ResetTokenModel object and store it in the database
            reset_token_obj = ResetTokenModel(token=reset_token, expiration_time=expiration_time)
            db.session.add(reset_token_obj)
            db.session.commit()
            # Send an email to the user with a link to reset their password
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            msg = Message('Password Reset', sender='joelflix0917@gmail.com', recipients=[user.email])
            msg.html = render_template('reset_email.html', reset_link=reset_link, name=user.name)
            mail.send(msg)
            return render_template('forgot_password.html',error='An email with instructions to reset your password has been sent.')
        else:
            return render_template('forgot_password.html',error='No user with that email address exists.')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        # Verify the reset token
        if verify_reset_token(token) and new_password == confirm_password:
            user = User.query.filter_by(email=session['email']).first()  # Retrieve the user based on their email or any other identifier
            
            if user:
                user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                db.session.commit()  # Commit the changes to the database
                flash('Your password has been reset successfully. You can now log in with your new password.', 'success')
                return redirect('/login')

        # user = verify_reset_token(token)
        # if user:
        #     # Check if the new password and confirmation match
        #     if new_password == confirm_password:
        #         # Update the user's password
        #         update_password(user, new_password)
        #         flash('Your password has been reset successfully. You can now log in with your new password.', 'success')
        #         return redirect('/login')

            else:
                flash('Passwords do not match.', 'danger')
        else:
            flash('Invalid or expired reset token.', 'danger')
    return render_template('reset_password.html', token=token)


@app.route('/dashboard')
def dashboard():
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html',user=user)
    
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)