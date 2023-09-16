from flask import Flask, request,render_template, redirect,session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_mail import Mail
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'
app.static_url_path = '/static'



# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Gmail SMTP server
app.config['MAIL_PORT'] = 587 # Port for TLS
app.config['MAIL_USE_TLS'] = True  # Use TLS (True for Gmail)
app.config['MAIL_USE_SSL'] = False # Do not use SSL
app.config['MAIL_USERNAME'] = 'joelflix0917@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'

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
                return render_template('locked.html')
            
            return render_template('login.html', error='Invalid Username or Password.')

    return render_template('login.html')

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