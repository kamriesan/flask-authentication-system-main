from flask import Flask, request,render_template, redirect,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import time

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

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

        new_user = User(name=name,email=email,password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')



    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    initialize_login_attempts()  # Initialize login attempts session variable
    suspended = False

    if session['login_attempts'] >= 3:
        suspension_duration = 60  # Duration in seconds
        if time.time() - session['last_failed_login'] < suspension_duration:
            suspended = True

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password) and not suspended:
            session['email'] = user.email
            session['login_attempts'] = 0  # Reset login attempts on successful login
            return redirect('/dashboard')
        else:
            session['login_attempts'] += 1  # Increment login attempts
            if session['login_attempts'] >= 3:
                session['last_failed_login'] = time.time()
                return render_template('login.html', error=f'Invalid username or password. Login again after {session["last_failed_login"]} seconds.', suspended=True)
            else:
                return render_template('login.html', error='Invalid username or password.', suspended=suspended)

    return render_template('login.html', suspended=suspended)



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