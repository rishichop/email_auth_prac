from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user
from itsdangerous import URLSafeTimedSerializer as Serializer


app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    verified = db.Column(db.Boolean, default=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

with app.app_context():
    db.create_all()

@app.route("/register", methods=['GET', 'POST']) 
def register(): 
    if request.method == 'POST': 
        email = request.form.get('email') 
        password = request.form.get('password') 
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if User.query.filter_by(email=email).first():
            print('Email address already registered. Please use a different one or log in.', 'danger')
            return redirect(url_for('login'))  

        user = User(email=email, password=hashed_password) 
        db.session.add(user) 
        db.session.commit()
        token = user.get_reset_token()
        send_verification_email(user, token)
        print('A verification email has been sent. Please check your inbox.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html')

def send_verification_email(user, token):
    msg = Message('Email Verification', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To verify your account, click on the following link:
                {url_for('verify_email', token=token, _external=True)}
                If you did not request this, please ignore this email.
                '''
    mail.send(msg)

@app.route("/verify_email/<token>") 
def verify_email(token): 
    user = User.verify_reset_token(token) 
    if user is None: 
        print('The verification link is invalid or has expired.', 'warning') 
        return redirect(url_for('register')) 
    user.verified = True 
    db.session.commit() 
    print('Your account has been verified!', 'success') 
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.verified:
                login_user(user)
                return redirect(url_for('home'))
            else:
                print('Please verify your email first.', 'warning')
                return redirect(url_for('login'))
        else:
            print('Login unsuccessful. Check email and password.', 'danger')
    return render_template('login.html')

@app.route("/home")
def home():
    return render_template("home.html")

if __name__ == "__main__":
    app.run(debug=True)
