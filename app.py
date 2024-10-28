from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os
from itsdangerous import URLSafeTimedSerializer

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Set a secret key for session management
app.config['SECRET_KEY'] = os.urandom(24)

# Configure the database URI
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'mymonsterlist.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure email settings using environment variables
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_SSL'] = True  # Use SSL for security
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Initialize the serializer
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Function to generate a password reset token
def generate_reset_token(email):
    return s.dumps(email, salt='password-reset-salt')

# Function to verify the token
def verify_reset_token(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Token valid for 1 hour
    except Exception:
        return None
    return email

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    display_name = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(150), unique=True, nullable=False)

# Monster Model
class Monster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    image_url = db.Column(db.String(250), nullable=True)
    flavour_profile = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/test_email')
def test_email():
    msg = Message('Test Email', recipients=['jhfgomesdesousa.lugh@gmail.com'])  # Change to your own email
    msg.body = 'This is a test email.'
    try:
        mail.send(msg)
        return 'Test email sent!'
    except Exception as e:
        return str(e)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        display_name = request.form['display_name']
        email = request.form['email']  # Get the email from the form
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash("Username already exists! Please choose a different one.")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash("Email already exists! Please choose a different one.")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, display_name=display_name, email=email, password=hashed_password)  # Save email
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! Please log in.")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Logged in successfully!")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password. Please try again.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        print("POST request received")  # Debugging line
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            print(f"User found: {user.username}")  # Debugging line
            token = generate_reset_token(user.email)
            msg = Message('Password Reset Request', recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}
If you did not make this request, simply ignore this email.
'''
            try:
                mail.send(msg)  # Ensure this line works correctly
                print("Email sent")  # Debugging line
                flash('A password reset email has been sent.', 'info')
            except Exception as e:
                print(f"Failed to send email: {str(e)}")  # Debugging line
                flash('Failed to send email. Please try again.', 'danger')
        else:
            print("No account associated with this email.")  # Debugging line
            flash('No account associated with this email.', 'warning')
        return redirect(url_for('login'))

    return render_template('request_password_reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)  # Implement this function
    if email is None:
        flash("This is an invalid or expired token.")
        return redirect(url_for('request_password_reset'))

    if request.method == 'POST':
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:  # Ensure the user exists before updating
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.commit()
            flash("Your password has been updated!")
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash("Logged out successfully.")
    return redirect(url_for('home'))

# Admin route to list all monsters
@app.route('/admin/monsters')
def admin_monsters():
    if 'user_id' not in session:
        flash("Please log in to access the admin page.")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:  # Check if the user is an admin
        flash("You do not have permission to access this page.")
        return redirect(url_for('home'))

    monsters = Monster.query.all()
    return render_template('admin/admin_monsters.html', monsters=monsters)

# Route to add a new monster
@app.route('/admin/monsters/add', methods=['GET', 'POST'])
def add_monster():
    if 'user_id' not in session:
        flash("Please log in to access the admin page.")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:  # Check if the user is an admin
        flash("You do not have permission to access this page.")
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        image_url = request.form['image_url']
        flavour_profile = request.form['flavour_profile']
        description = request.form['description']

        new_monster = Monster(name=name, image_url=image_url, flavour_profile=flavour_profile, description=description)
        db.session.add(new_monster)
        db.session.commit()
        flash("Monster added successfully!")
        return redirect(url_for('admin_monsters'))

    return render_template('admin/add_monster.html')

@app.route('/edit_monster/<int:monster_id>', methods=['GET', 'POST'])
def edit_monster(monster_id):
    if 'user_id' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:  # Check if the user is an admin
        flash("You do not have permission to access this page.")
        return redirect(url_for('home'))

    monster = Monster.query.get_or_404(monster_id)
    if request.method == 'POST':
        monster.name = request.form['name']
        monster.flavour_profile = request.form['flavour_profile']
        monster.image_url = request.form['image_url']
        monster.description = request.form['description']

        db.session.commit()
        flash("Monster updated successfully!")
        return redirect(url_for('admin_monsters'))

    return render_template('admin/edit_monster.html', monster=monster)

@app.route('/delete_monster/<int:monster_id>', methods=['POST'])
def delete_monster(monster_id):
    if 'user_id' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:  # Check if the user is an admin
        flash("You do not have permission to access this page.")
        return redirect(url_for('home'))

    monster = Monster.query.get_or_404(monster_id)
    db.session.delete(monster)
    db.session.commit()
    flash("Monster deleted successfully!")
    return redirect(url_for('admin_monsters'))

if __name__ == '__main__':
    app.run(debug=True)
