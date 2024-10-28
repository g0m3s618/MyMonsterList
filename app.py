from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)

# Set a secret key for session management
app.config['SECRET_KEY'] = os.urandom(24)  # Generates a random 24-byte secret key

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure the database URI to save mymonsterlist.db in the project root directory
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'mymonsterlist.db')}"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    display_name = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # New field for admin status

# Monster Model
class Monster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    image_url = db.Column(db.String(250), nullable=True)  # URL for the image
    flavour_profile = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        display_name = request.form['display_name']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash("Username already exists! Please choose a different one.")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, display_name=display_name, password=hashed_password)
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

    monster = Monster.query.get(monster_id)
    if monster:
        db.session.delete(monster)
        db.session.commit()
        flash("Monster deleted successfully!")
    else:
        flash("Monster not found!")
    return redirect(url_for('admin_monsters'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates the database tables if they don't exist

        # Example of creating an admin user (optional)
        if not User.query.filter_by(username='admin').first():  # Prevents duplicate admin user
            admin_user = User(username='admin', display_name='Admin User',
                               password=bcrypt.generate_password_hash('adminpassword').decode('utf-8'),
                               is_admin=True)
            db.session.add(admin_user)
            db.session.commit()


    app.run(debug=True)
