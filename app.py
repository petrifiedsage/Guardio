import os
import base64
import io
from dotenv import load_dotenv

from flask import Flask, render_template, redirect, url_for, request, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from cryptography.fernet import Fernet
from sqlalchemy.orm import backref

import pyotp
import qrcode

load_dotenv()

# --- App Initialization and Configuration ---

app = Flask(__name__)

# Load secret key from environment variable.
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("Error: SECRET_KEY not set. Make sure it's in your .env file.")
app.config['SECRET_KEY'] = SECRET_KEY

# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mfa_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Encryption Setup ---
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise ValueError("Error: ENCRYPTION_KEY not set. Make sure it's in your .env file.")
fernet = Fernet(ENCRYPTION_KEY.encode())


# --- Extensions Initialization ---

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---

class User(UserMixin, db.Model):
    """User model for storing user details."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
    
    # Relationships
    files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    folders = db.relationship('Folder', backref='owner', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User {self.username}>'

class Folder(db.Model):
    """Folder model for organizing files."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Self-referential relationship for nested folders
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'))
    parent = db.relationship('Folder', remote_side=[id], backref='subfolders')
    
    files = db.relationship('File', backref='folder', lazy='dynamic', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Folder {self.name}>'


class File(db.Model):
    """File model for storing encrypted user files."""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id')) # Link to a folder

    def __repr__(self):
        return f'<File {self.filename}>'


# --- Flask-Login User Loader ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # ... (Signup logic remains the same)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists. Please choose another.', 'danger')
            return redirect(url_for('signup'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        otp_secret = pyotp.random_base32()
        new_user = User(username=username, password_hash=hashed_password, email=email, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()
        provisioning_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name='FlaskMFAApp')
        qr_img = qrcode.make(provisioning_uri)
        buffered = io.BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_code_img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
        return render_template('show_qr.html', qr_code_img=qr_code_img_str)
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (Login logic remains the same)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(otp):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid 2FA token. Please try again.', 'danger')
        else:
            flash('Invalid username or password. Please try again.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

# --- File Manager Routes ---

@app.route('/dashboard', defaults={'folder_id': None}, methods=['GET', 'POST'])
@app.route('/dashboard/folder/<int:folder_id>', methods=['GET', 'POST'])
@login_required
def dashboard(folder_id):
    """Main dashboard view, acts as the file manager."""
    current_folder = None
    if folder_id:
        current_folder = Folder.query.get_or_404(folder_id)
        # Security check: ensure user owns the folder
        if current_folder.user_id != current_user.id:
            abort(403)

    # Handle file upload
    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
        elif file:
            encrypted_data = fernet.encrypt(file.read())
            new_file = File(
                filename=file.filename,
                data=encrypted_data,
                owner=current_user,
                folder_id=folder_id
            )
            db.session.add(new_file)
            db.session.commit()
            flash('File uploaded and encrypted successfully!', 'success')
        return redirect(url_for('dashboard', folder_id=folder_id))

    # Get contents for the current folder view
    if current_folder:
        folders = current_folder.subfolders
        files = current_folder.files
    else: # Root directory
        folders = Folder.query.filter_by(user_id=current_user.id, parent_id=None).all()
        files = File.query.filter_by(user_id=current_user.id, folder_id=None).all()

    return render_template('dashboard.html', files=files, folders=folders, current_folder=current_folder)


@app.route('/create-folder', methods=['POST'])
@login_required
def create_folder():
    """Creates a new folder."""
    folder_name = request.form.get('folder_name')
    parent_folder_id = request.form.get('parent_id') # Can be None for root
    
    if not folder_name:
        flash('Folder name cannot be empty.', 'danger')
    else:
        new_folder = Folder(
            name=folder_name,
            owner=current_user,
            parent_id=parent_folder_id if parent_folder_id else None
        )
        db.session.add(new_folder)
        db.session.commit()
        flash(f'Folder "{folder_name}" created successfully.', 'success')

    return redirect(url_for('dashboard', folder_id=parent_folder_id))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """Handles file decryption and download."""
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    try:
        decrypted_data = fernet.decrypt(file.data)
        return send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=file.filename)
    except Exception:
        flash('Could not decrypt or download the file.', 'danger')
        return redirect(url_for('dashboard', folder_id=file.folder_id))

@app.route('/delete/file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_to_delete = File.query.get_or_404(file_id)
    if file_to_delete.user_id != current_user.id:
        abort(403)
    
    parent_folder_id = file_to_delete.folder_id
    db.session.delete(file_to_delete)
    db.session.commit()
    flash('File deleted successfully.', 'success')
    return redirect(url_for('dashboard', folder_id=parent_folder_id))

@app.route('/delete/folder/<int:folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    folder_to_delete = Folder.query.get_or_404(folder_id)
    if folder_to_delete.user_id != current_user.id:
        abort(403)
    
    # Basic check: prevent deleting non-empty folders for simplicity
    if folder_to_delete.subfolders or folder_to_delete.files.first():
        flash('Cannot delete a non-empty folder.', 'danger')
        return redirect(url_for('dashboard', folder_id=folder_id))

    parent_folder_id = folder_to_delete.parent_id
    db.session.delete(folder_to_delete)
    db.session.commit()
    flash('Folder deleted successfully.', 'success')
    return redirect(url_for('dashboard', folder_id=parent_folder_id))


@app.route('/users')
@login_required
def users():
    """Serves the page that lists all registered users."""
    all_users = User.query.all()
    return render_template('users.html', users=all_users)

@app.route('/logout')
@login_required
def logout():
    """Logs the current user out."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

if __name__ == '__main__':
    app.run(debug=True)
