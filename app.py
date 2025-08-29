import os
import base64
import io
from dotenv import load_dotenv
from functools import wraps

from flask import Flask, render_template, redirect, url_for, request, flash, send_file, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from cryptography.fernet import Fernet
import google.generativeai as genai

import pyotp
import qrcode

load_dotenv()

# --- App Initialization and Configuration ---

app = Flask(__name__)

# Load keys from environment variables
SECRET_KEY = os.getenv('SECRET_KEY')
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

if not all([SECRET_KEY, ENCRYPTION_KEY, GEMINI_API_KEY]):
    raise ValueError("One or more required environment variables are not set.")

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mfa_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_timeout': 30}


# --- AI and Encryption Setup ---
fernet = Fernet(ENCRYPTION_KEY.encode())
genai.configure(api_key=GEMINI_API_KEY)

# --- Extensions Initialization ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- RBAC Decorator ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def analyze_file_with_ai(file_data, filename):
    """Sends file content to Gemini for analysis."""
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        content_preview = file_data.decode('utf-8', errors='ignore')
        prompt = f"Analyze the following file content from a file named '{filename}'. Provide a one-sentence summary and state if it appears safe or potentially malicious. Content preview: {content_preview[:2000]}"
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"AI analysis failed: {e}")
        return "AI analysis could not be performed due to an error."
# --- Database Models ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    folders = db.relationship('Folder', backref='owner', lazy=True, cascade="all, delete-orphan")
    password_entries = db.relationship('PasswordEntry', backref='owner', lazy=True, cascade="all, delete-orphan")

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'))
    parent = db.relationship('Folder', remote_side=[id], backref='subfolders')
    files = db.relationship('File', backref='folder', lazy='dynamic', cascade="all, delete-orphan")

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ai_summary = db.Column(db.Text, nullable=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# --- Flask-Login User Loader ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Standard Routes (Login, Signup, etc.) ---

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        # FIX: Separate checks for username and email to handle blank emails correctly
        user_by_username = User.query.filter_by(username=username).first()
        if user_by_username:
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('signup'))

        # Only check for email uniqueness if an email is provided
        if email:
            user_by_email = User.query.filter_by(email=email).first()
            if user_by_email:
                flash('Email already exists. Please choose another.', 'danger')
                return redirect(url_for('signup'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        otp_secret = pyotp.random_base32()
        
        role = 'admin' if User.query.count() == 0 else 'user'

        new_user = User(
            username=username, 
            password_hash=hashed_password, 
            email=email, 
            otp_secret=otp_secret,
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        flash(f'Account created successfully! Your role is: {role}. Please set up MFA.', 'success')

        provisioning_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name='FlaskMFAApp')
        qr_img = qrcode.make(provisioning_uri)
        buffered = io.BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_code_img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
        return render_template('show_qr.html', qr_code_img=qr_code_img_str)
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
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
    current_folder = None
    if folder_id:
        current_folder = Folder.query.get_or_404(folder_id)
        if current_folder.user_id != current_user.id:
            abort(403)

    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        analyze = request.form.get('analyze_file')

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file:
            file_data = file.read()
            encrypted_data = fernet.encrypt(file_data)
            
            ai_summary = None
            if analyze:
                try:
                    decrypted_data_for_ai = fernet.decrypt(encrypted_data)
                    ai_summary = analyze_file_with_ai(decrypted_data_for_ai, file.filename)
                except Exception as e:
                    ai_summary = f"Could not perform AI analysis. Error: {e}"

            new_file = File(
                filename=file.filename,
                data=encrypted_data,
                owner=current_user,
                ai_summary=ai_summary,
                folder_id=folder_id
            )
            db.session.add(new_file)
            db.session.commit()
            flash('File uploaded successfully!', 'success')
        
        return redirect(url_for('dashboard', folder_id=folder_id))

    if current_folder:
        folders = current_folder.subfolders
        files = current_folder.files
    else: 
        folders = Folder.query.filter_by(user_id=current_user.id, parent_id=None).all()
        files = File.query.filter_by(user_id=current_user.id, folder_id=None).all()

    return render_template('dashboard.html', files=files, folders=folders, current_folder=current_folder)



@app.route('/create-folder', methods=['POST'])
@login_required
def create_folder():
    """Creates a new folder."""
    folder_name = request.form.get('folder_name')
    parent_folder_id = request.form.get('parent_id')
    
    if not folder_name:
        flash('Folder name cannot be empty.', 'danger')
    else:
        parent_id = int(parent_folder_id) if parent_folder_id else None
        
        new_folder = Folder(
            name=folder_name,
            owner=current_user,
            parent_id=parent_id
        )
        db.session.add(new_folder)
        db.session.commit()
        flash(f'Folder "{folder_name}" created successfully.', 'success')

    if parent_folder_id:
        return redirect(url_for('dashboard', folder_id=parent_folder_id))
    else:
        return redirect(url_for('dashboard'))

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
    if folder_to_delete.subfolders or folder_to_delete.files.first():
        flash('Cannot delete a non-empty folder.', 'danger')
        return redirect(url_for('dashboard', folder_id=folder_id))
    parent_folder_id = folder_to_delete.parent_id
    db.session.delete(folder_to_delete)
    db.session.commit()
    flash('Folder deleted successfully.', 'success')
    return redirect(url_for('dashboard', folder_id=parent_folder_id))

# --- Password Manager Routes ---

@app.route('/password-manager')
@login_required
def password_manager():
    """Displays the password manager page."""
    entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    return render_template('password_manager.html', entries=entries)

@app.route('/add-password', methods=['POST'])
@login_required
def add_password():
    """Adds a new password entry."""
    website = request.form.get('website')
    username = request.form.get('username')
    password = request.form.get('password')

    if not all([website, username, password]):
        flash('All fields are required.', 'danger')
    else:
        encrypted_password = fernet.encrypt(password.encode())
        new_entry = PasswordEntry(
            website=website,
            username=username,
            encrypted_password=encrypted_password,
            owner=current_user
        )
        db.session.add(new_entry)
        db.session.commit()
        flash('Password entry added successfully!', 'success')
    
    return redirect(url_for('password_manager'))

@app.route('/reveal-password/<int:entry_id>')
@login_required
def reveal_password(entry_id):
    """Decrypts and returns a password."""
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    
    decrypted_password = fernet.decrypt(entry.encrypted_password).decode()
    return jsonify({'password': decrypted_password})

@app.route('/delete-password/<int:entry_id>', methods=['POST'])
@login_required
def delete_password(entry_id):
    """Deletes a password entry."""
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    
    db.session.delete(entry)
    db.session.commit()
    flash('Password entry deleted successfully.', 'success')
    return redirect(url_for('password_manager'))


# --- Admin Routes ---

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Displays the admin dashboard with a list of all users."""
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/user/<int:user_id>')
@login_required
@admin_required
def user_details(user_id):
    """Displays the details of a specific user's stored items."""
    user = User.query.get_or_404(user_id)
    # The admin can see the files and password entries, but not the encrypted data itself.
    return render_template('user_details.html', user=user)


# --- General Routes ---

@app.route('/users')
@login_required
def users():
    all_users = User.query.all()
    return render_template('users.html', users=all_users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

if __name__ == '__main__':
    app.run(debug=True)
