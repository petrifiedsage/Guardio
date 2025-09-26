import os
import base64
import io
import json
import hashlib
from datetime import datetime
from time import time
from dotenv import load_dotenv
from functools import wraps

from flask import Flask, render_template, redirect, url_for, request, flash, send_file, abort, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from cryptography.fernet import Fernet
import google.generativeai as genai

import pyotp
import qrcode
import secrets

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
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_UPLOAD_MB', '10')) * 1024 * 1024  # MB limit

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = set((os.getenv('ALLOWED_EXTENSIONS') or 'txt,pdf,png,jpg,jpeg,gif').split(','))
ALLOWED_EXTENSIONS = {ext.strip().lower() for ext in ALLOWED_EXTENSIONS if ext.strip()}


# --- AI and Encryption Setup ---
fernet = Fernet(ENCRYPTION_KEY.encode())
genai.configure(api_key=GEMINI_API_KEY)

# --- Extensions Initialization ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Simple API Rate Limiter (per user or IP) ---
RATE_LIMIT_PER_MIN = int(os.getenv('RATE_LIMIT_PER_MIN', '60'))
_request_counts = {}

@app.before_request
def _rate_limit_guard():
    # Use effective limits (DB settings if present)
    limits = get_effective_limits() if 'get_effective_limits' in globals() else {
        'rate_limit_per_min': RATE_LIMIT_PER_MIN
    }
    limit = limits['rate_limit_per_min']
    identifier = None
    if current_user.is_authenticated:
        identifier = f"user:{current_user.id}"
    else:
        identifier = f"ip:{request.remote_addr}"
    now = int(time() // 60)  # current minute bucket
    key = (identifier, now)
    _request_counts[key] = _request_counts.get(key, 0) + 1
    if _request_counts[key] > limit:
        return abort(429)

# --- CSRF Protection (simple) ---
def _ensure_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token

def _validate_csrf():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        sent = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        if not sent or sent != session.get('_csrf_token'):
            abort(400)

app.jinja_env.globals['csrf_token'] = _ensure_csrf_token

@app.before_request
def _csrf_before_request():
    _ensure_csrf_token()
    _validate_csrf()

# --- RBAC Decorator ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helpers ---
def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    settings = AppSettings.query.first()
    if settings:
        return ext in settings.allowed_extensions_set()
    return ext in ALLOWED_EXTENSIONS

def get_effective_limits():
    settings = AppSettings.query.first()
    if settings:
        return {
            'max_upload_mb': settings.max_upload_mb,
            'allowed_extensions': settings.allowed_extensions_set(),
            'rate_limit_per_min': settings.rate_limit_per_min,
        }
    return {
        'max_upload_mb': int(os.getenv('MAX_UPLOAD_MB', '10')),
        'allowed_extensions': ALLOWED_EXTENSIONS,
        'rate_limit_per_min': RATE_LIMIT_PER_MIN,
    }

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


# --- Audit Blockchain Models ---

class AuditBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False, unique=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    actor_user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(100), nullable=False)
    metadata_json = db.Column(db.Text, nullable=False, default='{}')
    previous_hash = db.Column(db.String(64), nullable=False)
    block_hash = db.Column(db.String(64), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'index': self.index,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'actor_user_id': self.actor_user_id,
            'action': self.action,
            'metadata': json.loads(self.metadata_json or '{}'),
            'previous_hash': self.previous_hash,
            'block_hash': self.block_hash,
        }


class UserAuditMarker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    last_saved_block_index = db.Column(db.Integer, nullable=False, default=-1)


class AppSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    max_upload_mb = db.Column(db.Integer, nullable=False, default=int(os.getenv('MAX_UPLOAD_MB', '10')))
    allowed_extensions_csv = db.Column(db.String(255), nullable=False, default='txt,pdf,png,jpg,jpeg,gif')
    rate_limit_per_min = db.Column(db.Integer, nullable=False, default=int(os.getenv('RATE_LIMIT_PER_MIN', '60')))

    def allowed_extensions_set(self):
        return {e.strip().lower() for e in (self.allowed_extensions_csv or '').split(',') if e.strip()}

# --- Flask-Login User Loader ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Audit Helpers ---

def _compute_block_hash(index, timestamp_iso, actor_user_id, action, metadata_json, previous_hash):
    payload = f"{index}|{timestamp_iso}|{actor_user_id}|{action}|{metadata_json}|{previous_hash}"
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def append_audit(action, metadata=None, actor_user_id=None):
    metadata = metadata or {}
    metadata_json = json.dumps(metadata, sort_keys=True, separators=(',', ':'))
    last_block = AuditBlock.query.order_by(AuditBlock.index.desc()).first()
    next_index = 0 if last_block is None else last_block.index + 1
    previous_hash = '0' * 64 if last_block is None else last_block.block_hash
    timestamp = datetime.utcnow()
    timestamp_iso = timestamp.isoformat() + 'Z'
    block_hash = _compute_block_hash(next_index, timestamp_iso, actor_user_id, action, metadata_json, previous_hash)
    new_block = AuditBlock(
        index=next_index,
        timestamp=timestamp,
        actor_user_id=actor_user_id,
        action=action,
        metadata_json=metadata_json,
        previous_hash=previous_hash,
        block_hash=block_hash,
    )
    db.session.add(new_block)
    # caller is responsible for committing along with their operation
    return new_block

# --- Standard Routes (Login, Signup, etc.) ---

@app.route('/')
def landing():
    """Landing page route rendering the product hero section."""
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User signup route with username/email uniqueness and MFA bootstrap."""
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
        # Audit: user signup (commit with user)
        append_audit('USER_SIGNUP', {'username': username, 'email_provided': bool(email)}, actor_user_id=new_user.id)
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
    """User login with password and TOTP verification."""
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
                # Audit: successful login
                append_audit('USER_LOGIN', {'username': username}, actor_user_id=user.id)
                db.session.commit()
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
    """User file dashboard supporting folder navigation and uploads."""
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
            if not allowed_file(file.filename):
                flash('File type not allowed.', 'danger')
                return redirect(request.url)
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
            # Audit: file upload
            append_audit('FILE_UPLOAD', {'filename': file.filename, 'folder_id': folder_id}, actor_user_id=current_user.id)
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
    """Create a new folder for the current user; requires non-empty name."""
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
        # Audit: folder created
        append_audit('FOLDER_CREATE', {'folder_name': folder_name, 'parent_id': parent_id}, actor_user_id=current_user.id)
        db.session.commit()
        flash(f'Folder "{folder_name}" created successfully.', 'success')

    if parent_folder_id:
        return redirect(url_for('dashboard', folder_id=parent_folder_id))
    else:
        return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """Decrypt and stream a file owned by the current user."""
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    try:
        decrypted_data = fernet.decrypt(file.data)
        # Audit: file download (no content logged)
        append_audit('FILE_DOWNLOAD', {'file_id': file_id, 'filename': file.filename}, actor_user_id=current_user.id)
        db.session.commit()
        return send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=file.filename)
    except Exception:
        flash('Could not decrypt or download the file.', 'danger')
        return redirect(url_for('dashboard', folder_id=file.folder_id))

@app.route('/delete/file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete a file the current user owns, auditing the action."""
    file_to_delete = File.query.get_or_404(file_id)
    if file_to_delete.user_id != current_user.id:
        abort(403)
    parent_folder_id = file_to_delete.folder_id
    db.session.delete(file_to_delete)
    # Audit: file deleted
    append_audit('FILE_DELETE', {'file_id': file_id, 'filename': file_to_delete.filename}, actor_user_id=current_user.id)
    db.session.commit()
    flash('File deleted successfully.', 'success')
    return redirect(url_for('dashboard', folder_id=parent_folder_id))

@app.route('/delete/folder/<int:folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    """Delete an empty folder owned by the current user."""
    folder_to_delete = Folder.query.get_or_404(folder_id)
    if folder_to_delete.user_id != current_user.id:
        abort(403)
    if folder_to_delete.subfolders or folder_to_delete.files.first():
        flash('Cannot delete a non-empty folder.', 'danger')
        return redirect(url_for('dashboard', folder_id=folder_id))
    parent_folder_id = folder_to_delete.parent_id
    db.session.delete(folder_to_delete)
    # Audit: folder deleted
    append_audit('FOLDER_DELETE', {'folder_id': folder_id, 'folder_name': folder_to_delete.name}, actor_user_id=current_user.id)
    db.session.commit()
    flash('Folder deleted successfully.', 'success')
    return redirect(url_for('dashboard', folder_id=parent_folder_id))

# --- Password Manager Routes ---

@app.route('/password-manager')
@login_required
def password_manager():
    """Display the password manager page for the current user."""
    entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    return render_template('password_manager.html', entries=entries)

@app.route('/add-password', methods=['POST'])
@login_required
def add_password():
    """Add a password entry (encrypted at rest) for the current user."""
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
        # Audit: password entry added (no password logged)
        append_audit('PASSWORD_ADD', {'website': website, 'username': username}, actor_user_id=current_user.id)
        db.session.commit()
        flash('Password entry added successfully!', 'success')
    
    return redirect(url_for('password_manager'))

@app.route('/reveal-password/<int:entry_id>')
@login_required
def reveal_password(entry_id):
    """Return decrypted password for an entry owned by the current user."""
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    
    # Audit: password revealed (do not log secret)
    append_audit('PASSWORD_REVEAL', {'entry_id': entry_id, 'website': entry.website}, actor_user_id=current_user.id)
    db.session.commit()
    decrypted_password = fernet.decrypt(entry.encrypted_password).decode()
    return jsonify({'password': decrypted_password})

@app.route('/delete-password/<int:entry_id>', methods=['POST'])
@login_required
def delete_password(entry_id):
    """Delete a password entry owned by the current user."""
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    
    db.session.delete(entry)
    # Audit: password entry deleted
    append_audit('PASSWORD_DELETE', {'entry_id': entry_id, 'website': entry.website}, actor_user_id=current_user.id)
    db.session.commit()
    flash('Password entry deleted successfully.', 'success')
    return redirect(url_for('password_manager'))


# --- Admin Routes ---

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Displays the admin dashboard with comprehensive system analytics."""
    # Ensure this function is defined, imported, or accessible
    # from the AuditBlock model (as it was in the original project)
    from sqlalchemy import func

    users = User.query.all()
    
    # Calculate system statistics
    total_users = len(users)
    admin_users = len([u for u in users if u.role == 'admin'])
    regular_users = total_users - admin_users
    
    # File statistics
    total_files = File.query.count()
    total_folders = Folder.query.count()
    total_password_entries = PasswordEntry.query.count()
    
    # Storage statistics (approximate) - Added safer check
    total_storage_mb = 0
    for file in File.query.all():
        if file.data:
            total_storage_mb += len(file.data) / (1024 * 1024)  # Convert bytes to MB
    
    # User activity (files per user)
    user_stats = []
    for user in users:
        file_count = len(user.files)
        folder_count = len(user.folders)
        password_count = len(user.password_entries)
        
        # Get audit chain status
        try:
            # Reusing the existing function to get audit summary
            audit_summary = get_audit_chain_summary(user.id)
            audit_blocks = audit_summary['total_blocks']
            chain_valid = audit_summary['chain_valid']
        except Exception as e:
            # Handle case when audit system isn't fully set up
            audit_blocks = 0
            chain_valid = False
        
        user_stats.append({
            'user': user,
            'file_count': file_count,
            'folder_count': folder_count,
            'password_count': password_count,
            'audit_blocks': audit_blocks,
            'chain_valid': chain_valid
        })
    
    # Sort users by activity
    user_stats.sort(key=lambda x: x['file_count'] + x['password_count'], reverse=True)
    
    stats = {
        'total_users': total_users,
        'admin_users': admin_users,
        'regular_users': regular_users,
        'total_files': total_files,
        'total_folders': total_folders,
        'total_password_entries': total_password_entries,
        'total_storage_mb': round(total_storage_mb, 2),
        # Assuming you don't have separate logic for "recent," just use total counts for placeholder
        'recent_files': total_files, 
        'recent_passwords': total_password_entries,
        'user_stats': user_stats
    }
    
    # FIX: Ensure 'stats' is passed in the render_template call
    return render_template('admin_dashboard.html', users=users, stats=stats)


# --- Admin User Management ---
@app.route('/admin/user/<int:user_id>/update', methods=['POST'])
@login_required
@admin_required
def admin_update_user(user_id):
    user = User.query.get_or_404(user_id)
    new_username = request.form.get('username', user.username)
    new_email = request.form.get('email', user.email)
    new_role = request.form.get('role', user.role)
    changes = {}
    if new_username != user.username:
        changes['username'] = {'from': user.username, 'to': new_username}
        user.username = new_username
    if new_email != user.email:
        changes['email'] = {'from': user.email, 'to': new_email}
        user.email = new_email
    if new_role != user.role:
        changes['role'] = {'from': user.role, 'to': new_role}
        user.role = new_role
    db.session.add(user)
    append_audit('ADMIN_USER_UPDATE', {'user_id': user.id, 'changes': changes}, actor_user_id=current_user.id)
    db.session.commit()
    flash('User updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if current_user.id == user_id:
        flash('Admin cannot delete own account.', 'danger')
        return redirect(url_for('admin_dashboard'))
    user = User.query.get_or_404(user_id)
    append_audit('ADMIN_USER_DELETE', {'user_id': user.id, 'username': user.username}, actor_user_id=current_user.id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/backup', methods=['POST'])
@login_required
@admin_required
def admin_backup():
    # Return a JSON bundle with core tables and configuration snapshot
    users = [
        {'id': u.id, 'username': u.username, 'email': u.email, 'role': u.role}
        for u in User.query.all()
    ]
    blocks = [b.to_dict() for b in AuditBlock.query.order_by(AuditBlock.index.asc()).all()]
    snapshot = {
        'exported_at': datetime.utcnow().isoformat() + 'Z',
        'config': {
            'max_upload_mb': int(os.getenv('MAX_UPLOAD_MB', '10')),
            'allowed_extensions': sorted(list(ALLOWED_EXTENSIONS)),
            'rate_limit_per_min': RATE_LIMIT_PER_MIN,
        },
        'users': users,
        'audit_blocks': blocks,
    }
    payload = json.dumps(snapshot, indent=2)
    append_audit('ADMIN_BACKUP_EXPORT', {'user_count': len(users), 'block_count': len(blocks)}, actor_user_id=current_user.id)
    db.session.commit()
    return send_file(io.BytesIO(payload.encode('utf-8')), as_attachment=True, download_name='guardio_admin_backup.json', mimetype='application/json')


@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings():
    settings = AppSettings.query.first()
    if settings is None:
        settings = AppSettings()
        db.session.add(settings)
        db.session.commit()
    errors = {}
    if request.method == 'POST':
        raw_max = request.form.get('max_upload_mb', '').strip()
        raw_ext = request.form.get('allowed_extensions_csv', '').strip()
        raw_rate = request.form.get('rate_limit_per_min', '').strip()
        max_upload_mb = settings.max_upload_mb
        rate_limit_per_min = settings.rate_limit_per_min
        allowed_extensions_csv = settings.allowed_extensions_csv
        if not raw_max:
            errors['max_upload_mb'] = 'Required.'
        else:
            try:
                max_upload_mb = int(raw_max)
                if max_upload_mb < 1 or max_upload_mb > 1024:
                    errors['max_upload_mb'] = 'Must be between 1 and 1024.'
            except ValueError:
                errors['max_upload_mb'] = 'Must be a number.'
        if not raw_rate:
            errors['rate_limit_per_min'] = 'Required.'
        else:
            try:
                rate_limit_per_min = int(raw_rate)
                if rate_limit_per_min < 1 or rate_limit_per_min > 10000:
                    errors['rate_limit_per_min'] = 'Must be between 1 and 10000.'
            except ValueError:
                errors['rate_limit_per_min'] = 'Must be a number.'
        if not raw_ext:
            errors['allowed_extensions_csv'] = 'Provide at least one extension.'
        else:
            parts = [p.strip().lower() for p in raw_ext.split(',') if p.strip()]
            if not parts:
                errors['allowed_extensions_csv'] = 'Provide at least one extension.'
            elif any(not p.isalnum() for p in parts):
                errors['allowed_extensions_csv'] = 'Extensions must be alphanumeric (e.g., pdf,jpg).'
            else:
                allowed_extensions_csv = ','.join(sorted(set(parts)))

        if not errors:
            changes = {}
            if settings.max_upload_mb != max_upload_mb:
                changes['max_upload_mb'] = {'from': settings.max_upload_mb, 'to': max_upload_mb}
                settings.max_upload_mb = max_upload_mb
                app.config['MAX_CONTENT_LENGTH'] = max_upload_mb * 1024 * 1024
            if settings.allowed_extensions_csv != allowed_extensions_csv:
                changes['allowed_extensions_csv'] = {'from': settings.allowed_extensions_csv, 'to': allowed_extensions_csv}
                settings.allowed_extensions_csv = allowed_extensions_csv
            if settings.rate_limit_per_min != rate_limit_per_min:
                changes['rate_limit_per_min'] = {'from': settings.rate_limit_per_min, 'to': rate_limit_per_min}
                settings.rate_limit_per_min = rate_limit_per_min
            db.session.add(settings)
            append_audit('ADMIN_SETTINGS_UPDATE', {'changes': changes}, actor_user_id=current_user.id)
            db.session.commit()
            flash('Settings updated.', 'success')
            return redirect(url_for('admin_settings'))
        else:
            flash('Please correct the errors below.', 'danger')
    return render_template('admin_settings.html', settings=settings, errors=errors)

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

@app.route('/audit')
@login_required
def audit_view():
    is_admin = getattr(current_user, 'role', 'user') == 'admin'
    # Validate chain integrity (full chain)
    all_blocks = AuditBlock.query.order_by(AuditBlock.index.asc()).all()
    is_chain_valid = True
    previous_hash = '0' * 64
    for b in all_blocks:
        timestamp_iso = b.timestamp.isoformat() + 'Z'
        expected_hash = _compute_block_hash(b.index, timestamp_iso, b.actor_user_id, b.action, b.metadata_json, previous_hash)
        if expected_hash != b.block_hash:
            is_chain_valid = False
            break
        previous_hash = b.block_hash
    if is_admin:
        blocks = all_blocks
    else:
        # Show only GENESIS and blocks performed by the current user
        blocks = (
            AuditBlock.query
            .filter((AuditBlock.actor_user_id == current_user.id) | (AuditBlock.action == 'GENESIS'))
            .order_by(AuditBlock.index.asc())
            .all()
        )
    marker = UserAuditMarker.query.filter_by(user_id=current_user.id).first()
    last_saved = marker.last_saved_block_index if marker else -1
    return render_template('audit.html', blocks=blocks, last_saved=last_saved, is_admin=is_admin, is_chain_valid=is_chain_valid)


@app.route('/audit/export')
@login_required
def audit_export():
    is_admin = getattr(current_user, 'role', 'user') == 'admin'
    if is_admin:
        blocks = AuditBlock.query.order_by(AuditBlock.index.asc()).all()
    else:
        blocks = (
            AuditBlock.query
            .filter((AuditBlock.actor_user_id == current_user.id) | (AuditBlock.action == 'GENESIS'))
            .order_by(AuditBlock.index.asc())
            .all()
        )
    data = [b.to_dict() for b in blocks]
    scope = 'full' if is_admin else 'user'
    payload = json.dumps({'exported_at': datetime.utcnow().isoformat() + 'Z', 'scope': scope, 'user_id': None if is_admin else current_user.id, 'blocks': data}, indent=2)
    filename = 'audit_blockchain_full.json' if is_admin else f'audit_blockchain_user_{current_user.id}.json'
    return send_file(io.BytesIO(payload.encode('utf-8')), as_attachment=True, download_name=filename, mimetype='application/json')


@app.route('/audit/save', methods=['POST'])
@login_required
def audit_save_marker():
    last_block = AuditBlock.query.order_by(AuditBlock.index.desc()).first()
    latest_index = last_block.index if last_block else -1
    marker = UserAuditMarker.query.filter_by(user_id=current_user.id).first()
    if marker is None:
        marker = UserAuditMarker(user_id=current_user.id, last_saved_block_index=latest_index)
        db.session.add(marker)
    else:
        marker.last_saved_block_index = latest_index
    # Audit: user saved audit snapshot marker
    append_audit('AUDIT_SNAPSHOT_SAVE', {'saved_index': latest_index}, actor_user_id=current_user.id)
    db.session.commit()
    flash('Audit snapshot saved to your profile.', 'success')
    return redirect(url_for('audit_view'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

with app.app_context():
    # Ensure all tables exist; initialize genesis block if chain is empty
    db.create_all()
    if AuditBlock.query.count() == 0:
        append_audit('GENESIS', {'note': 'chain initialized'}, actor_user_id=None)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
