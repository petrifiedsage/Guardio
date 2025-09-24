# Guardio: Your Private, End-to-End Encrypted Cloud

![Guardio Landing Page](https://placehold.co/1200x600/6D5BDE/FFFFFF?text=Guardio)

**Guardio is a full-stack, security-first web application that gives you total control over your digital life. It combines an encrypted file manager and a secure password vault, all protected by robust Multi-Factor Authentication (MFA).**

---

## ✨ Features

Guardio is built on the principle of zero-knowledge privacy. We can't see your data, and no one else can either.

* 🔐 **Multi-Factor Authentication (MFA):** Secure your account beyond just a password. Guardio integrates with standard authenticator apps (like Google Authenticator or Authy) to provide time-based one-time password (TOTP) verification at login.

* 📂 **Encrypted File Manager:**
    * **Upload & Organize:** Upload your sensitive documents, photos, and files. Organize them with a simple and intuitive folder structure.
    * **End-to-End Encryption:** Every file is encrypted on the server with the powerful Fernet (AES-128) symmetric encryption before it's ever written to disk. Your files are stored as unreadable ciphertext.
    * **Secure Downloads:** Files are decrypted in memory only when you request them for download, ensuring your plain data is never exposed on the server.

* 🔑 **Encrypted Password Manager:**
    * **Secure Vault:** Store your website logins, passwords, and usernames in a centralized, secure vault.
    * **Zero-Knowledge:** Just like your files, your passwords are encrypted before being saved. The "Reveal" function decrypts them on-the-fly, only for you.

* 🛡️ **Admin Oversight (RBAC):**

### Audit Blockchain

All audit events are stored in a single, append-only blockchain with SHA-256 linking between blocks. Users can:

- View the full chain at the Audit page
- Export the chain as JSON
- Save a personal snapshot marker indicating the latest block they have acknowledged

Implementation details:

- Models: `AuditBlock`, `UserAuditMarker`
- Helper: `append_audit(action, metadata, actor_user_id)` computes and stores chained hashes
- Genesis block is created automatically on first run
    * The first user to register automatically becomes the **Admin**.
    * The admin panel provides a high-level overview of all registered users and allows the admin to see *what* is being stored (e.g., filenames, password entry websites) but not the encrypted content itself, respecting user privacy while allowing for system management.

---

## 🚀 Tech Stack

Guardio is built with a focus on security, reliability, and modern development practices.

| Category      | Technology                               | Purpose                                          |
|---------------|------------------------------------------|--------------------------------------------------|
| **Backend** | Python, Flask                            | Core application logic and routing.              |
| **Database** | SQLite via Flask-SQLAlchemy              | Data persistence for users, files, and passwords.|
| **Security** | Flask-Bcrypt, `cryptography`, `pyotp`    | Password hashing, data encryption, and MFA.      |
| **Frontend** | HTML, CSS (with Jinja2 Templating)       | User interface and design.                       |

---

## ⚙️ Getting Started

Follow these steps to set up and run a local instance of Guardio.

### 1. Prerequisites
* Python 3.8+
* A virtual environment tool (`venv`)

### 2. Setup Instructions

1.  **Clone & Enter:**
    ```bash
    git clone [https://your-repo-url.git](https://your-repo-url.git)
    cd guardio
    ```

2.  **Activate Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment:**
    * Create a `.env` file in the root directory.
    * Generate a secure encryption key:
        ```bash
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        ```
    * Add your keys to the `.env` file:
        ```
        SECRET_KEY='a_strong_random_string_for_flask_sessions'
        ENCRYPTION_KEY='your_generated_key_from_the_command_above'
        ```

5.  **Initialize the Database:**
    * This creates the `mfa_app.db` file with all necessary tables. **Run this only once.**
    ```bash
    python -c "from app import app, db; app.app_context().push(); db.create_all()"
    ```

6.  **Run the App:**
    ```bash
    flask run
    ```
    Guardio is now running at `http://127.0.0.1:5000`. The first account you create will be the admin.

