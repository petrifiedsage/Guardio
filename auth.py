from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from flask import current_app

from models import db, User

# Signup function
def signup_user(username, email, password):
    # check if user exists
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return None, "User already exists"

    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, email=email, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return new_user, None

# Login function
def login_user(username, password):
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return None, "Invalid username or password"

    # generate JWT token
    token = jwt.encode(
        {
            "user_id": user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        },
        current_app.config["SECRET_KEY"],
        algorithm="HS256"
    )
    return token, None
