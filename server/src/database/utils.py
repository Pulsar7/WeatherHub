import bcrypt
#
from .models import User
from .database_manager import session
from src.constants import ClientType, ClientPermission


def hash_password(password:str) -> str:
    """Hash a password using bcrypt."""

    salt = bcrypt.gensalt()  # Generate a salt
    hashed_password = bcrypt.hashpw(password.encode(), salt)  # Hash the password
    return hashed_password.decode()  # Return the hashed password as a string

def verify_password(stored_password:str, provided_password:str) -> bool:
    """Verify a stored password against a provided password."""

    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

def authenticate_user(username:str, password:str) -> bool:
    """Authenticate a user by verifying their password."""

    user = get_user_by_username(username)
    if user:
        return verify_password(user.password, password)
    return False


def create_user(username:str, password:str, client_type:ClientType, client_permission:ClientPermission) -> User|None:
    """Create a new user and add to the database."""

    if not get_user_by_username(username):
        return None

    new_user = User(username=username, password=hash_password(password), client_type=client_type, client_permission=client_permission)
    session.add(new_user)
    session.commit()
    return new_user

def get_user_by_username(username:str) -> User|None:
    """Fetch a user by their username."""

    return session.query(User).filter_by(username=username).first()
