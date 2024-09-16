import bcrypt
#
from .models import User, Station
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
    """Create a new user."""

    if get_user_by_username(username):
        return None

    try:
        new_user = User(username=username, password=hash_password(password), client_type=client_type, client_permission=client_permission)
        session.add(new_user)
        session.commit()
    except Exception as _e:
        return None
    return new_user

def create_new_station(user_id, station_name:str, station_location:str) -> User|None:
    """Create a new weather-station."""

    if get_station_by_name(station_name):
        return None

    try:
        new_station = Station(user_id=user_id, station_name=station_name, station_location=station_location)
        session.add(new_station)
        session.commit()
    except Exception as _e:
        return None
    return new_station

def change_user_password(username:str, new_password:str) -> tuple[bool, str|None]:
    """Change an user-password."""

    user:User|None = get_user_by_username(username)
    if not user:
        return (False, f"Something went wrong. There is no user with the username '{username}'")

    try:
        user.password = hash_password(new_password)
        session.commit()
        return (True, None)
    except Exception as _e:
        return (False, str(_e))

def get_all_users() -> list[User]:
    """Fetch all users."""
    return session.query(User).all()

def get_user_by_username(username:str) -> User|None:
    """Fetch a user by their username."""

    return session.query(User).filter_by(username=username).first()

def get_station_by_name(station_name:str) -> Station|None:
    """Fetch a station by their station-name."""

    return session.query(Station).filter_by(station_name=station_name).first()

def get_all_stations_by_user_id(user_id) -> list[Station]|None:
    """Fetch all stations by their user_id."""

    stations = session.query(Station).filter_by(user_id=user_id).all()
    return stations if stations else None

def delete_station(station:Station) -> bool:
    """Delete a station."""

    if not isinstance(station, Station):
        return False

    try:
        session.delete(station)
        session.commit()
        return True
    except Exception as _e:
        return False

def delete_user_by_user(user_to_delete:User) -> tuple[bool, str|None]:
    """Delete a user by its user-object."""

    try:
        # Deleting the user will also delete all associated stations
        session.delete(user_to_delete)
        session.commit()  # This will trigger the cascade and delete stations
        return (True, None)
    except Exception as _e:
        return (False, str(_e))
