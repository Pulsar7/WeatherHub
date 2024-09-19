import bcrypt
#
from .database_manager import session
from .models import User, Station, Measurement
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
        session.rollback()  # Rollback in case of error
        return None
    return new_user

def create_new_station(user_id, station_name:str, station_location:str) -> Station|None:
    """Create a new weather-station."""

    if get_station_by_name(station_name):
        return None

    try:
        new_station = Station(user_id=user_id, station_name=station_name, station_location=station_location)
        session.add(new_station)
        session.commit()
        return new_station
    except Exception as _e:
        session.rollback()  # Rollback in case of error
        return None

def add_measurement_to_station_by_station(station:Station, data:dict) -> tuple[bool, str|Measurement]:
    """Add a new measurement to a station by its station-object."""

    required_keys:list[str] = ["timestamp", "current_temperature_kelvin", "current_wind_speed_kph", "current_humidty_percent", "current_pressure_hpa"]

    if not station:
        return (False, "Given station is None.")

    for key in required_keys:
        if key not in list(data.keys()):
            return (False, f"The data-key '{key}' is missing.")
    try:
        new_measurement = Measurement(timestamp=data[required_keys[0]], current_temperature_kelvin=data[required_keys[1]], current_wind_speed_kph=data[required_keys[2]],
                            current_humidity_percent=data[required_keys[3]], current_pressure_hpa=data[required_keys[4]], station_id=station.id)
        session.add(new_measurement)
        session.commit()
        return (True, new_measurement)
    except Exception as _e:
        print(f"SOMETHING WENT FUCKING WRONG! DATA={data} => {_e}")
        session.rollback()  # Rollback in case of error
        return (False, str(_e))

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
        session.rollback()  # Rollback in case of error
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

def get_station_by_ID(station_id:int) -> Station|None:
    """Fetch a station by their station-ID."""

    return session.query(Station).filter_by(id=station_id).first()

def get_measurement_by_ID(measurement_id:int) -> Measurement|None:
    """Fetch a measurement by their measurement-ID."""

    return session.query(Measurement).filter_by(id=measurement_id).first()

def get_all_stations_by_user_id(user_id:int) -> list[Station]|None:
    """Fetch all stations by their user_id."""

    stations = session.query(Station).filter_by(user_id=user_id).all()
    return stations if stations else None

def get_all_measurements_of_station_by_station(station:Station) -> list[Measurement]|None:
    """Fetch all measurements of a station by its station-object."""

    measurements:list[Measurement]|None = session.query(Measurement).filter_by(station_id=station.id).all()
    return measurements if measurements else None

def delete_measurement(measurement:Measurement) -> tuple[bool, str|None]:
    """Delete a measurement."""

    if not isinstance(measurement, Measurement):
        return (False, "TypeError")

    try:
        session.delete(measurement)
        session.commit()
        return (True, None)
    except Exception as _e:
        session.rollback()
        return (False, str(_e))

def delete_station(station:Station) -> tuple[bool, str|None]:
    """Delete a station."""

    if not isinstance(station, Station):
        return (False, "TypeError")

    try:
        session.delete(station)
        session.commit()
        return (True, None)
    except Exception as _e:
        session.rollback()  # Rollback in case of error
        return (False, str(_e))

def delete_user_by_user(user_to_delete:User) -> tuple[bool, str|None]:
    """Delete a user by its user-object."""

    try:
        # Deleting the user will also delete all associated stations
        session.delete(user_to_delete)
        session.commit()  # This will trigger the cascade and delete stations
        return (True, None)
    except Exception as _e:
        session.rollback()  # Rollback in case of error
        return (False, str(_e))
