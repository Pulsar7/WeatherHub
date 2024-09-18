import time
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, Float, String, Enum as SQLAlchemyEnum, ForeignKey
from sqlalchemy.orm import relationship
#
from src.constants import ClientType, ClientPermission

Base = declarative_base()

class User(Base):

    """Client users."""

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    client_type = Column(SQLAlchemyEnum(ClientType), nullable=False)
    client_permission = Column(SQLAlchemyEnum(ClientPermission), nullable=False)
    creation_timestamp = Column(Float, nullable=False, default=time.time())

    # Relationship to stations (one-to-many)
    stations = relationship("Station", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return (f"<User(id={self.id}, username={self.username}, "
                f"client_type={self.client_type}, client_permission={self.client_permission})>")


class Station(Base):
    """Weather Stations."""

    __tablename__ = 'stations'

    id = Column(Integer, primary_key=True)
    creation_timestamp = Column(Float, nullable=False, default=time.time)
    station_name = Column(String, nullable=False)
    station_location = Column(String, nullable=False)

    # Foreign key to reference the user who owns the station
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    # Relationship back to the user
    user = relationship("User", back_populates="stations")

    measurements = relationship("Measurement", back_populates="station", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Station(id={self.id}, station_name={self.station_name}, user_id={self.user_id})>"


class Measurement(Base):
    """Weather Station Measurements."""

    __tablename__ = 'measurements'

    id = Column(Integer, primary_key=True)
    timestamp = Column(Float, nullable=False, default=time.time)
    current_temperature_kelvin = Column(Float, nullable=False)
    current_wind_speed_kph = Column(Float, nullable=False)
    current_humidity_percent = Column(Float, nullable=False)
    current_pressure_hpa = Column(Float, nullable=False)

    # Foreign key to reference the station
    station_id = Column(Integer, ForeignKey('stations.id', ondelete='CASCADE'), nullable=False)

    # Relationship back to the station
    station = relationship("Station", back_populates="measurements")

    def __repr__(self):
        return (f"<Measurement(id={self.id}, timestamp={self.timestamp}, "
                f"temperature={self.current_temperature_kelvin}, "
                f"wind_speed={self.current_wind_speed_kph}, humidity={self.current_humidity_percent})>")
