from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Enum as SQLAlchemyEnum
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

    def __repr__(self):
        return (f"<User(id={self.id}, username={self.username}, "
                f"client_type={self.client_type}, client_permission={self.client_permission})>")
