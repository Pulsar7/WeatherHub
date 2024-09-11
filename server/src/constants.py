from enum import Enum, auto


class ClientType(Enum):
    UNKNOWN = auto(),
    ADMIN = auto(),
    WEATHER_STATION = auto(),
    DATA_VIRTUALIZER = auto(),
    
