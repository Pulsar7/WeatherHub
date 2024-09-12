import os
from dotenv import load_dotenv


load_dotenv()


SERVER_HOST:str = os.getenv("SERVER_HOST", "")
SERVER_PORT:int = int(os.getenv("SERVER_PORT", 0))
SERVER_SSL_KEYFILEPATH:str = os.getenv("SERVER_SSL_KEYFILEPATH", "")
SERVER_SSL_CERTFILEPATH:str = os.getenv("SERVER_SSL_CERTFILEPATH", "")
SERVER_SSL_KEYFILEPASSWORD:str = os.getenv("SERVER_SSL_KEYFILEPASSWORD", "")
MAX_INCOMING_CONNECTIONS:int = int(os.getenv("MAX_INCOMING_CONNECTIONS", 0))
MAX_MSG_CHUNK_SIZE:int = int(os.getenv("MAX_MSG_CHUNK_SIZE", 0))
SOCKET_BUFFER_SIZE:int = int(os.getenv("SOCKET_BUFFER_SIZE", 0))
LOG_DIRPATH:str = os.getenv("LOG_DIRPATH", "")
LOG_FILENAME:str = os.getenv("LOG_FILENAME", "")
