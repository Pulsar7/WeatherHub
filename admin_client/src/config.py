import os
from dotenv import load_dotenv

load_dotenv()

TIMEZONE:str = os.getenv("TIMEZONE", "")
SERVER_CERTIFICATE_FILEPATH:str = os.getenv("SERVER_CERTIFICATE_FILEPATH", "")
CLIENT_CERTIFICATE_FILEPATH:str = os.getenv("CLIENT_CERTIFICATE_FILEPATH", "")
CLIENT_KEYFILE_PATH:str = os.getenv("CLIENT_KEYFILE_PATH", "")
CLIENT_KEYFILE_PASSWORD:str = os.getenv("CLIENT_KEYFILE_PASSWORD", "")
CLIENT_USERNAME:str = os.getenv("CLIENT_USERNAME", "")
CLIENT_PASSWORD:str = os.getenv("CLIENT_PASSWORD", "")
DEFAULT_MAX_MSG_CHUNK_SIZE:int = int(os.getenv("DEFAULT_MAX_MSG_CHUNK_SIZE", 0))
DEFAULT_BUFFER_SIZE:int = int(os.getenv("DEFAULT_BUFFER_SIZE", 0))
RESPONSECODE_SEPARATOR:str = os.getenv("RESPONSECODE_SEPARATOR", "")
