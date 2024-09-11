import os, json
from os.dotenv import load_dotenv


load_dotenv()


SERVER_HOST:str = os.getenv("SERVER_HOST, "")
SERVER_PORT:int = int(os.getenv("SERVER_PORT, 0))
SERVER_TLS_KEYFILEPATH:str = os.getenv("SERVER_TLS_KEYFILEPATH", "")
SERVER_TLS_CERTFILEPATH:str = os.getenv("SERVER_TLS_CERTFILEPATH", "")
