# WeatherHub

A small project to gather weather data from several weather stations, which are connected to a centralized server.

## Installation

To create a keyfile and the self-signed certificate for the TLS-encryption, you could use `openssl`:

```
# Generate keyfile
openssl genpkey -algorithm RSA -out keyfile_server.key -aes256

# Generate certificate signing request (CSR) - Fill in your data.
openssl req -new -key keyfile_server.key -out server.csr \
    -subj "/C=DE/ST=BIELEFELD/L=BIELEFELD/O=BIELEFELD GmbH/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in server.csr -signkey keyfile_server.key -out certfile_server.crt
```

In order to work, you have to create a `server/.env`-file with those values:

```
SERVER_HOST="localhost"
SERVER_PORT=1337
SERVER_SSL_KEYFILEPATH="ssl_files/keyfile_server.key"
SERVER_SSL_CERTFILEPATH="ssl_files/certfile_server.crt"
MAX_INCOMING_CONNECTIONS=10
MAX_MSG_CHUNK_SIZE=1024
SOCKET_BUFFER_SIZE=2048
LOG_DIRPATH="logs/"
LOG_FILENAME="weatherhub_server.log"
SERVER_SSL_KEYFILEPASSWORD=""
DATABASE_URI="sqlite:///instances/database.db"
RESPONSECODE_SEPARATOR="_#R#_"
```

And you need also a `admin-client/.env`:

```
TIMEZONE="UTC"
SERVER_CERTIFICATE_FILEPATH="ssl_files/certfile_server.crt"
CLIENT_CERTIFICATE_FILEPATH="ssl_files/certfile_client.crt"
CLIENT_KEYFILE_PATH="ssl_files/keyfile_client.key"
CLIENT_KEYFILE_PASSWORD=""
CLIENT_USERNAME=""
CLIENT_PASSWORD=""
DEFAULT_MAX_MSG_CHUNK_SIZE=1024
DEFAULT_BUFFER_SIZE=1024
RESPONSECODE_SEPARATOR="_#R#_"
```


Execute server-script manually:

```BASH
python3 main.py
```
