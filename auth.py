from passlib.context import CryptContext
import crud

from datetime import datetime, timedelta, timezone

from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

import os
import base64
from dotenv import load_dotenv
import os

import time

# to get a string like this run:
# openssl rand -hex 32

load_dotenv()  # take environment variables from .env.


SECRET_KEY = os.getenv("SECRET_KEY")
SECRET_KEY_REFRESH = os.getenv("SECRET_KEY_REFRESH")


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(fake_db, username: str, password: str):
    user = crud.get_user_and_roles(fake_db, username)
    if not user:    
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

## Create a new token give the user data
def create_refresh_token(data: str):
    to_encode = {"sub": data}
    expire = datetime.now(timezone.utc) + timedelta(days=5)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_REFRESH, algorithm=ALGORITHM)
    return encoded_jwt

def create_access_token2(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=5)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_REFRESH, algorithm=ALGORITHM)
    return encoded_jwt


def generate_base64_random_number():
    # Generate a random number
    random_number = os.urandom(16)

    # Convert the random number to base64
    base64_number = base64.b64encode(random_number)

    return base64_number.decode()  # decode it to string from bytes



def is_token_expired(token, secret):
    try:
        print("Token: .----------- -- - - -- - -- - -", token)
        # Decode the token without verification to get the payload
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        # Get the current time
        current_time = time.time()
        # Check if the token is expired
        return current_time > payload.get('exp', 0)
    except JWTError as e:
        return True  # If the token can't be decoded, consider it as expired
    
def is_payload_expired(payload):
    try:
        print("Payload: .----------- -- - - -- - -- - -", payload)
        # Get the current time
        current_time = time.time()
        # Check if the token is expired
        return current_time > payload.get('exp', 0)
    except JWTError as e:
        print("Error: .----------- -- - - -- - -- - -", e)
        return True  # If the token can't be decoded, consider it as expired