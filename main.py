from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from fastapi.middleware.cors import CORSMiddleware

import crud, models, schemas, auth
import database
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt



app = FastAPI()
models.database.Base.metadata.create_all(bind=database.engine)


origins = [
    "http://localhost:4200",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: Annotated[str, Depends(auth.oauth2_scheme)], db: Session = Depends(get_db)):
    print("GET CURRENT USER ------------------------------------")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token_expired_exception = HTTPException(
        status_code=status.HTTP_406_NOT_ACCEPTABLE,
        detail="Token expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if auth.is_token_expired(token, auth.SECRET_KEY):
            raise token_expired_exception
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email)
    except JWTError:
        print("JWT ERROR ----------------------------")
        raise credentials_exception
    user = crud.get_user(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user




async def get_current_active_user(
    current_user: Annotated[schemas.User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user



@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@app.get("/users/", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@app.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user



@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)
) -> schemas.Token:
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    refresh_token = auth.create_access_token2(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    #refresh_token = auth.create_refresh_token(user.email)

    user.token = access_token
    user.refresh_token = refresh_token

    crud.update_user_tokens(db, user)
    return schemas.Token(access_token=access_token, refresh_token=refresh_token)

@app.post("/refresh", response_model=schemas.Token)
async def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    payload = jwt.decode(refresh_token, auth.SECRET_KEY_REFRESH, algorithms=[auth.ALGORITHM])

    email: str = payload.get("sub")
    user = crud.get_user_by_email(db, email)
    # add extra check : search user by refresh token: compare
    if (user is None):
        raise HTTPException(status_code=404, detail="User not found")
    if (auth.is_payload_expired(payload)):
        print ("Token expired")
        raise HTTPException(status_code=404, detail="Token expired")
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": email}, expires_delta=access_token_expires)
    refresh_token = auth.create_refresh_token(email)

    user = crud.get_user_by_email(db, email)
    user.refresh_token = refresh_token
    crud.update_user_tokens(db, user)

    return schemas.Token(access_token=access_token, refresh_token=refresh_token)






