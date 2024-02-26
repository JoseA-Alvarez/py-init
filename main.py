from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta
from fastapi.middleware.cors import CORSMiddleware

import crud, models, schemas, auth
import database
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from typing import List

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

async def get_current_user(token: Annotated[str, Depends(auth.oauth2_scheme)], db: Session = Depends(get_db),  required_roles: List[str] = []):
    ## añadir roles
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
        if required_roles != []:
            roles: List[str] = payload.get("roles", [])
            if not any(role in roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email)
    except JWTError as error:
        if "Signature has expired" in str(error):
            raise token_expired_exception
    user = crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[schemas.User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.put("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user= crud.create_user(db=db, user=user)
    role_names = [role.name for role in db_user.roles]

    return schemas.User(id=db_user.id, email=db_user.email, name=db_user.name, 
                        surname=db_user.surname, other=db_user.other, 
                        is_active=db_user.is_active, 
                        roles=role_names)



@app.post("/users/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user: schemas.UserUpdate, db: Session = Depends(get_db)):
    print("USER",user.roles)
    db_user = crud.update_user(db, user_id, user)
    return db_user

@app.get("/users/", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users



@app.get("/users/{user_id}", response_model=schemas.UserCreate)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user_and_roles_by_id(db, user_id)
    print("ROLEEEE",db_user.roles)
    print("TOQUEEUEU EUE U",db_user.roles)

    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    role_names = [role.name for role in db_user.roles]


    return schemas.UserCreate(
        email=db_user.email, name=db_user.name, surname=db_user.surname, other=db_user.other, password="",
        roles=role_names
    )


@app.post("/login")
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
    for role in user.roles:
        print(role.name)

    access_token = auth.create_access_token(
        data={"sub": user.email, "roles": [role.name for role in user.roles]}, expires_delta=access_token_expires
    )
    refresh_token = auth.create_access_token2(
        data={"sub": user.email, "roles": [role.name for role in user.roles]}, expires_delta=access_token_expires
    )

    user.token = access_token
    user.refresh_token = refresh_token

    crud.update_user_tokens(db, user)
    return schemas.Token(access_token=access_token, refresh_token=refresh_token)

@app.post("/refresh", response_model=schemas.Token)
async def refresh_token(token: schemas.TokenUpdate, db: Session = Depends(get_db)):
    payload = jwt.decode(token.refresh_token, auth.SECRET_KEY_REFRESH, algorithms=[auth.ALGORITHM])

    email: str = payload.get("sub")
    user = crud.get_user_by_email(db, email)
    # add extra check : search user by refresh token: compare
    if (user is None):
        raise HTTPException(status_code=404, detail="User not found")
    if (auth.is_payload_expired(payload)):
        raise HTTPException(status_code=404, detail="Token expired")
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": email}, expires_delta=access_token_expires)
    refresh_token = auth.create_refresh_token(email)

    user = crud.get_user_by_email(db, email)
    user.refresh_token = refresh_token
    crud.update_user_tokens(db, user)

    return schemas.Token(access_token=access_token, refresh_token=refresh_token)






