from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import services.users_crud as users_crud, schemas, services.auth as auth
import database
from typing import Annotated
from jose import JWTError, jwt
from typing import List

router = APIRouter()


async def get_current_user(token: Annotated[str, Depends(auth.oauth2_scheme)], 
                           db: Session = Depends(database.get_db),  
                           required_roles: List[str] = []):
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
    user = users_crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[schemas.User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@router.put("/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = users_crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user= users_crud.create_user(db=db, user=user)
    role_names = [role.name for role in db_user.roles]

    return schemas.User(id=db_user.id, email=db_user.email, name=db_user.name, 
                        surname=db_user.surname, other=db_user.other, 
                        is_active=db_user.is_active, 
                        roles=role_names)



@router.post("/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user: schemas.UserUpdate, db: Session = Depends(database.get_db)):
    print("USER",user.roles)
    db_user = users_crud.update_user(db, user_id, user)
    return db_user

@router.get("/", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db), 
               current_user: schemas.User = Depends(get_current_user)):
    users = users_crud.get_users(db, skip=skip, limit=limit)
    return users


@router.get("/{user_id}", response_model=schemas.UserCreate)
def read_user(user_id: int, db: Session = Depends(database.get_db)):
    db_user = users_crud.get_user_and_roles_by_id(db, user_id)

    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    role_names = [role.name for role in db_user.roles]

    return schemas.UserCreate(
        email=db_user.email, name=db_user.name, surname=db_user.surname, other=db_user.other, password="",
        roles=role_names
    )




