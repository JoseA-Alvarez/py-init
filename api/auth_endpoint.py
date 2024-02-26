from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta

import services.users_crud as users_crud, schemas, services.auth as auth
import database
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt

router = APIRouter()



@router.post("/login")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(database.get_db)
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

    users_crud.update_user_tokens(db, user)
    return schemas.Token(access_token=access_token, refresh_token=refresh_token)

@router.post("/refresh", response_model=schemas.Token)
async def refresh_token(token: schemas.TokenUpdate, db: Session = Depends(database.get_db)):
    payload = jwt.decode(token.refresh_token, auth.SECRET_KEY_REFRESH, algorithms=[auth.ALGORITHM])

    email: str = payload.get("sub")
    user = users_crud.get_user_by_email(db, email)
    # add extra check : search user by refresh token: compare
    if (user is None):
        raise HTTPException(status_code=404, detail="User not found")
    if (auth.is_payload_expired(payload)):
        raise HTTPException(status_code=404, detail="Token expired")
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": email}, expires_delta=access_token_expires)
    refresh_token = auth.create_refresh_token(email)

    user = users_crud.get_user_by_email(db, email)
    user.refresh_token = refresh_token
    users_crud.update_user_tokens(db, user)

    return schemas.Token(access_token=access_token, refresh_token=refresh_token)






