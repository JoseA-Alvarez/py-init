from typing import List

from sqlalchemy.orm import Session

import models, schemas, services.auth as auth
from sqlalchemy.orm import joinedload




def get_user(db: Session, id: str):
    return db.query(models.User).filter(models.User.id == id).first()

def get_user_and_roles(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).options(joinedload(models.User.roles)).first()

def get_user_and_roles_by_id(db: Session, id: str):
    return db.query(models.User).filter(models.User.id == id).options(joinedload(models.User.roles)).first()

def get_user_profile(db: Session, id: str):
    return db.query(models.User).filter(models.User.id == id).first()

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()

def get_roles(db: Session, role_ids: List[int]):
    return db.query(models.Role).filter(models.Role.id.in_(role_ids)).all()

def create_user(db: Session, user: schemas.UserCreate):
    fake_hashed_password =  auth.get_password_hash(user.password)
    db_user = models.User(roles=[],email=user.email, hashed_password=fake_hashed_password, name=user.name, surname=user.surname, other=user.other)
    for role in user.roles: 
        rol = db.query(models.Role).filter(models.Role.name == role).first()
        if rol:
            db_user.roles.append(rol)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user_tokens(db: Session, user: schemas.User):
    db_user = db.query(models.User).filter(models.User.id == user.id).one()
    db_user.refresh_token = user.refresh_token
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user(db: Session, user_id: int, user: schemas.UserBase):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        return None
    for key, value in user.dict().items():
        if key == "roles":
            # Obtén los objetos Role correspondientes a los roles
            roles = db.query(models.Role).filter(models.Role.name.in_(value)).all()
            setattr(db_user, key, roles)
        else:
            setattr(db_user, key, value)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user_profile(db: Session, user_id: int, user: schemas.UserProfileWrite):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        return None
    if (user.password):
        db_user.hashed_password = auth.get_password_hash(user.password)

    db_user.name = user.name
    db_user.surname = user.surname
    db_user.other = user.other

    db.commit()
    db.refresh(db_user)
    return db_user