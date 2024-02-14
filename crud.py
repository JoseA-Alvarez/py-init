from sqlalchemy.orm import Session

import models, schemas, auth
from sqlalchemy.orm import joinedload

def get_user(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_user_and_roles(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).options(joinedload(models.User.roles)).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate):
    fake_hashed_password =  auth.get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=fake_hashed_password, name=user.name, surname=user.surname, other=user.other)

    rolete = db.query(models.Role).filter(models.Role.name == "admin").first()
    if rolete is None:
        rolete = models.Role(name="admin")
        db.add(rolete)
        db.commit()
        db.refresh(rolete)

    db_user.roles.append(rolete) # TODO añadimos admin por defecto 
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

