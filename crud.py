from sqlalchemy.orm import Session

import models, schemas, auth


def get_user(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate):
    fake_hashed_password =  auth.get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=fake_hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user_tokens(db: Session, user: schemas.User):
    print("Updating tokens", user.token)
    db_user = db.query(models.User).filter(models.User.id == user.id).one()
    db_user.refresh_token = user.refresh_token
    db.commit()
    db.refresh(db_user)
    return db_user

