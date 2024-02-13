from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Table
from sqlalchemy.orm import relationship

import database


# Tabla de asociación
user_roles = Table('user_roles', database.Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('role_id', Integer, ForeignKey('roles.id'))
)

class User(database.Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(128), unique=True, index=True)
    hashed_password = Column(String(1280))
    is_active = Column(Boolean, default=True)
    token = Column(String(1280))
    refresh_token = Column(String(1280))

    roles = relationship('Role', secondary=user_roles, back_populates='users')

class Role(database.Base):
    __tablename__ = 'roles'

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    users = relationship('User', secondary=user_roles, back_populates='roles')