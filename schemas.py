from pydantic import BaseModel

class UserBase(BaseModel):
    email: str
    name: str
    surname: str
    other: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    refresh_token: str


class TokenData(BaseModel):
    username: str | None = None,
    email: str | None = None

class TokenUpdate(BaseModel):
    refresh_token: str