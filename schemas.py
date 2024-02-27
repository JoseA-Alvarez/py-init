from pydantic import BaseModel

class UserBase(BaseModel):
    email: str
    name: str
    surname: str
    other: str

class UserProfileRead(BaseModel):
    name: str
    email: str
    surname: str
    other: str    

class UserProfileWrite(BaseModel):
    name: str
    surname: str
    other: str    
    password: str


class UserCreate(UserBase):
    password: str
    roles: list[str]
  
class UserUpdate(BaseModel):
    name: str
    surname: str
    other: str
    roles: list[str]


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

class UserUI(BaseModel):
    name: str
    email: str
    roles: list[str]
    access_token: str
    refresh_token: str