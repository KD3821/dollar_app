from pydantic import BaseModel, EmailStr


class BaseUser(BaseModel):
    email: EmailStr


class UserCreate(BaseUser):
    password: str


class User(BaseUser):
    id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access: str
    token_type: str | None = 'Bearer'
