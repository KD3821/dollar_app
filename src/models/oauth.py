from datetime import datetime

from pydantic import BaseModel, EmailStr


class BaseOAuthClient(BaseModel):
    name: str


class OAuthClientCreate(BaseOAuthClient):
    password: str


class OAuthClient(BaseOAuthClient):
    id: int
    client_id: str
    secret_key: str

    class Config:
        from_attributes = True


class OAuthRefreshRequest(BaseModel):
    client_id: str
    client_secret: str
    token: str


class OAuthRefreshResponse(BaseModel):
    access_token: str
    expires_in: int
    token_type: str
    scope: str


class OAuthProvideRequest(BaseModel):
    client_id: str
    client_secret: str
    username: EmailStr
    password: str


class OAuthProvideResponse(OAuthRefreshResponse):
    refresh_token: str


class IntrospectRequest(OAuthRefreshRequest):
    pass


class IntrospectResponse(BaseModel):
    client_id: str
    username: EmailStr
    scope: str | None
    exp: int
    active: bool
    refresh: bool
    error: str | None


class OAuthRevokeRequest(OAuthRefreshRequest):
    pass


class AccessToken(BaseModel):
    access: str
    expire_date: datetime
    scope: str
    token_type: str = 'Bearer'


class RefreshToken(BaseModel):
    refresh: str
    expire_date: datetime
