from datetime import datetime, timedelta
from typing import Annotated
from decimal import Decimal

from pydantic import ValidationError
from jose import jwt, JWTError
from passlib.hash import bcrypt
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from src import tables
from src.database import get_session
from src.models.auth import User, Token, UserCreate
from src.settings import dollar_settings


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    return AuthService.validate_token(token)


class AuthService:
    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    @classmethod
    def verify_password(cls, password: str, hashed_password: str) -> bool:
        return bcrypt.verify(password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def validate_token(cls, token: str) -> User:
        credential_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid credentials',
            headers={'WWW-Authenticate': 'Bearer'}
        )

        try:
            payload = jwt.decode(
                token,
                dollar_settings.jwt_secret,
                algorithms=[dollar_settings.jwt_algorithm]
            )
        except JWTError:
            raise credential_exception

        if payload.get('exp') < datetime.timestamp(datetime.utcnow()):  # added
            raise credential_exception

        user_data = payload.get('user')

        try:
            user = User.model_validate(user_data)
        except ValidationError:
            raise credential_exception

        return user

    @classmethod
    def create_token(cls, user: tables.User):
        user_data = User.model_validate(user)

        now = datetime.utcnow()

        payload = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=dollar_settings.jwt_expiration),
            'sub': str(user_data.id),
            'user': user_data.model_dump()
        }

        token = jwt.encode(
            payload,
            dollar_settings.jwt_secret,
            algorithm=dollar_settings.jwt_algorithm
        )

        return Token(access=token)

    def register_user(self, user_data: UserCreate) -> Token:
        """
        Create User of Dollar Service and User's Wallet
        """
        user = (
            self.session
            .query(tables.User)
            .filter(tables.User.email == user_data.email)
            .first()
        )

        if user:
            raise HTTPException(
                detail='User with such Email is already registered. Do you want to reset password?',
                status_code=status.HTTP_400_BAD_REQUEST
            )

        user = tables.User(
            email=user_data.email,
            hashed_password=self.hash_password(user_data.password)
        )

        wallet = tables.Wallet(
            owner=user_data.email,
            debit=Decimal('50.00'),  # welcome bonus of $50 upon registration
            balance=Decimal('50.00'),
            credit=Decimal('0.00')
        )

        self.session.add_all([user, wallet])
        self.session.commit()

        return self.create_token(user)

    def authenticate_user(self, email: str, password: str) -> Token:
        authentication_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid email or password',
            headers={'WWW-Authenticate': 'Bearer'}
        )

        user = (
            self.session
            .query(tables.User)
            .filter(tables.User.email == email)
            .first()
        )

        if not user:
            raise authentication_exception

        if not self.verify_password(password, user.hashed_password):
            raise authentication_exception

        return self.create_token(user)
