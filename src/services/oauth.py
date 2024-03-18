import random
import string
from datetime import datetime, timedelta
from decimal import Decimal

import pytz
from pydantic import ValidationError
from passlib.hash import bcrypt
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from fastapi import Depends, status
from fastapi.exceptions import HTTPException

from src import tables
from src.settings import dollar_settings
from src.database import get_session
from src.models.auth import User
from src.models.oauth import (
    OAuthClientCreate,
    OAuthClient,
    OAuthProvideResponse,
    OAuthRevokeRequest,
    IntrospectResponse,
    OAuthRefreshRequest,
    OAuthRefreshResponse,
    AccessToken,
    RefreshToken,
)


class OAuthService:
    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    @classmethod
    def verify_password(cls, password: str, hashed_password: str) -> bool:
        return bcrypt.verify(password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    def create_account(self, user: tables.User, client: tables.OAuthClient) -> None:
        timestamp = datetime.utcnow()

        timestamp_str = str(timestamp.timestamp())

        account = tables.Account(
            user_email=user.email,
            client_id=client.client_id,
            client_name=client.name,
            registered_at=timestamp,
            account_number=f"{user.id}{timestamp_str.split('.')[0]}",
            debit=Decimal('0.00'),
            balance=Decimal('0.00'),
            credit=Decimal('0.00')
        )

        self.session.add(account)
        self.session.commit()

    @classmethod
    def validate_user_token(cls, token: str) -> User:
        token_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid token',
            headers={'WWW-Authenticate': 'Bearer'}
        )

        try:
            payload = jwt.decode(
                token,
                dollar_settings.jwt_secret,
                algorithms=[dollar_settings.jwt_algorithm]
            )
        except JWTError:
            raise token_exception

        user_data = payload.get('user')

        try:
            user = User.model_validate(user_data)
        except ValidationError:
            raise token_exception

        return user

    @classmethod
    def create_token(cls, user: tables.User, client_id: str, token_type: str = 'access'):
        user_data = User.model_validate(user)

        now = datetime.utcnow()

        delta = 1200 if token_type == 'refresh' else dollar_settings.jwt_expiration  # hardcode 'exp'(20 min)

        payload = {
            'exp': now + timedelta(seconds=delta),
            'client_id': client_id,
            'user': user_data.model_dump()
        }

        if token_type == 'access':
            payload.update({'scope': 'read write introspection'})

        token = jwt.encode(
            payload,
            dollar_settings.jwt_secret,
            algorithm=dollar_settings.jwt_algorithm
        )

        if token_type == 'refresh':
            return RefreshToken(refresh=token, expire_date=payload.get('exp'))

        return AccessToken(access=token, expire_date=payload.get('exp'), scope=payload.get('scope'))

    def remind_creds(self, name: str, password: str) -> OAuthClient:
        authentication_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid client credentials',
            headers={'WWW-Authenticate': 'Bearer'}
        )

        client = (
            self.session
            .query(tables.OAuthClient)
            .filter(tables.OAuthClient.name == name)
            .first()
        )

        if not client:
            raise authentication_exception

        if not self.verify_password(password, client.hashed_password):
            raise authentication_exception

        return client

    def authenticate_client(self, client_id: str, secret_key: str) -> tables.OAuthClient:
        authentication_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid client credentials',
            headers={'WWW-Authenticate': 'Bearer'}
        )

        client = (
            self.session
            .query(tables.OAuthClient)
            .filter(tables.OAuthClient.client_id == client_id)
            .first()
        )

        if not client:
            raise authentication_exception

        if client.secret_key != secret_key:  # later implement 'hashed secret_key' check
            raise authentication_exception

        return client

    def authenticate_user(self, email: str, password: str) -> tables.User:
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

        return user

    def refresh_token(self, token_data: OAuthRefreshRequest) -> OAuthRefreshResponse | dict:
        client = self.authenticate_client(
            client_id=token_data.client_id,
            secret_key=token_data.client_secret
        )

        token = token_data.token

        user = self.validate_user_token(token)

        refresh_token = (
            self.session
            .query(tables.OAuthToken)
            .filter(tables.OAuthToken.refresh == True)
            .filter(tables.OAuthToken.revoked == False)
            .filter(tables.OAuthToken.token == token_data.token)
            .filter(tables.OAuthToken.client_name == client.name)
            .first()
        )

        if refresh_token:
            access_token = self.create_token(user, client.client_id)
            response_data = {
                'access_token': access_token.access,
                'expires_in': dollar_settings.jwt_expiration,
                'token_type': 'Bearer',
                'scope': access_token.scope,
            }
            access_t = tables.OAuthToken(
                user_id=user.id,
                user_email=user.email,
                client_name=client.name,
                token=access_token.access,
                expire_date=access_token.expire_date,
                scope=access_token.scope
            )
            self.session.add(access_t)
            self.session.commit()
            return OAuthRefreshResponse(**response_data)

        return {"error": "invalid refresh"}

    def revoke_tokens(self, token_data: OAuthRevokeRequest, revoke_all: bool = False) -> dict:
        client = self.authenticate_client(
            client_id=token_data.client_id,
            secret_key=token_data.client_secret
        )
        token_exists = (
            self.session
            .query(tables.OAuthToken)
            .filter(tables.OAuthToken.client_name == client.name)
            .filter(tables.OAuthToken.revoked == False)
            .filter(tables.OAuthToken.token == token_data.token)
            .first()
        )
        if token_exists:
            if revoke_all:
                active_tokens = (
                    self.session
                    .query(tables.OAuthToken)
                    .filter(tables.OAuthToken.client_name == client.name)
                    .filter(tables.OAuthToken.revoked == False)
                    .filter(tables.OAuthToken.user_email == token_exists.user_email)
                )
            else:
                active_tokens = (
                    self.session
                    .query(tables.OAuthToken)
                    .filter(tables.OAuthToken.client_name == client.name)
                    .filter(tables.OAuthToken.revoked == False)
                    .filter(tables.OAuthToken.user_email == token_exists.user_email)
                    .filter(tables.OAuthToken.refresh == False)
                )

            now = datetime.utcnow()

            for token in active_tokens:
                token.revoke_date = now
                token.revoked = True

            self.session.commit()
            return {"message": "token revoked"}

        return {"error": "no need for revoke"}

    def provide_oauth(self, data: dict) -> OAuthProvideResponse | dict:
        client = self.authenticate_client(
            client_id=data.get('client_id'),
            secret_key=data.get('secret_key')
        )

        user = self.authenticate_user(
            email=data.get('email'),
            password=data.get('password')
        )

        if user:
            account = (
                self.session
                .query(tables.Account)
                .filter(tables.Account.client_id == client.client_id)
                .filter(tables.Account.user_email == user.email)
                .first()
            )

            if account is None:
                self.create_account(user, client)

            valid_refresh_token = (
                self.session
                .query(tables.OAuthToken)
                .filter(tables.OAuthToken.client_name == client.name)
                .filter(tables.OAuthToken.revoked == False)
                .filter(tables.OAuthToken.user_email == user.email)
                .filter(tables.OAuthToken.refresh == False)
                .first()
            )
            if valid_refresh_token:
                revoke_request = OAuthRevokeRequest(
                    client_id=client.client_id,
                    client_secret=client.secret_key,
                    token=valid_refresh_token.token
                )

                self.revoke_tokens(revoke_request, revoke_all=True)

            access_token = self.create_token(user, client.client_id)
            refresh_token = self.create_token(user, client.client_id, 'refresh')

            response_data = {
                'access_token': access_token.access,
                'refresh_token': refresh_token.refresh,
                'expires_in': dollar_settings.jwt_expiration,
                'token_type': 'Bearer',
                'scope': access_token.scope,
            }
            access_t = tables.OAuthToken(
                user_id=user.id,
                user_email=user.email,
                client_name=client.name,
                token=access_token.access,
                expire_date=access_token.expire_date,
                scope=access_token.scope
            )
            refresh_t = tables.OAuthToken(
                user_id=user.id,
                user_email=user.email,
                client_name=client.name,
                token=refresh_token.refresh,
                expire_date=refresh_token.expire_date,
                refresh=True
            )

            self.session.add_all([access_t, refresh_t])
            self.session.commit()

            return OAuthProvideResponse(**response_data)
        return {"error": "invalid creds"}

    def register_client(self, client_data: OAuthClientCreate) -> OAuthClient:
        client_exists = (
            self.session
            .query(tables.OAuthClient)
            .filter(tables.OAuthClient.name == client_data.name)
            .first()
        )

        if client_exists:
            raise HTTPException(
                detail='OAuthClient with such name already exists.',
                status_code=status.HTTP_400_BAD_REQUEST
            )

        client_id_exists = True

        while client_id_exists:
            client_id_exists = False

            new_client_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))

            client_same_id = (
                self.session
                .query(tables.OAuthClient)
                .filter(tables.OAuthClient.client_id == new_client_id)
                .first()
            )
            if client_same_id:
                client_id_exists = True

        tmp_secret_key = self.hash_password(client_data.password + new_client_id + client_data.name)  # noqa
        new_secret_key = tmp_secret_key[-10:] + new_client_id[::2]

        client = tables.OAuthClient(
            name=client_data.name,
            hashed_password=self.hash_password(client_data.password),
            client_id=new_client_id,
            secret_key=new_secret_key  # later implement 'show once' logic and hash key before saving to DB
        )

        wallet = tables.Wallet(
            owner=new_client_id,
            is_business=True,
            debit=Decimal('0.00'),
            balance=Decimal('0.00'),
            credit=Decimal('0.00')
        )

        self.session.add_all([client, wallet])
        self.session.commit()

        return client

    def check_token(self, data: dict) -> IntrospectResponse | dict:
        now = datetime.utcnow()

        client = self.authenticate_client(
            client_id=data.get('client_id'),
            secret_key=data.get('secret_key')
        )

        token = data.get('token')

        try:
            payload = jwt.decode(
                token,
                dollar_settings.jwt_secret,
                algorithms=[dollar_settings.jwt_algorithm]
            )

            user_dict = payload.get('user')

            token_exists = (
                self.session
                .query(tables.OAuthToken)
                .filter(tables.OAuthToken.user_email == user_dict.get('email'))
                .filter(tables.OAuthToken.client_name == client.name)
                .filter(tables.OAuthToken.expire_date > now)
                .filter(tables.OAuthToken.token == token)
                .filter(tables.OAuthToken.revoked == False)
                .first()
            )

            if token_exists:
                return self.introspect_token(token=token_exists, client=client)

        except JWTError:
            print('jwt_error')  # need to create new_access if access expired between moments of send and receive

            user_token = (
                self.session
                .query(tables.OAuthToken)
                .filter(tables.OAuthToken.client_name == client.name)
                .filter(tables.OAuthToken.expire_date <= now)
                .filter(tables.OAuthToken.token == token)
                .first()
            )

            if user_token:
                valid_refresh_token = (
                    self.session
                    .query(tables.OAuthToken)
                    .filter(tables.OAuthToken.client_name == client.name)
                    .filter(tables.OAuthToken.user_email == user_token.user_email)
                    .filter(tables.OAuthToken.revoked == False)
                    .filter(tables.OAuthToken.refresh == True)
                    .filter(tables.OAuthToken.expire_date > now)
                    .first()
                )

                if valid_refresh_token:
                    return self.introspect_token(token=valid_refresh_token, client=client)

                else:
                    data = {"active": False, "revoke": True}

                    revoke_request = OAuthRevokeRequest(
                        client_id=client.client_id,
                        client_secret=client.secret_key,
                        token=token
                    )
                    result = self.revoke_tokens(token_data=revoke_request, revoke_all=True)

                    if result.get('error'):
                        data['error'] = result.get('error')

                    return data

        print('not_active')
        return {"active": False}

    def introspect_token(self, token: tables.OAuthToken, client: tables.OAuthClient) -> IntrospectResponse:
        exp = token.expire_date
        service_timezone = pytz.timezone("Europe/Moscow")
        utc_exp = pytz.utc.localize(exp)
        local_exp = utc_exp.astimezone(service_timezone)

        introspect_data = {
            'client_id': client.client_id,
            'username': token.user_email,
            'scope': token.scope,
            'exp': int(round(datetime.timestamp(local_exp))),
            'active': True,
            'refresh': token.refresh,
            'error': None
        }
        if token.refresh:
            introspect_data.update({'scope': 'attach user scope'})

            revoke_request = OAuthRevokeRequest(
                client_id=client.client_id,
                client_secret=client.secret_key,
                token=token.token
            )
            result = self.revoke_tokens(token_data=revoke_request, revoke_all=False)

            if result.get('error'):
                introspect_data['error'] = result.get('error')

        print(introspect_data)
        return IntrospectResponse(**introspect_data)
