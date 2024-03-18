from fastapi import APIRouter, Depends

from src.services.oauth import OAuthService
from src.models.oauth import (
    OAuthClientCreate,
    OAuthClient,
    OAuthProvideRequest,
    OAuthProvideResponse,
    OAuthRevokeRequest,
    IntrospectRequest,
    OAuthRefreshRequest,
    OAuthRefreshResponse,
)


router = APIRouter(
    prefix='/clients',
    tags=['OAuth Clients']
)


@router.post('/register/', response_model=OAuthClient)
def register(
    client_data: OAuthClientCreate,
    service: OAuthService = Depends()
):
    """
    Register Client of OAuth Service.
    """
    return service.register_client(client_data)


@router.post('/keys/', response_model=OAuthClient)
def keys(
    auth_data: OAuthClientCreate,
    service: OAuthService = Depends()
):
    """
    Request Client's service credentials
    """
    return service.remind_creds(name=auth_data.name, password=auth_data.password)


@router.post('/tokens/', response_model=OAuthProvideResponse)
def provide(
    oauth_data: OAuthProvideRequest,
    service: OAuthService = Depends()
):
    """
    Validate credentials or refresh token & Provide Access and Refresh tokens
    """
    data = {
        'client_id': oauth_data.client_id,
        'secret_key': oauth_data.client_secret,
        'email': oauth_data.username,
        'password': oauth_data.password,
    }
    return service.provide_oauth(data)


@router.post('/refresh/', response_model=OAuthRefreshResponse)
def refresh(
    token_data: OAuthRefreshRequest,
    service: OAuthService = Depends()
):
    """
    Refresh User's Access token
    """
    return service.refresh_token(token_data)


@router.post('/revoke_token/')
def revoke(
    token_data: OAuthRevokeRequest,
    service: OAuthService = Depends()
):
    """
    Revoke User's Access and Refresh tokens
    """
    return service.revoke_tokens(token_data, revoke_all=True)


@router.post('/introspect/')
async def introspect(
    introspect_data: IntrospectRequest,
    service: OAuthService = Depends()
):
    data = {
        'client_id': introspect_data.client_id,
        'secret_key': introspect_data.client_secret,
        'token': introspect_data.token
    }
    return service.check_token(data)
