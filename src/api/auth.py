from typing import Annotated

from fastapi import APIRouter, Depends

from src.models.auth import UserCreate, Token, User
from src.services.auth import AuthService, get_current_user


router = APIRouter(
    prefix='/auth',
    tags=['Sign In - Sign Up']
)

CurrentUser = Annotated[User, Depends(get_current_user)]


@router.post('/register/', response_model=Token)
def register(
    user_data: UserCreate,
    service: AuthService = Depends()
):
    """
    Register User of Accounting Service
    """
    return service.register_user(user_data)


@router.post('/login/', response_model=Token)
def login(
    auth_data: UserCreate,
    service: AuthService = Depends()
):
    """
    Please use EMAIL as username to login via OAuthForm
    """

    return service.authenticate_user(auth_data.email, auth_data.password)


@router.get('/info/', response_model=User)
def retrieve_user(user: CurrentUser):
    """
    Get info about own account (Auth required)
    """
    return user
