from typing import List, Annotated

from fastapi import APIRouter, Depends, Response, status

from src.models.accounts import Account
from src.services.accounts import AccountsService
from src.models.auth import User
from src.services.auth import get_current_user


router = APIRouter(
    prefix='/accounts',
    tags=['Business Accounts']
)

CurrentUser = Annotated[User, Depends(get_current_user)]


@router.get('/', response_model=List[Account])
def get_accounts(
    user: CurrentUser,
    service: AccountsService = Depends()
):
    """
    Get list of all User's Accounts registered in 'Accounting Service'.
    """
    return service.get_list(user_email=user.email)


@router.get('/{account_number}/', response_model=Account)
def get_account(
    user: CurrentUser,
    account_number: str,
    service: AccountsService = Depends()
):
    """
    Get info about User's account (Auth required)
    """
    return service.get(user_email=user.email, account_number=account_number)


@router.delete('/{account_number}/')
def delete_account(
    user: CurrentUser,
    account_number: str,
    service: AccountsService = Depends()
):
    """
    Delete Account (Auth required)
    """
    service.delete(user_email=user.email, account_number=account_number)

    return Response(status_code=status.HTTP_204_NO_CONTENT)
