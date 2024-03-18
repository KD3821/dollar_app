from typing import List

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from src import tables
from src.database import get_session


class AccountsService:
    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def get_list(self, user_email: str) -> List[tables.Account]:
        query = self.session.query(tables.Account)
        query = query.filter_by(user_email=user_email)
        accounts = query.all()
        return accounts

    def get(self, user_email: str, account_number: str) -> tables.Account:
        account = (
            self.session
            .query(tables.Account)
            .filter_by(user_email=user_email)
            .filter_by(account_number=account_number)
            .first()
        )

        if not account:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        return account

    def delete(self,  user_email: str, account_number: str) -> None:
        account = self.get(user_email, account_number)

        if account.balance > 0:
            raise HTTPException(
                detail='Invalid request: account has available balance. Please contact support.',
                status_code=status.HTTP_400_BAD_REQUEST
            )

        self.session.delete(account)
        self.session.commit()
