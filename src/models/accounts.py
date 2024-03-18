from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, EmailStr


class Account(BaseModel):
    id: int
    user_email: EmailStr
    account_number: str
    client_id: str
    client_name: str
    registered_at: datetime
    debit: Decimal
    credit: Decimal
    balance: Decimal

    class Config:
        from_attributes = True
