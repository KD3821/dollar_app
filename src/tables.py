import sqlalchemy as sa
from sqlalchemy.orm import declarative_base


Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = sa.Column(sa.Integer, primary_key=True)
    email = sa.Column(sa.String, unique=True)
    is_admin = sa.Column(sa.Boolean, default=False)
    hashed_password = sa.Column(sa.String)


class OAuthClient(Base):
    __tablename__ = 'clients'

    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String, unique=True)
    hashed_password = sa.Column(sa.String)
    client_id = sa.Column(sa.String, unique=True)
    secret_key = sa.Column(sa.String)


class Wallet(Base):
    __tablename__ = 'wallets'
    id = sa.Column(sa.Integer, primary_key=True)
    owner = sa.Column(sa.String, unique=True)
    is_business = sa.Column(sa.Boolean, default=False)
    debit = sa.Column(sa.Numeric(10, 2))
    credit = sa.Column(sa.Numeric(10, 2))
    balance = sa.Column(sa.Numeric(10, 2))


class Service(Base):
    __tablename__ = 'services'

    id = sa.Column(sa.Integer, primary_key=True)
    client_id = sa.Column(sa.String, sa.ForeignKey('clients.client_id'))
    name = sa.Column(sa.String)
    is_reccurent = sa.Column(sa.Boolean, default=False)
    recurring_interval = sa.Column(sa.Integer, nullable=True)
    fee = sa.Column(sa.Numeric(8, 2))


class Operation(Base):
    __tablename__ = 'operations'
    id = sa.Column(sa.Integer, primary_key=True)
    account_number = sa.Column(sa.String, sa.ForeignKey('accounts.account_number'))
    service_id = sa.Column(sa.Integer, sa.ForeignKey('services.id'))
    service_name = sa.Column(sa.String)
    date = sa.Column(sa.DateTime)
    amount = sa.Column(sa.Numeric(8, 2))
    remaining_balance = sa.Column(sa.Numeric(10, 2))


class Account(Base):
    __tablename__ = 'accounts'

    id = sa.Column(sa.Integer, primary_key=True)
    user_email = sa.Column(sa.String, sa.ForeignKey('users.email'))
    account_number = sa.Column(sa.String, unique=True)
    client_id = sa.Column(sa.String, sa.ForeignKey('clients.client_id'))
    client_name = sa.Column(sa.String)
    registered_at = sa.Column(sa.DateTime)
    debit = sa.Column(sa.Numeric(10, 2))
    credit = sa.Column(sa.Numeric(10, 2))
    balance = sa.Column(sa.Numeric(10, 2))


class OAuthToken(Base):
    __tablename__ = 'tokens'
    id = sa.Column(sa.Integer, primary_key=True)
    refresh = sa.Column(sa.Boolean, default=False)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id'))
    user_email = sa.Column(sa.String, sa.ForeignKey('users.email'))
    client_name = sa.Column(sa.String, sa.ForeignKey('clients.name'))
    scope = sa.Column(sa.String, nullable=True)
    token = sa.Column(sa.String)
    expire_date = sa.Column(sa.DateTime)
    revoke_date = sa.Column(sa.DateTime, nullable=True)
    revoked = sa.Column(sa.Boolean, default=False)
