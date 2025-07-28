import datetime

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import ForeignKey, DateTime


class Base(DeclarativeBase):
    pass


class AppUser(Base):
    """
    A user defined in the DB table appuser
    """
    __tablename__ = 'appuser'
    id: Mapped[int] = mapped_column('appuser_id', primary_key=True)
    name: Mapped[str] = mapped_column('appuser_name')
    # Encrypted password
    password: Mapped[str] = mapped_column('appuser_password')


class AppUserLogin(Base):
    """
    A user login with a cookie
    """
    __tablename__ = 'appuserlogin'
    id: Mapped[int] = mapped_column('appuserlogin_id', primary_key=True)
    appuser_id: Mapped[int] = mapped_column('appuserlogin_appuser_id',
                                            ForeignKey('appuser.appuser_id'))
    cookie: Mapped[str] = mapped_column('appuserlogin_cookie')
    end: Mapped[datetime.datetime] = mapped_column('appuserlogin_end',
                                                   DateTime(timezone=True))


class AppRole(Base):
    """
    A role that can be given to a user
    """
    __tablename__ = 'approle'
    id: Mapped[int] = mapped_column('approle_id', primary_key=True)
    zoperole: Mapped[str] = mapped_column('approle_zoperole')


class AppUserXRole(Base):
    """
    MxN table mapping users to roles
    """
    __tablename__ = 'appuserxrole'
    id: Mapped[int] = mapped_column('appuserxrole_id', primary_key=True)
    appuser_id: Mapped[int] = mapped_column('appuserxrole_appuser_id',
                                            ForeignKey('appuser.appuser_id'))
    approle_id: Mapped[int] = mapped_column('appuserxrole_approle_id',
                                            ForeignKey('approle.approle_id'))
