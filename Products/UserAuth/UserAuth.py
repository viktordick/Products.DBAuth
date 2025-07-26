#!/usr/bin/python

import uuid

from AuthEncoding.AuthEncoding import pw_validate
from AccessControl import ClassSecurityInfo
from AccessControl.users import BasicUser
from AccessControl.SimpleObjectPolicies import _noroles
from AccessControl.class_init import InitializeClass
from OFS.ObjectManager import ObjectManager
from OFS.userfolder import BasicUserFolder
from ZPublisher import zpublish
from Products.PageTemplates.PageTemplateFile import PageTemplateFile

from zope.sqlalchemy import register
from sqlalchemy import create_engine, select, func, insert, ForeignKey
from sqlalchemy.orm import sessionmaker, scoped_session, DeclarativeBase
from sqlalchemy.orm import Mapped, mapped_column, Session


engine = create_engine("postgresql+psycopg://zope@/zope")
DBSession = scoped_session(sessionmaker(bind=engine))
register(DBSession)


class Base(DeclarativeBase):
    pass


class AppUser(Base):
    __tablename__ = 'appuser'
    id: Mapped[int] = mapped_column('appuser_id', primary_key=True)
    name: Mapped[str] = mapped_column('appuser_name')
    password: Mapped[str] = mapped_column('appuser_password')


class AppUserLogin(Base):
    __tablename__ = 'appuserlogin'
    id: Mapped[int] = mapped_column('appuserlogin_id', primary_key=True)
    appuser_id: Mapped[int] = mapped_column('appuserlogin_appuser_id',
                                            ForeignKey('appuser.appuser_id'))
    cookie: Mapped[str] = mapped_column('appuserlogin_cookie')


class User(BasicUser):

    # we don't want to support the domains thing
    domains = ()

    def __init__(self, name, roles=()):
        # bypass immutability
        data = self.__dict__
        data['name'] = name
        data['roles'] = roles
        data['extra'] = {}

    def __setattr__(self, name, value):
        # This type of user object should never get modified
        raise AttributeError('This object is immutable')

    def __getitem__(self, name):
        return self.extra[name]

    def _getPassword(self):
        """Return the password of the user - although in fact we don't, it is
        not necessary and we don't want to allow basic auth here."""
        return None

    def getDomains(self):
        """Return the list of domain restrictions for a user"""
        # This is always an empty tuple, since we don't support
        # domain restrictions.
        return ()

    def getRoles(self):
        """Return the list of roles assigned to a user."""
        return tuple(self.roles) + ('Authenticated', )

    def getUserName(self):
        """Return the username of a user"""
        return self.name


class UserAuth(BasicUserFolder):
    """
    Product to be placed in Zope for authenticating users against the database
    using a login cookie in the database.
    """
    meta_type = "User Auth"
    zmi_show_add_dialog = False
    security = ClassSecurityInfo()
    security.declareProtected('View management screens', 'manage_main')
    security.declareProtected('Manage users', 'getUserNames')

    manage_options = (
        ObjectManager.manage_options[0:1]
        + BasicUserFolder.manage_options[2:]
    )

    def _exec(self, stmt):
        return list(DBSession().scalars(stmt))

    def getUserNames(self):
        """Return a list of usernames"""
        return []

    def getUser(self, name):
        """Return the named user object or None"""
        users = self._exec(
            select(AppUser)
            .where(func.lower(AppUser.name) == name.lower())
        )
        if not users:
            return
        user = users[0]
        return User(user.name)

    def validate(self, request, auth='', roles=_noroles):
        """
        Check authentication. Here, we simply check for a login cookie and
        check it against the database. A separate method that is not tightly
        bound into the Zope authentication methods will allow checking the
        password of the user and generate a cookie if it is correct. We don't
        want to allow Basic Auth here.
        """
        value = request['PUBLISHED']  # the published object
        context = self._getobcontext(value, request)
        cookie = request.cookies.get('__user_login')
        if not cookie:
            return
        user = self._exec(
            select(AppUser)
            .join(AppUserLogin)
            .where(AppUserLogin.cookie == cookie)
        )
        if user:
            user = self.getUser(user[0].name)
        # We found a user and the user wasn't the emergency user.
        # We need to authorize the user against the published object.
        if user and self.authorize(user, *context, roles):
            return user.__of__(self)
        if user and self.authorize(self._nobody, *context, roles):
            # The user is not allowed to access this, but Anonymous is?
            return self._nobody.__of__(self)
        # Otherwise we return None, delegating to the next level

    _login_form = PageTemplateFile('zpt/login_form', globals())

    @zpublish
    def login_form(self):
        return self._login_form()

    @zpublish
    def login_action(self, username, password):
        """Check user and password and generate a cookie if successful."""
        resp = self.REQUEST.RESPONSE
        redirect = resp.redirect
        target = self.absolute_url()
        users = self._exec(
            select(AppUser)
            .where(func.lower(AppUser.name) == username.lower())
        )
        if not users:
            redirect(target)
            return
        user = users[0]
        if not pw_validate(user.password, password):
            redirect(target)
            return
        cookie = str(uuid.uuid4())
        self._exec(
            insert(AppUserLogin)
            .values(
                appuser_id=user.id,
                cookie=cookie,
            )
        )
        Session().commit()
        resp.setCookie(
            '__user_login',
            cookie,
            path='/',
            secure=self.REQUEST.URL.startswith('https://'),
            http_only=True,
            same_site='Strict',
        )
        redirect(target)


def add_UserAuth(self, REQUEST=None):
    """Add a UserAuth as acl_users"""
    obj = UserAuth()
    self._setObject('acl_users', obj)
    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_main')


InitializeClass(UserAuth)
