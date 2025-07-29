#!/usr/bin/python

import uuid
import json

from AuthEncoding.AuthEncoding import pw_validate
from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import manage_users
from AccessControl.users import BasicUser
from AccessControl.SimpleObjectPolicies import _noroles
from AccessControl.class_init import InitializeClass
from OFS.userfolder import BasicUserFolder
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from ZPublisher import zpublish

import sqlalchemy
from sqlalchemy import create_engine, func, select, insert, update
from sqlalchemy.orm import Session, sessionmaker, scoped_session
from zope.sqlalchemy import register

from .schema import AppUser, AppRole, AppUserXRole, AppUserLogin


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


class DBAuth(BasicUserFolder):
    """
    Product to be placed in Zope for authenticating users against the database
    using a login cookie in the database.
    Adding this will create an acl_users object - you will want to add it to
    some subfolder of the application root.
    POST a request to acl_users/login with params username and password to
    generate a login and set a login cookie - the password should be stored as
    SSHA hash in appuser_password.
    Afterwards, accessing with this login cookie will authenticate for all
    access inside the folder with the roles given in appuserxgroup.
    """
    meta_type = "DB Auth"
    zmi_show_add_dialog = False
    zmi_icon = 'far fa-id-card'
    security = ClassSecurityInfo()
    security.declareProtected('View management screens', 'manage_main')

    manage_workspace = PageTemplateFile('zpt/main', globals())
    manage = manage_main = manage_workspace
    manage_main.__name__ = 'manage_main'
    manage_main._need__name__ = False
    manage.__name__ = 'manage'
    manage._need__name__ = False

    manage_options = []

    _connstr = "postgresql+psycopg://zope@/zope"

    def __init__(self, connstr=None):
        if connstr:
            self._connstr = connstr

    @security.protected(manage_users)
    def connstr(self):
        "Return connection string"
        return self._connstr

    def _session(self):
        """
        Get SQLAlchemy session.
        If the connection string changed, disconnects everything and creates a
        new engine and scoped session.
        """
        engine = getattr(self, '_v_sqlalchemy_engine', None)
        if engine and engine.url.render_as_string() != self._connstr:
            self._v_sqlalchemy_session.expire_all()
            engine = None
        if not engine:
            engine = create_engine(
                self._connstr,
                execution_options={"isolation_level": "AUTOCOMMIT"},
            )
            session = scoped_session(sessionmaker(bind=engine))
            self._v_sqlalchemy_engine = engine
            self._v_sqlalchemy_session = session
            register(session)
        return self._v_sqlalchemy_session()

    def _exec(self, stmt):
        "Execute an SQLAlchemy statement"
        result = self._session().execute(stmt)
        if isinstance(result._metadata,
                      sqlalchemy.engine.cursor._NoResultMetaData):
            return
        return result.scalars().all()

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
        appuser = self._exec(
            select(AppUser)
            .join(AppUserLogin)
            .where(AppUserLogin.cookie == cookie)
            .where(AppUserLogin.end.is_(None))
        )
        if not appuser:
            # Delegate to next level
            return
        username = appuser[0].name
        approles = self._exec(
            select(AppRole)
            .join(AppUserXRole)
            .where(AppUserXRole.appuser_id == appuser[0].id)
        )
        user = User(
            username,
            tuple(role.zoperole for role in approles),
        )
        # We found a user and the user wasn't the emergency user.
        # We need to authorize the user against the published object.
        if self.authorize(user, *context, roles):
            return user.__of__(self)
        if self.authorize(self._nobody, *context, roles):
            # The user is not allowed to access this, but Anonymous is?
            return self._nobody.__of__(self)
        # Otherwise we return None, delegating to the next level

    @zpublish(methods='POST')
    @security.protected(manage_users)
    def manage_setConnstr(self, connstr):
        "Change connection string"
        self._connstr = connstr
        self.REQUEST.RESPONSE.redirect('manage_main')

    @zpublish(methods='POST')
    def login(self, username, password):
        """
        Check user and password and generate a cookie if successful.
        :param username: Username to try. Note that this is checked
            case-insensitive against the DB
        :password: password of the user

        :returns: JSON encoded:
        {
            "success": bool, if login was successful,
            "username": Actual username in DB
        }
        Side effects: If successful, an entry is added to appuserlogin and the
        __user_login cookie is set.
        """
        resp = self.REQUEST.RESPONSE
        resp.setHeader('Content-Type', 'application/json')
        users = self._exec(
            select(AppUser)
            .where(func.lower(AppUser.name) == username.lower())
        )
        if not users:
            return json.dumps({'success': False})
        user = users[0]
        if not pw_validate(user.password, password):
            return json.dumps({'success': False})
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
        return json.dumps({
            'success': True,
            'username': user.name,
        })

    def logout(self):
        """
        Log out current user.
        Expires the login on the DB and expires the cookie.
        """
        cookie = self.REQUEST.cookies.get('__user_login')
        resp = self.REQUEST.RESPONSE
        resp.setHeader('Content-Type', 'application/json')
        if not cookie:
            return json.dumps({'success': False})
        self._exec(
            update(AppUserLogin)
            .where(AppUserLogin.cookie == cookie)
            .where(AppUserLogin.end.is_(None))
            .values(end=func.now())
        )
        resp.expireCookie('__user_login', path='/')
        return json.dumps({'success': True})


def add_DBAuth(self, REQUEST=None):
    """Add a DBAuth as acl_users"""
    obj = DBAuth()
    self._setObject('acl_users', obj)
    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_main')


InitializeClass(DBAuth)
