from .DBAuth import DBAuth, add_DBAuth


def initialize(registrar):
    registrar.registerClass(
        DBAuth,
        constructors=(add_DBAuth, ),
    )
