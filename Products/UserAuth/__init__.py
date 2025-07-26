from .UserAuth import UserAuth, add_UserAuth


def initialize(registrar):
    registrar.registerClass(
        UserAuth,
        constructors=(add_UserAuth, ),
    )
