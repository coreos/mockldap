class LDAPError(Exception):
    pass


class INVALID_CREDENTIALS(LDAPError):
    pass


class NO_SUCH_OBJECT(LDAPError):
    pass


class NO_SUCH_ATTRIBUTE(LDAPError):
    pass


class ALREADY_EXISTS(LDAPError):
    pass


SCOPE_BASE = 0
SCOPE_ONELEVEL = 1
SCOPE_SUBTREE = 2

RES_SEARCH_RESULT = 101


class PresetReturnRequiredError(Exception):
    pass


OPT_X_TLS_DEMAND = False
