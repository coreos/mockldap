from collections import defaultdict

from .ldapobject import LDAPObject, SeedRequired


URI_DEFAULT = '__default__'


class MockLdap(object):
    """
    Top-level class managing directories and patches.
    """
    def __init__(self, directory=None):
        self.directories = {}
        self.ldap_objects = None
        self.patchers = {}

        if directory is not None:
            self.add_directory(directory)

    def __getitem__(self, uri):
        if self.ldap_objects is None:
            raise KeyError("You must call start() before asking for mock LDAP objects.")

        return self.ldap_objects[uri]

    def add_directory(self, directory, uri=URI_DEFAULT):
        self.directories[uri] = directory

    def start(self, path='ldap.initialize'):
        """
        Patch ldap.initialize() to return mock LDAPObject instances.
        """
        from mock import patch

        if path in self.patchers:
            raise ValueError("{0!r} is already patched.".format(path))

        if self.ldap_objects is None:
            ldap_objects = map_values(LDAPObject, self.directories)
            self.ldap_objects = defaultdict(self._new_ldap_object, ldap_objects)

        patcher = patch(path, new_callable=lambda: self.initialize)
        patcher.start()
        self.patchers[path] = patcher

    def _new_ldap_object(self):
        from .ldapobject import LDAPObject

        try:
            return LDAPObject(self.directories[URI_DEFAULT])
        except KeyError:
            raise KeyError("No default mock LDAP content provided")

    def stop(self, path='ldap.initialize'):
        if path not in self.patchers:
            raise ValueError("{0!r} has not been patched.".format(path))

        self.patchers[path].stop()
        del self.patchers[path]

        if len(self.patchers) == 0:
            self.ldap_objects = None

    def stop_all(self):
        for patcher in self.patchers.itervalues():
            patcher.stop()

        self.patchers.clear()
        self.ldap_objects = None

    def initialize(self, uri, *args, **kwargs):
        """
        A mock replacement for ldap.initialize(). This returns one of our
        LDAPObject instances.
        """
        ldap_object = self[uri]

        # For recording purposes only.
        ldap_object.initialize(uri, *args, **kwargs)

        return ldap_object


# Map a dictionary by applying a function to each value.
map_values = lambda f, d: dict((k, f(v)) for k, v in d.iteritems())
