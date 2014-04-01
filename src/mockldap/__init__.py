from collections import defaultdict

from ldap.cidict import cidict

from .ldapobject import LDAPObject
from .recording import SeedRequired  # noqa


URI_DEFAULT = '__default__'


class MockLdap(object):
    """
    Top-level class managing directories and patches.

    :param directory: Default directory contents.

    After calling :meth:`~mockldap.MockLdap.start`, ``mockldap[uri]`` returns
    an :class:`~mockldap.LDAPObject`. This is the same object that will be
    returned by ``ldap.initialize(uri)``, so you can use it to seed return
    values and discover which APIs were called.
    """
    def __init__(self, directory=None):
        self.directories = {}
        self.ldap_objects = None
        self.patchers = {}

        if directory is not None:
            self.set_directory(directory)

    def __getitem__(self, uri):
        if self.ldap_objects is None:
            raise KeyError(
                "You must call start() before asking for mock LDAP objects.")

        return self.ldap_objects[uri]

    def set_directory(self, directory, uri=URI_DEFAULT):
        """
        Set the mock LDAP content for a given URI.

        :param uri: The LDAP URI to associate this content with.
        :type uri: string

        If URI is not given, this will set the default content for all unknown
        URIs.
        """
        if self.ldap_objects is not None:
            raise Exception("You can't add a directory after calling start().")

        self.directories[uri] = cidict(map_keys(lambda s: s.lower(), directory))

    def start(self, path='ldap.initialize'):
        """
        Patch :func:`ldap.initialize` to return mock LDAPObject instances. This
        calls :func:`mock.patch`, so you must have the `mock
        <https://pypi.python.org/pypi/mock/>`_ library installed.

        :param path: The module path to ``ldap.initialize``.
        :type path: string

        If the code under test looks like::

            import ldap
            ...
            ldap.initialize(uri)

        then you can use the default value of path. If the code reads::

            from ldap import initialize
            ...
            initialize(uri)

        then you need to call ``start('path.to.your.mod.initialize')``. See
        :ref:`where-to-patch` for more.
        """
        try:
            from unittest.mock import patch
        except ImportError:
            from mock import patch

        if path in self.patchers:
            raise ValueError("%r is already patched." % (path,))

        if self.ldap_objects is None:
            ldap_objects = map_values(LDAPObject, self.directories)
            self.ldap_objects = defaultdict(self._new_ldap_object,
                                            ldap_objects)

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
        """
        Stop patching :func:`ldap.initialize`.

        Calls to :meth:`~mockldap.MockLdap.start` and
        :meth:`~mockldap.MockLdap.stop` must be balanced. After the final call
        to stop, we'll reset all :class:`~mockldap.LDAPObject` instances.
        """
        if path not in self.patchers:
            raise ValueError("%r is not patched." % (path,))

        self.patchers[path].stop()
        del self.patchers[path]

        if len(self.patchers) == 0:
            self.ldap_objects = None

    def stop_all(self):
        """
        Remove all patches and reset our state.

        If you called :meth:`~mockldap.MockLdap.start` multiple times, this is
        the easiest way to reset everything.
        """
        for patcher in self.patchers.values():
            patcher.stop()

        self.patchers.clear()
        self.ldap_objects = None

    def initialize(self, uri, *args, **kwargs):
        ldap_object = self[uri]

        # For recording purposes only.
        ldap_object.initialize(uri, *args, **kwargs)

        return ldap_object


# Map a dictionary by applying a function to each key/value.
map_keys = lambda f, d: dict((f(k), v) for k, v in d.items())
map_values = lambda f, d: dict((k, f(v)) for k, v in d.items())
