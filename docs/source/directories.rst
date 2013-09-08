Mock Directories
================

The first step to using mockldap is to define some static LDAP content and
install it as a mock :class:`~mockldap.LDAPObject`. For this, you will use
:class:`mockldap.MockLdap`. Only one instance of this class should exist at a
time; :meth:`~unittest.TestCase.setUpClass` is a good place to instantiate it.

:class:`~mockldap.MockLdap` can mock multiple LDAP directories, identified by
URI. You can provide directory content for URIs individually and you can also
provide default content for connections to any unrecognized URI. If the code
under test is only expected to make one LDAP connection, the simplest option is
just to provide default content. If you need multiple directories, you can call
:meth:`~mockldap.MockLdap.set_directory` on your :class:`~mockldap.MockLdap`
instance.

LDAP content takes the form of a Python dictionary. Each key is a distinguished
name in string form; each value is a dictionary mapping attributes to lists of
values. In other words, ``directory.items()`` should take the same form as
results from :meth:`~ldap.LDAPObject.search_s`.

::

    directory = {
        'uid=alice,ou=people,o=test': {
            'uid': ['alice'],
            'objectClass': ['person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount'],
            'userPassword': ['password'],
            'uidNumber': ['1000'],
            'gidNumber': ['1000'],
            'givenName': ['Alice'],
            'sn': ['Adams']
        },
        'cn=active,ou=groups,o=test': {
            'cn': ['active'],
            'objectClass': ['groupOfNames'],
            'member': ['uid=alice,ou=people,o=test']
        },
    }

:class:`~mockldap.MockLdap` is stateful. The overview shows a complete
:ref:`example <example>`, but following are the enumerated steps.

For some collection of tests:

    - Instantiate :class:`~mockldap.MockLdap`. Optionally pass in default
      directory contents.
    - :meth:`Add content <mockldap.MockLdap.set_directory>` for any additional
      directories. This is only necessary if the code under test will connect to
      multiple LDAP directories.

For each test:

    - Just before an individual test, call :meth:`~mockldap.MockLdap.start`.
      This will instantiate your mock directories and patch
      :func:`ldap.initialize`. You may need to call this multiple times if
      :func:`~ldap.initialize` is accessed by multiple names.
    - Any time during your test, you can access an individual
      :class:`~mockldap.LDAPObject` as ``mockldap[uri]``. This will let you seed
      return values for LDAP operations and recover the record of which
      operations were performed.
    - After the test, call :meth:`~mockldap.MockLdap.stop` or
      :meth:`~mockldap.MockLdap.stop_all`.

.. warning::

    The code under test must not keep an LDAP "connection" open across
    individual test cases. If it does, it will be sharing a mock
    :class:`~mockldap.LDAPObject` across tests, so any state mutations will
    persist.


MockLdap
--------

.. autoclass:: mockldap.MockLdap
    :members:
