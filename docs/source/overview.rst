Overview
========

The goal of mockldap is to provide a mock instance of LDAPObject in response to
any call to ldap.initialize. In the general case, you would register return
values for all LDAPObject calls that you expect the code under test to make.
Your assertions would then verify that the tested code behaved correctly given
this set of return values from the LDAP APIs.

As a convenience, the mock LDAPObject isn't just a dumb mock object. The typical
way to use mockldap is to provide some static directory content and then let
:class:`~mockldap.ldapobject.LDAPObject` generate real return values. This will
only work for simple LDAP operations--this obviously isn't a complete Python
LDAP server implementation--but those simple operations tend to cover a lot of
cases.


.. _example:

Example
-------

::

    import unittest
    import ldap

    from mockldap import MockLdap

    class MyTestCase(unittest.TestCase):
        """
        A simple test case showing off some of the basic features of mockldap.
        """
        manager = ("cn=Manager,ou=example,o=test", {"userPassword": ["ldaptest"]})
        alice = ("cn=alice,ou=example,o=test", {"userPassword": ["alicepw"]})
        bob = ("cn=bob,ou=other,o=test", {"userPassword": ["bobpw"]})

        # This is the content of our mock LDAP directory. It takes the form
        # {dn: {attr: [value, ...], ...}, ...}.
        directory = dict([manager, alice, bob])

        @classmethod
        def setUpClass(cls):
            # We only need to create the MockLdap instance once. The content we
            # pass in will be used for all LDAP connections.
            cls.mockldap = MockLdap(cls.directory)

        def setUp(self):
            # Patch ldap.initialize
            self.mockldap.start()

        def tearDown(self):
            # Stop patching ldap.initialize and reset state.
            self.mockldap.stop()

        def test_some_ldap(self):
            """
            Some LDAP operations, including binds and simple searches, can be
            mimicked.
            """
            ldapobj = self.mockldap['ldap://localhost/']

            results = _do_simple_ldap_search()

            self.assertEquals(ldapobj.methods_called(), ['initialize', 'simple_bind_s', 'search_s'])
            self.assertEquals(sorted(results), sorted([self.manager, self.alice]))

        def test_complex_search(self):
            """
            Some LDAP operations, such as complex searches, are not implemented.
            If you're doing anything nontrivial, you have to set an explicit
            return value for a set of parameters.
            """
            ldapobj = self.mockldap['ldap://localhost/']
            ldapobj.search_s.seed('o=test', ldap.SCOPE_SUBTREE, '(|(cn=bob)(cn=alice))')([self.alice, self.bob])

            results = _do_complex_ldap_search()

            self.assertEquals(ldapobj.methods_called(), ['initialize', 'simple_bind_s', 'search_s'])
            self.assertEquals(sorted(results), sorted([self.alice, self.bob]))


    def _do_simple_ldap_search():
        conn = ldap.initialize('ldap://localhost/')
        conn.simple_bind_s('cn=alice,ou=example,o=test', 'alicepw')
        results = conn.search_s('ou=example,o=test', ldap.SCOPE_ONELEVEL, '(cn=*)')

        return results


    def _do_complex_ldap_search():
        conn = ldap.initialize('ldap://localhost/')
        conn.simple_bind_s('cn=alice,ou=example,o=test', 'alicepw')
        results = conn.search_s('o=test', ldap.SCOPE_SUBTREE, '(|(cn=bob)(cn=alice))')

        return results
