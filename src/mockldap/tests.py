from __future__ import absolute_import

from doctest import DocTestSuite
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import ldap

from . import MockLdap
from .ldapobject import LDAPObject


manager = ("cn=Manager,ou=example,o=test", {"userPassword": ["ldaptest"]})
alice = ("cn=alice,ou=example,o=test", {"userPassword": ["alicepw"]})
bob = ("cn=bob,ou=other,o=test", {"userPassword": ["bobpw", "bobpw2"]})
theo = ("cn=theo,ou=example,o=test", {"userPassword": [
    "{CRYPT}$1$95Aqvh4v$pXrmSqYkLg8XwbCb4b5/W/",
    "{CRYPT}$1$G2delXmX$PVmuP3qePEtOYkZcMa2BB/"]})

directory = dict([manager, alice, bob, theo])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()

    suite.addTests(tests)
    suite.addTest(DocTestSuite('mockldap.recording'))

    return suite


class TestLDAPObject(unittest.TestCase):
    def setUp(self):
        self.ldap = LDAPObject(directory)

    def test_set_option(self):
        self.ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
        self.assertEqual(self.ldap.get_option(ldap.OPT_X_TLS_DEMAND), True)

    def test_simple_bind_s_success(self):
        self.assertEqual(self.ldap.simple_bind_s("cn=alice,ou=example,o=test", "alicepw"), (97, []))

    def test_simple_bind_s_success_case_insensitive(self):
        self.assertEqual(self.ldap.simple_bind_s("cn=manager,ou=Example,o=test", "ldaptest"), (97, []))

    def test_simple_bind_s_anon_user(self):
        self.assertEqual(self.ldap.simple_bind_s(), (97, []))

    def test_simple_bind_s_raise_no_such_object(self):
        self.assertRaises(ldap.NO_SUCH_OBJECT, self.ldap.simple_bind_s, "cn=blah,o=test", "password")

    def test_simple_bind_s_fail_login(self):
        self.assertRaises(ldap.INVALID_CREDENTIALS, self.ldap.simple_bind_s, "cn=alice,ou=example,o=test", "wrong")

    def test_simple_bind_s_secondary_password(self):
        self.assertEqual(self.ldap.simple_bind_s("cn=bob,ou=other,o=test", "bobpw2"), (97, []))

    def test_simple_bind_s_success_crypt_password(self):
        self.assertEqual(self.ldap.simple_bind_s("cn=theo,ou=example,o=test", "theopw"), (97, []))

    def test_simple_bind_s_success_crypt_secondary_password(self):
        self.assertEqual(self.ldap.simple_bind_s("cn=theo,ou=example,o=test", "theopw2"), (97, []))

    def test_simple_bind_s_fail_crypt_password(self):
        self.assertRaises(ldap.INVALID_CREDENTIALS, self.ldap.simple_bind_s, "cn=theo,ou=example,o=test", "theopw3")

    def test_search_s_get_directory_items_with_scope_onelevel(self):
        result = []
        for key, attrs in directory.items():
            if key.endswith("ou=example,o=test"):
                result.append((key, attrs))
        self.assertEqual(self.ldap.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL, '(cn=*)'), result)

    def test_search_s_get_all_directory_items_with_scope_subtree(self):
        result = []
        for key, attrs in directory.items():
            if key.endswith("o=test"):
                result.append((key, attrs))
        self.assertEqual(self.ldap.search_s("o=test", ldap.SCOPE_SUBTREE, '(cn=*)'), result)

    def test_search_s_get_specific_item_with_scope_base(self):
        result = [("cn=alice,ou=example,o=test", directory["cn=alice,ou=example,o=test"])]
        self.assertEqual(self.ldap.search_s("cn=alice,ou=example,o=test", ldap.SCOPE_BASE), result)

    def test_search_s_get_specific_attr(self):
        result = [("cn=alice,ou=example,o=test", {"userPassword": ["alicepw"]})]
        self.assertEqual(self.ldap.search_s("cn=alice,ou=example,o=test", ldap.SCOPE_BASE, attrlist=["userPassword"]), result)

    def test_search_s_use_attrsonly(self):
        result = [("cn=alice,ou=example,o=test", {"userPassword": []})]
        self.assertEqual(self.ldap.search_s("cn=alice,ou=example,o=test", ldap.SCOPE_BASE, attrlist=["userPassword"], attrsonly=1), result)

    def test_search_s_scope_base_no_such_object(self):
        self.assertRaises(ldap.NO_SUCH_OBJECT, self.ldap.search_s, "cn=blah,ou=example,o=test", ldap.SCOPE_BASE)

    def test_search_s_empty_list(self):
        self.assertEqual(self.ldap.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL, '(uid=blah)'), [])


def initialize(*args, **kwargs):
    """ Dummy patch target for the tests below. """
    pass


class TestMockLdap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(directory)

    @classmethod
    def tearDownClass(cls):
        del cls.mockldap

    def tearDown(self):
        self.mockldap.stop_all()

    def test_uninitialized(self):
        self.assertRaises(KeyError, lambda: self.mockldap[''])

    def test_duplicate_patch(self):
        self.mockldap.start()

        self.assertRaises(ValueError, lambda: self.mockldap.start())

    def test_unbalanced_stop(self):
        self.assertRaises(ValueError, lambda: self.mockldap.stop())

    def test_stop_penultimate(self):
        self.mockldap.start()
        self.mockldap.start('mockldap.tests.initialize')
        self.mockldap.stop()

        self.assert_(self.mockldap[''] is not None)

    def test_stop_last(self):
        self.mockldap.start()
        self.mockldap.start('mockldap.tests.initialize')
        self.mockldap.stop()
        self.mockldap.stop('mockldap.tests.initialize')

        self.assertRaises(KeyError, lambda: self.mockldap[''])

    def test_initialize(self):
        self.mockldap.start()
        conn = ldap.initialize('ldap:///')

        self.assertEqual(conn.methods_called(), ['initialize'])

    def test_specific_content(self):
        tmp_directory = dict([alice, bob])
        self.mockldap.set_directory(tmp_directory, uri='ldap://example.com/')
        self.mockldap.start()
        conn = ldap.initialize('ldap://example.com/')

        self.assertEqual(conn.directory, tmp_directory)

    def test_no_default(self):
        mockldap = MockLdap()
        mockldap.start()

        self.assertRaises(KeyError, lambda: mockldap[''])

    def test_indepdendent_connections(self):
        self.mockldap.start()

        self.assertNotEqual(self.mockldap['foo'], self.mockldap['bar'])

    def test_volatile_modification(self):
        self.mockldap.start()
        conn1 = ldap.initialize('')
        conn1.directory['cn=alice,ou=example,o=test']['userPassword'][0] = 'modified'
        self.mockldap.stop()

        self.mockldap.start()
        conn2 = ldap.initialize('')
        self.mockldap.stop()

        self.assertNotEqual(conn1.directory, conn2.directory)
