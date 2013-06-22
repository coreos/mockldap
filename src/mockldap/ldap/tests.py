from ldapobject import LDAPObject
import unittest
import ldap

directory = {
    "cn=Manager,ou=example,o=test": {
        "userPassword": ["ldaptest"],
    },
    "cn=alice,ou=example,o=test": {
        "userPassword": ["alicepw"],
    },
    "cn=bob,ou=other,o=test": {
        "userPassword": ["bobpw"],
    },
}

class TestLDAPObject(unittest.TestCase):
    def setUp(self):
        self.ldap = LDAPObject(directory)

    def tearDown(self):
        self.ldap.reset()

    def test_set_option(self):
        self.ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
        self.assertEqual(self.ldap.get_option(ldap.OPT_X_TLS_DEMAND), True)

    def test_simple_bind_s_success(self):
        self.assertEqual(self.ldap.simple_bind_s("cn=alice,ou=example,o=test", "alicepw"), (97, []))

    def test_simple_bind_s_success_case_insensitive(self):
        self.assertEqual(self.ldap.simple_bind_s("cn=manager,ou=Example,o=test", "ldaptest"), (97, []))

    def test_fail_anon_simple_bind_s(self):
        self.assertEqual(self.ldap.simple_bind_s(), (97, []))

    def test_simple_bind_s_raise_no_such_object(self):
        self.assertRaises(ldap.NO_SUCH_OBJECT, self.ldap.simple_bind_s, "cn=blah,o=test", "password")

    def test_simple_bind_s_fail_login(self):
        self.assertRaises(ldap.INVALID_CREDENTIALS, self.ldap.simple_bind_s, "cn=alice,ou=example,o=test", "wrong")

    def test_search_s_get_directory_items_with_scope_onelevel(self):
        result = []
        for key, attrs in directory.iteritems():
            if key.endswith("ou=example,o=test"):
                result.append((key, attrs))
        self.assertEqual(self.ldap.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL, '(cn=*)'), result)

    def test_search_s_get_all_directory_items_with_scope_subtree(self):
        result = []
        for key, attrs in directory.iteritems():
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
