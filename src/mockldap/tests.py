from ldap.ldapobject import LDAPObject
import unittest
import ldap

directory = {
    "cn=Manager,ou=example,o=test": {
        "userPassword": ["ldaptest"],
    }
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
        self.assertEqual(self.ldap.simple_bind_s("cn=Manager,ou=example,o=test", "ldaptest"), (97, []))

    def test_fail_anon_simple_bind_s(self):
        self.assertEqual(self.ldap.simple_bind_s(), (97, []))

    def test_simple_bind_s_raise_no_such_object(self):
        self.assertRaises(ldap.NO_SUCH_OBJECT, self.ldap.simple_bind_s, "cn=blah,o=test", "password")

    def test_simple_bind_s_fail_login(self):
        self.assertRaises(ldap.INVALID_CREDENTIALS, self.ldap.simple_bind_s, "cn=Manager,ou=example,o=test", "wrong")
