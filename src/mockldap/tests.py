from __future__ import absolute_import, with_statement

from copy import copy
from doctest import DocTestSuite
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import ldap
import ldap.modlist
import ldap.filter
try:
    import passlib
except ImportError:
    passlib = None

from . import MockLdap
from .recording import SeedRequired


test = ("o=test", {"objectClass": ["top"]})
example = ("ou=example,o=test", {"objectClass": ["top"]})
other = ("ou=other,o=test", {"objectClass": ["top"]})

manager = ("cn=manager,ou=example,o=test", {
    "userPassword": ["ldaptest"],
    "objectClass": ["top", "posixAccount", "inetOrgPerson"]})
alice = ("cn=alice,ou=example,o=test", {
    "cn": ["alice"], "uid": ["alice"], "userPassword": ["alicepw"],
    "objectClass": ["top", "posixAccount"]})
theo = ("cn=theo,ou=example,o=test", {"userPassword": [
    "{CRYPT}$1$95Aqvh4v$pXrmSqYkLg8XwbCb4b5/W/",
    "{CRYPT}$1$G2delXmX$PVmuP3qePEtOYkZcMa2BB/"],
    "objectClass": ["top", "posixAccount"]})
john = ("cn=john,ou=example,o=test", {"objectClass": ["top"]})

bob = ("cn=bob,ou=other,o=test", {
    "userPassword": ["bobpw", "bobpw2"], "objectClass": ["top"]})

directory = dict([test, example, other, manager, alice, theo, john, bob])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()

    suite.addTests(tests)
    suite.addTest(DocTestSuite('mockldap.recording'))

    return suite


class TestLDAPObject(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(directory)

    @classmethod
    def tearDownClass(cls):
        del cls.mockldap

    def setUp(self):
        self.mockldap.start()
        self.ldapobj = self.mockldap['ldap://localhost']

    def tearDown(self):
        self.mockldap.stop()

    def test_manual_ldapobject(self):
        from .ldapobject import LDAPObject

        ldapobj = LDAPObject(directory)

        self.assertIsInstance(ldapobj.directory, ldap.cidict.cidict)

    def test_set_option(self):
        self.ldapobj.set_option(ldap.OPT_X_TLS_DEMAND, True)
        self.assertEqual(self.ldapobj.get_option(ldap.OPT_X_TLS_DEMAND), True)

    def test_simple_bind_s_success(self):
        result = self.ldapobj.simple_bind_s("cn=alice,ou=example,o=test", "alicepw")

        self.assertEqual(result, (97, []))

    def test_simple_bind_s_success_case_insensitive(self):
        result = self.ldapobj.simple_bind_s("cn=manager,ou=Example,o=test", "ldaptest")

        self.assertEqual(result, (97, []))

    def test_simple_bind_s_anon_user(self):
        result = self.ldapobj.simple_bind_s()

        self.assertEqual(result, (97, []))

    def test_simple_bind_s_fail_login_with_invalid_username(self):
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            self.ldapobj.simple_bind_s("cn=blah,o=test", "password")

    def test_simple_bind_s_fail_login(self):
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            self.ldapobj.simple_bind_s("cn=alice,ou=example,o=test", "wrong")

    def test_simple_bind_s_secondary_password(self):
        result = self.ldapobj.simple_bind_s("cn=bob,ou=other,o=test", "bobpw2")

        self.assertEqual(result, (97, []))

    @unittest.skipIf(not passlib, "passlib needs to be installed")
    def test_simple_bind_s_success_crypt_password(self):
        result = self.ldapobj.simple_bind_s("cn=theo,ou=example,o=test", "theopw")

        self.assertEqual(result, (97, []))

    @unittest.skipIf(not passlib, "passlib needs to be installed")
    def test_simple_bind_s_success_crypt_secondary_password(self):
        result = self.ldapobj.simple_bind_s("cn=theo,ou=example,o=test", "theopw2")

        self.assertEqual(result, (97, []))

    @unittest.skipIf(not passlib, "passlib needs to be installed")
    def test_simple_bind_s_fail_crypt_password(self):
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            self.ldapobj.simple_bind_s("cn=theo,ou=example,o=test", "theopw3")

    def test_simple_bind_s_invalid_dn(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldapobj.simple_bind_s('invalid', 'invalid')

    def test_search_s_get_directory_items_with_scope_onelevel(self):
        results = self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL)

        self.assertEqual(sorted(results), sorted([manager, alice, theo, john]))

    def test_search_s_get_all_directory_items_with_scope_subtree(self):
        results = self.ldapobj.search_s("o=test", ldap.SCOPE_SUBTREE)

        self.assertEqual(sorted(results), sorted(directory.iteritems()))

    def test_search_s_get_specific_item_with_scope_base(self):
        results = self.ldapobj.search_s("cn=alice,ou=example,o=test", ldap.SCOPE_BASE)

        self.assertEqual(results, [alice])

    def test_search_s_base_case_insensitive(self):
        results = self.ldapobj.search_s('cn=ALICE,ou=Example,o=TEST', ldap.SCOPE_BASE)

        self.assertEquals(results, [alice])

    def test_search_s_get_specific_attr(self):
        results = self.ldapobj.search_s("cn=alice,ou=example,o=test", ldap.SCOPE_BASE,
                                        attrlist=["userPassword"])

        self.assertEqual(results, [(alice[0], {'userPassword': alice[1]['userPassword']})])

    def test_search_s_use_attrsonly(self):
        results = self.ldapobj.search_s("cn=alice,ou=example,o=test", ldap.SCOPE_BASE,
                                        attrlist=["userPassword"], attrsonly=1)

        self.assertEqual(results, [(alice[0], {'userPassword': []})])

    def test_search_s_specific_attr_in_filterstr(self):
        results = self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL,
                                        '(userPassword=alicepw)')

        self.assertEqual(results, [alice])

    def test_search_s_escaped(self):
        escaped = ldap.filter.escape_filter_chars('alicepw', 2)
        results = self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL,
                                        '(userPassword=%s)' % (escaped,))

        self.assertEqual(results, [alice])

    def test_search_s_unparsable_filterstr(self):
        with self.assertRaises(ldap.FILTER_ERROR):
            self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL,
                                  'invalid=*')

    def test_search_s_unparsable_filterstr_test(self):
        with self.assertRaises(ldap.FILTER_ERROR):
            self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL,
                                  '(invalid=)')

    def test_search_s_filterstr_wildcard(self):
        with self.assertRaises(SeedRequired):
            self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL,
                                  '(invalid=foo*bar)')

    def test_search_s_invalid_filterstr(self):
        results = self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL,
                                        '(invalid=*)')

        self.assertEqual(results, [])

    def test_search_s_invalid_filterstr_op(self):
        with self.assertRaises(SeedRequired):
            self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL,
                                  '(invalid~=bogus)')

    def test_search_async(self):
        msgid = self.ldapobj.search("cn=alice,ou=example,o=test", ldap.SCOPE_BASE)
        results = self.ldapobj.result(msgid)

        self.assertEqual(results, (ldap.RES_SEARCH_RESULT, [alice]))

    def test_useful_seed_required_message(self):
        filterstr = '(invalid~=bogus)'
        try:
            self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL,
                                  filterstr, attrlist=['ou'])
        except SeedRequired, e:
            self.assertIn("search_s('ou=example,o=test', 1, '(invalid~=bogus)', attrlist=['ou']", str(e))
        else:
            self.fail("Expected SeedRequired exception")

    def test_search_s_get_items_that_have_userpassword_set(self):
        results = self.ldapobj.search_s(
            "ou=example,o=test", ldap.SCOPE_ONELEVEL, '(userPassword=*)')

        self.assertEqual(sorted(results), sorted([alice, manager, theo]))

    def test_search_s_filterstr_with_not(self):
        results = self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_SUBTREE,
                                        "(!(userPassword=alicepw))")

        self.assertEqual(sorted(results),
                         sorted([example, manager, theo, john]))

    def test_search_s_mutliple_filterstr_items_with_and(self):
        results = self.ldapobj.search_s(
            "ou=example,o=test", ldap.SCOPE_SUBTREE,
            "(&(objectClass=top)(objectClass=posixAccount)(userPassword=*))"
        )

        self.assertEqual(sorted(results), sorted([alice, manager, theo]))

    def test_search_s_mutliple_filterstr_items_one_invalid_with_and(self):
        results = self.ldapobj.search_s(
            "ou=example,o=test", ldap.SCOPE_SUBTREE,
            "(&(objectClass=top)(invalid=yo)(objectClass=posixAccount))"
        )

        self.assertEqual(results, [])

    def test_search_s_multiple_filterstr_items_with_or(self):
        results = self.ldapobj.search_s(
            "ou=example,o=test", ldap.SCOPE_SUBTREE,
            "(|(objectClass=inetOrgPerson)(userPassword=alicepw))"
        )

        self.assertEqual(sorted(results), sorted([alice, manager]))

    def test_search_s_multiple_filterstr_items_one_invalid_with_or(self):
        results = self.ldapobj.search_s(
            "ou=example,o=test", ldap.SCOPE_SUBTREE,
            "(|(objectClass=inetOrgPerson)(invalid=yo)(userPassword=alicepw))"
        )

        self.assertEqual(sorted(results), sorted([alice, manager]))

    def test_search_s_scope_base_no_such_object(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldapobj.search_s("cn=blah,ou=example,o=test", ldap.SCOPE_BASE)

    def test_search_s_no_results(self):
        results = self.ldapobj.search_s("ou=example,o=test", ldap.SCOPE_ONELEVEL,
                                        '(uid=blah)')

        self.assertEqual(results, [])

    def test_search_s_invalid_dn(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldapobj.search_s("invalid", ldap.SCOPE_SUBTREE)

    def test_start_tls_s_disabled_by_default(self):
        self.assertEqual(self.ldapobj.tls_enabled, False)

    def test_start_tls_s_enabled(self):
        self.ldapobj.start_tls_s()
        self.assertEqual(self.ldapobj.tls_enabled, True)

    def test_compare_s_no_such_object(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldapobj.compare_s('cn=blah,ou=example,o=test', 'objectClass',
                                   'top')

    def test_compare_s_undefined_type(self):
        with self.assertRaises(ldap.UNDEFINED_TYPE):
            self.ldapobj.compare_s('cn=alice,ou=example,o=test', 'objectClass1',
                                   'top')

    def test_compare_s_true(self):
        result = self.ldapobj.compare_s('cn=Manager,ou=example,o=test',
                                        'objectClass', 'top')

        self.assertEqual(result, 1)

    def test_compare_s_false(self):
        result = self.ldapobj.compare_s('cn=Manager,ou=example,o=test',
                                        'objectClass', 'invalid')

        self.assertEqual(result, 0)

    def test_compare_s_invalid_dn(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldapobj.compare_s('invalid', 'invalid', 'invalid')

    def test_add_s_success_code(self):
        dn = 'cn=mike,ou=example,o=test'
        attrs = {
            'objectClass': ['top', 'organizationalRole'],
            'cn': ['mike'],
            'userPassword': ['mikepw'],
        }
        ldif = ldap.modlist.addModlist(attrs)

        result = self.ldapobj.add_s(dn, ldif)

        self.assertEqual(result, (105, [], 1, []))

    def test_add_s_successfully_add_object(self):
        dn = 'cn=mike,ou=example,o=test'
        attrs = {
            'objectClass': ['top', 'organizationalRole'],
            'cn': ['mike'],
            'userPassword': ['mikepw'],
        }
        ldif = ldap.modlist.addModlist(attrs)

        self.ldapobj.add_s(dn, ldif)

        self.assertEqual(self.ldapobj.directory[dn], attrs)

    def test_add_s_already_exists(self):
        attrs = {'cn': ['mike']}
        ldif = ldap.modlist.addModlist(attrs)

        with self.assertRaises(ldap.ALREADY_EXISTS):
            self.ldapobj.add_s(alice[0], ldif)
        self.assertNotEqual(self.ldapobj.directory[alice[0]], attrs)

    def test_add_s_invalid_dn(self):
        dn = 'invalid'
        attrs = {
            'objectClass': ['top', 'organizationalRole'],
            'cn': ['mike'],
            'userPassword': ['mikepw'],
        }
        ldif = ldap.modlist.addModlist(attrs)

        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldapobj.add_s(dn, ldif)

    def test_modify_s_undefined_type(self):
        mod_list = [(ldap.MOD_REPLACE, 'invalid', 'test')]

        with self.assertRaises(ldap.UNDEFINED_TYPE):
            self.ldapobj.modify_s(alice[0], mod_list)

    def test_modify_s_no_such_object(self):
        mod_list = [(ldap.MOD_REPLACE, 'userPassword', 'test')]

        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldapobj.modify_s('ou=invalid,o=test', mod_list)

    def test_modify_s_success_code(self):
        new_pw = ['alice', 'alicepw2']
        mod_list = [(ldap.MOD_REPLACE, 'userPassword', new_pw)]

        result = self.ldapobj.modify_s(alice[0], mod_list)

        self.assertEqual(result, (103, []))

    def test_modify_s_replace_value_of_attribute_with_multiple_others(self):
        new_pw = ['alice', 'alicepw2']
        mod_list = [(ldap.MOD_REPLACE, 'userPassword', new_pw)]

        self.ldapobj.modify_s(alice[0], mod_list)

        self.assertEqual(self.ldapobj.directory[alice[0]]['userPassword'],
                         new_pw)

    def test_modify_s_replace_value_of_attribute_with_another_single(self):
        new_pw = 'alice'
        mod_list = [(ldap.MOD_REPLACE, 'userPassword', new_pw)]

        self.ldapobj.modify_s(alice[0], mod_list)

        self.assertEqual(self.ldapobj.directory[alice[0]]['userPassword'],
                         [new_pw])

    def test_modify_s_replace_with_none(self):
        mod_list = [(ldap.MOD_REPLACE, 'objectClass', None)]

        self.ldapobj.modify_s(manager[0], mod_list)

        self.assertNotIn('objectClass',
                         self.ldapobj.directory[manager[0]].keys())

    def test_modify_s_add_single_value_to_attribute(self):
        old_pw = copy(self.ldapobj.directory[alice[0]]['userPassword'])
        new_pw = 'test'
        mod_list = [(ldap.MOD_ADD, 'userPassword', new_pw)]

        self.ldapobj.modify_s(alice[0], mod_list)

        self.assertEqual(set(old_pw) | set([new_pw]),
                         set(self.ldapobj.directory[alice[0]]['userPassword']))

    def test_modify_s_add_multiple_values_to_attribute(self):
        old_pw = copy(self.ldapobj.directory[alice[0]]['userPassword'])
        new_pw = ['test1', 'test2']
        mod_list = [(ldap.MOD_ADD, 'userPassword', new_pw)]

        self.ldapobj.modify_s(alice[0], mod_list)

        self.assertEqual(set(old_pw) | set(new_pw),
                         set(self.ldapobj.directory[alice[0]]['userPassword']))

    def test_modify_s_add_none_value_raises_protocol_error(self):
        mod_list = [(ldap.MOD_ADD, 'userPassword', None)]

        with self.assertRaises(ldap.PROTOCOL_ERROR):
            self.ldapobj.modify_s(bob[0], mod_list)

    def test_modify_s_dont_add_already_existing_value(self):
        old_pw = copy(self.ldapobj.directory[bob[0]]['userPassword'])
        mod_list = [(ldap.MOD_ADD, 'userPassword', 'bobpw')]

        self.ldapobj.modify_s(bob[0], mod_list)

        self.assertEqual(self.ldapobj.directory[bob[0]]['userPassword'],
                         old_pw)

    def test_modify_s_delete_single_value_from_attribute(self):
        mod_list = [(ldap.MOD_DELETE, 'userPassword', 'bobpw')]

        self.ldapobj.modify_s(bob[0], mod_list)

        self.assertEqual(self.ldapobj.directory[bob[0]]['userPassword'],
                         ['bobpw2'])

    def test_modify_s_delete_multiple_values_from_attribute(self):
        mod_list = [(ldap.MOD_DELETE, 'objectClass', ['top', 'inetOrgPerson'])]

        self.ldapobj.modify_s(manager[0], mod_list)

        self.assertEqual(self.ldapobj.directory[manager[0]]['objectClass'],
                         ['posixAccount'])

    def test_modify_s_delete_all_values_from_attribute(self):
        mod_list = [(ldap.MOD_DELETE, 'objectClass', None)]

        self.ldapobj.modify_s(manager[0], mod_list)

        self.assertNotIn('objectClass',
                         self.ldapobj.directory[manager[0]].keys())

    def test_modify_s_invalid_dn(self):
        mod_list = [(ldap.MOD_DELETE, 'objectClass', None)]

        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldapobj.modify_s('invalid', mod_list)

    def test_rename_s_successful_code(self):
        result = self.ldapobj.rename_s('cn=alice,ou=example,o=test', 'uid=alice1')

        self.assertEqual(result, (109, []))

    def test_rename_s_only_rdn_check_dn(self):
        self.ldapobj.rename_s(alice[0], 'uid=alice1')

        self.assertIn('uid=alice1,ou=example,o=test',
                      self.ldapobj.directory.keys())

    def test_rename_s_only_rdn_append_value_to_existing_attr(self):
        self.ldapobj.rename_s(alice[0], 'uid=alice1')

        self.assertEquals(
            self.ldapobj.directory['uid=alice1,ou=example,o=test']['uid'],
            ['alice', 'alice1']
        )

    def test_rename_s_only_rdn_create_new_attr(self):
        self.ldapobj.rename_s(alice[0], 'sn=alice1')

        self.assertIn('sn', self.ldapobj.directory['sn=alice1,ou=example,o=test'])
        self.assertEquals(self.ldapobj.directory['sn=alice1,ou=example,o=test']['sn'],
                          ['alice1'])

    def test_rename_s_removes_old_dn(self):
        self.ldapobj.rename_s(alice[0], 'uid=alice1')

        self.assertNotIn(alice[0], self.ldapobj.directory.keys())

    def test_rename_s_removes_old_attr(self):
        self.ldapobj.rename_s(alice[0], 'uid=alice1')

        self.assertNotIn('cn', self.ldapobj.directory['uid=alice1,ou=example,o=test'])

    def test_rename_s_does_not_remove_multivalued_old_attr(self):
        self.ldapobj.directory[alice[0]]['cn'].append('alice1')

        self.ldapobj.rename_s(alice[0], 'uid=alice1')

        self.assertIn('cn', self.ldapobj.directory['uid=alice1,ou=example,o=test'])
        self.assertIn('alice1', self.ldapobj.directory['uid=alice1,ou=example,o=test']['cn'])
        self.assertNotIn('alice', self.ldapobj.directory['uid=alice1,ou=example,o=test']['cn'])

    def test_rename_s_newsuperior_check_dn(self):
        self.ldapobj.rename_s(alice[0], 'uid=alice1', 'ou=new,o=test')

        self.assertIn('uid=alice1,ou=new,o=test', self.ldapobj.directory)

    def test_rename_s_no_such_object(self):
        self.assertRaises(ldap.NO_SUCH_OBJECT, self.ldapobj.rename_s,
                          'uid=invalid,ou=example,o=test', 'uid=invalid2')

    def test_rename_s_invalid_dn(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldapobj.rename_s('invalid', 'uid=blah')

    def test_rename_s_invalid_newrdn(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldapobj.rename_s('uid=something,ou=example,o=test', 'invalid')

    def test_rename_s_invalid_newsuperior(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldapobj.rename_s('uid=alice,ou=example,o=test', 'cn=alice',
                                  'invalid')

    def test_delete_s_success_code(self):
        self.assertEqual(self.ldapobj.delete_s(alice[0]), (107, []))

    def test_delete_s_successful_removal(self):
        self.ldapobj.delete_s(alice[0])

        self.assertNotIn(alice[0], self.ldapobj.directory)

    def test_delete_s_no_such_object(self):
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            self.ldapobj.delete_s('uid=invalid,ou=example,o=test')

    def test_delete_s_invalid_dn(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self.ldapobj.delete_s('invalid')

    def test_unbind(self):
        self.ldapobj.simple_bind_s(alice[0], 'alicepw')
        self.ldapobj.unbind()

        self.assertEqual(self.ldapobj.bound_as, None)

    def test_unbind_s(self):
        self.ldapobj.simple_bind_s(alice[0], 'alicepw')
        self.ldapobj.unbind_s()

        self.assertEqual(self.ldapobj.bound_as, None)


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
        conn1.directory['cn=alice,ou=example,o=test'][
            'userPassword'][0] = 'modified'
        self.mockldap.stop()

        self.mockldap.start()
        conn2 = ldap.initialize('')
        self.mockldap.stop()

        self.assertNotEqual(conn1.directory, conn2.directory)
