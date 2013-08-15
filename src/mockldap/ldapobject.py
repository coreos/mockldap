from __future__ import absolute_import

from copy import deepcopy
import re

import ldap
try:
    from passlib.hash import ldap_md5_crypt
except ImportError:
    pass

from .recording import SeedRequired, RecordableMethods, recorded


class LDAPObject(RecordableMethods):
    """
    :param directory: The initial content of this LDAP connection.
    :type directory: ``{dn: {attr: [values]}}``

    Our mock replacement for :class:`ldap.LDAPObject`. This exports selected
    LDAP operations and allows you to set return values in advance as well as
    discover which methods were called after the fact.

    All of these methods take the same arguments as their python-ldap
    counterparts. Some are self-explanatory; those that are only partially
    implemented are documented as such.

    .. attribute:: options

        *dict*: Options that have been set by
        :meth:`~mockldap.LDAPObject.set_option`.

    .. attribute:: tls_enabled

        *bool*: True if :meth:`~mockldap.LDAPObject.start_tls_s` was called.

    .. attribute:: bound_as

        *string*: DN of the last successful bind. None if unbound.
    """
    def __init__(self, directory):
        self.directory = ldap.cidict.cidict(deepcopy(directory))
        self.async_results = []
        self.options = {}
        self.tls_enabled = False
        self.bound_as = None

    #
    # Begin LDAP methods
    #

    @recorded
    def initialize(self, *args, **kwargs):
        """ This only exists for recording purposes. """
        pass

    @recorded
    def get_option(self, option):
        """
        """
        return self.options[option]

    @recorded
    def set_option(self, option, invalue):
        """
        """
        self.options[option] = invalue

    @recorded
    def simple_bind_s(self, who='', cred=''):
        """
        """
        success = False

        if(who == '' and cred == ''):
            success = True
        elif self._compare_s(who, 'userPassword', cred):
            success = True

        if success:
            self.bound_as = who
            return (97, []) # python-ldap returns this; I don't know what it means
        else:
            raise ldap.INVALID_CREDENTIALS('%s:%s' % (who, cred))

    @recorded
    def search(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        """
        Implements searching with simple filters of the form (attr=value),
        where value can be a string or *. attrlist and attrsonly are also
        supported. Beyond that, this method must be seeded.
        """
        value = self._search_s(base, scope, filterstr, attrlist, attrsonly)

        return self._add_async_result(value)

    @recorded
    def result(self, msgid, all=1, timeout=None):
        """
        """
        return ldap.RES_SEARCH_RESULT, self._pop_async_result(msgid)

    @recorded
    def search_s(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        """
        Implements searching with simple filters of the form (attr=value),
        where value can be a string or *. attrlist and attrsonly are also
        supported. Beyond that, this method must be seeded.
        """
        return self._search_s(base, scope, filterstr, attrlist, attrsonly)

    @recorded
    def start_tls_s(self):
        """
        """
        self.tls_enabled = True

    @recorded
    def compare_s(self, dn, attr, value):
        """
        """
        return self._compare_s(dn, attr, value)

    @recorded
    def modify_s(self, dn, mod_attrs):
        """
        """
        return self._modify_s(dn, mod_attrs)

    @recorded
    def add_s(self, dn, record):
        """
        """
        return self._add_s(dn, record)

    @recorded
    def unbind(self):
        """
        """
        self.bound_as = None

    @recorded
    def unbind_s(self):
        """
        """
        self.bound_as = None

    #
    # Internal implementations
    #

    def _compare_s(self, dn, attr, value):
        if dn not in self.directory:
            raise ldap.NO_SUCH_OBJECT

        if attr not in self.directory[dn]:
            raise ldap.NO_SUCH_ATTRIBUTE

        if attr == 'userPassword':
            for password in self.directory[dn][attr]:
                try:
                    # TODO: Implement more ldap pwd hashes from passlib
                    # http://pythonhosted.org/passlib/lib/passlib.hash.html#ldap-hashes
                    if ldap_md5_crypt.verify(value, password):
                        return 1
                except (NameError, ValueError):
                    pass
        return (value in self.directory[dn][attr]) and 1 or 0

    def _search_s(self, base, scope, filterstr, attrlist, attrsonly):
        valid_filterstr = re.compile(r'\(\w+=([\w@.]+|[*])\)')

        if not valid_filterstr.match(filterstr):
            raise SeedRequired('search_s("%s", %d, "%s", "%s", %d)' %
                (base, scope, filterstr, attrlist, attrsonly))

        def check_dn(dn, all_dn):
            if dn not in all_dn:
                raise ldap.NO_SUCH_OBJECT

        def get_results(dn, filterstr, results):
            attrs = self.directory.get(dn)
            attr, value = filterstr[1:-1].split('=')
            if attrs and attr in attrs.keys() and str(value) in attrs[attr] or value == u'*':
                new_attrs = attrs.copy()
                if attrlist or attrsonly:
                    for item in new_attrs.keys():
                        if attrsonly:
                            new_attrs[item] = []
                        if attrlist and item not in attrlist:
                            del(new_attrs[item])
                results.append((dn, new_attrs))

        results = []
        all_dn = self.directory.keys()
        if scope == ldap.SCOPE_BASE:
            check_dn(base, all_dn)
            get_results(base, filterstr, results)
        elif scope == ldap.SCOPE_ONELEVEL:
            for dn in all_dn:
                check_dn(dn, all_dn)
                if len(dn.split('=')) == len(base.split('=')) + 1 and dn.endswith(base):
                    get_results(dn, filterstr, results)
        elif scope == ldap.SCOPE_SUBTREE:
            for dn in all_dn:
                check_dn(dn, all_dn)
                if dn.endswith(base):
                    get_results(dn, filterstr, results)

        return results

    def _modify_s(self, dn, mod_attrs):
        try:
            entry = self.directory[dn]
        except KeyError:
            raise ldap.NO_SUCH_OBJECT

        for item in mod_attrs:
            op, key, value = item
            if op is 0:
                # FIXME: Can't handle multiple entries with the same name
                # its broken right now
                # do a MOD_ADD, assume it to be a list of values
                key.append(value)
            elif op is 1:
                # do a MOD_DELETE
                if row is tpyes.ListType:
                    row = entry[key]
                    for i in range(len(row)):
                        if value is row[i]:
                            del row[i]
                else:
                    del entry[key]
                self.directory[dn] = entry
            elif op is 2:
                # do a MOD_REPLACE
                entry[key] = value

        self.directory[dn] = entry

        return (103, [])

    def _add_s(self, dn, record):
        entry = {}
        dn = str(dn)
        for item in record:
            entry[item[0]] = list(item[1])
        try:
            self.directory[dn]
            raise ldap.ALREADY_EXISTS
        except KeyError:
            self.directory[dn] = entry
            return (105, [], len(self.methods_called()), [])

    #
    # Async
    #

    def _add_async_result(self, value):
        self.async_results.append(value)

        return len(self.async_results) - 1

    def _pop_async_result(self, msgid):
        if msgid in xrange(len(self.async_results)):
            value = self.async_results[msgid]
            self.async_results[msgid] = None
        else:
            value = None

        return value
