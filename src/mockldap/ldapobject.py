from __future__ import absolute_import

import re

import ldap
try:
    from passlib.hash import ldap_md5_crypt
except ImportError:
    pass

from .recording import RecordableMethods, recorded


class LDAPObject(RecordableMethods):
    """
    Simple operations can be simulated, but for nontrivial searches, the client
    will have to seed the mock object with return values for expected API calls.
    This may sound like cheating, but it's really no more so than a simulated
    LDAP server. The fact is we can not require python-ldap to be installed in
    order to run the unit tests, so all we can do is verify that LDAPBackend is
    calling the APIs that we expect.

    set_return_value takes the name of an API, a tuple of arguments, and a
    return value. Every time an API is called, it looks for a predetermined
    return value based on the arguments received. If it finds one, then it
    returns it, or raises it if it's an Exception. If it doesn't find one, then
    it tries to satisfy the request internally. If it can't, it raises a
    PresetReturnRequiredError.

    At any time, the client may call ldap_methods_called_with_arguments() or
    ldap_methods_called() to get a record of all of the LDAP API calls that have
    been made, with or without arguments.
    """
    def __init__(self, directory):
        """
        directory is a complex structure with the entire contents of the
        mock LDAP directory. directory must be a dictionary mapping
        distinguished names to dictionaries of attributes. Each attribute
        dictionary maps attribute names to lists of values. e.g.:

        {
            "uid=alice,ou=users,dc=example,dc=com":
            {
                "uid": ["alice"],
                "userPassword": ["secret"],
            },
        }
        """
        self.directory = ldap.cidict.cidict(directory)
        self.async_results = []
        self.options = {}
        self.tls_enabled = False

    #
    # Begin LDAP methods
    #

    @recorded
    def get_option(self, option):
        return self.options[option]

    @recorded
    def set_option(self, option, invalue):
        self.options[option] = invalue

    @recorded
    def initialize(self, *args, **kwargs):
        """ This only exists for recording purposes. """
        pass

    @recorded
    def simple_bind_s(self, who='', cred=''):
        success = False

        if(who == '' and cred == ''):
            success = True
        elif self._compare_s(who, 'userPassword', cred):
            success = True

        if success:
            return (97, []) # python-ldap returns this; I don't know what it means
        else:
            raise ldap.INVALID_CREDENTIALS('%s:%s' % (who, cred))

    @recorded
    def search(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        value = self._search_s(base, scope, filterstr, attrlist, attrsonly)

        return self._add_async_result(value)

    @recorded
    def result(self, msgid, all=1, timeout=None):
        return ldap.RES_SEARCH_RESULT, self._pop_async_result(msgid)

    @recorded
    def search_s(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        return self._search_s(base, scope, filterstr, attrlist, attrsonly)

    @recorded
    def start_tls_s(self):
        self.tls_enabled = True

    @recorded
    def compare_s(self, dn, attr, value):
        return self._compare_s(dn, attr, value)

    @recorded
    def add_s(self, dn, record):
        return self._add_s(dn, record)

    @recorded
    def unbind(self):
        pass

    @recorded
    def unbind_s(self):
        pass

    #
    # Internal implementations
    #

    def _compare_s(self, dn, attr, value):
        if dn not in self.directory:
            raise ldap.NO_SUCH_OBJECT

        if attr not in self.directory[dn]:
            raise ldap.NO_SUCH_ATTRIBUTE

        if attr == 'userPassword':
            try:
                # TODO: Implement more ldap pwd hashes from passlib
                # http://pythonhosted.org/passlib/lib/passlib.hash.html#ldap-hashes
                if ldap_md5_crypt.verify(value, self.directory[dn][attr][0]):
                    return 1
            except (NameError, ValueError):
                pass
        return (value in self.directory[dn][attr]) and 1 or 0

    def _search_s(self, base, scope, filterstr, attrlist, attrsonly):
        """
        We can do a search with a filter on the form (attr=value), where value
        can be a string or *. attrlist and attrsonly are also supported.
        Beyond that, you're on your own.
        """
        valid_filterstr = re.compile(r'\(\w+=([\w@.]+|[*])\)')

        if not valid_filterstr.match(filterstr):
            raise ldap.PresetReturnRequiredError('search_s("%s", %d, "%s", "%s", %d)' %
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
            return (105, [], len(self.calls), [])

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
