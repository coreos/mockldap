from __future__ import absolute_import

from copy import deepcopy

import ldap
from ldap.cidict import cidict
import ldap.dn

try:
    from passlib.hash import ldap_md5_crypt
except ImportError:
    pass

from .recording import SeedRequired, RecordableMethods, recorded


class LDAPObject(RecordableMethods):
    """
    :param directory: The initial content of this LDAP connection.
    :type directory: :class:`ldap.cidict.cidict`: ``{dn: {attr: [values]}}``

    Our mock replacement for :class:`ldap.LDAPObject`. This exports selected
    LDAP operations and allows you to set return values in advance as well as
    discover which methods were called after the fact.

    All of these methods take the same arguments as their python-ldap
    counterparts. Some are self-explanatory; those that are only partially
    implemented are documented as such.

    Ignore the *static* annotations; that's just a Sphinx artifact.

    .. attribute:: options

        *dict*: Options that have been set by
        :meth:`~mockldap.LDAPObject.set_option`.

    .. attribute:: tls_enabled

        *bool*: True if :meth:`~mockldap.LDAPObject.start_tls_s` was called.

    .. attribute:: bound_as

        *string*: DN of the last successful bind. None if unbound.
    """
    def __init__(self, directory):
        if not isinstance(directory, ldap.cidict.cidict):
            from . import map_keys
            directory = cidict(map_keys(lambda s: s.lower(), directory))

        self.directory = deepcopy(directory)
        self.async_results = []
        self.options = {}
        self.tls_enabled = False
        self.bound_as = None

    def _check_valid_dn(self, dn):
        try:
            ldap.dn.str2dn(dn)
        except ldap.DECODING_ERROR:
            raise ldap.INVALID_DN_SYNTAX

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

        try:
            if(who == '' and cred == ''):
                success = True
            elif self._compare_s(who, 'userPassword', cred):
                success = True
        except ldap.NO_SUCH_OBJECT:
            pass

        if success:
            self.bound_as = who
            return (97, [])
        else:
            raise ldap.INVALID_CREDENTIALS('%s:%s' % (who, cred))

    @recorded
    def search(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        """
        See :meth:`~mockldap.LDAPObject.search_s`.
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
        Supports many, but not all, filter strings.

        Tests of the form ``'(foo=bar)'`` and ``'(foo=\*)'`` are supported, as
        are the &, \|, and !  operators. attrlist and attrsonly are also
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
    def rename_s(self, dn, newrdn, newsuperior=None):
        """
        """
        return self._rename_s(dn, newrdn, newsuperior)

    @recorded
    def delete_s(self, dn):
        """
        """
        return self._delete_s(dn)

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
        self._check_valid_dn(dn)
        try:
            if attr not in self.directory[dn]:
                raise ldap.UNDEFINED_TYPE
        except KeyError:
            raise ldap.NO_SUCH_OBJECT

        if attr == 'userPassword':
            for password in self.directory[dn][attr]:
                try:
                    if ldap_md5_crypt.verify(value, password):
                        return 1
                except (NameError, ValueError):
                    pass

        return (1 if (value in self.directory[dn][attr]) else 0)

    def _search_s(self, base, scope, filterstr, attrlist, attrsonly):
        from .filter import parse, UnsupportedOp

        self._check_valid_dn(base)

        if base not in self.directory:
            raise ldap.NO_SUCH_OBJECT

        # Find directory entries within the requested scope
        base_parts = ldap.dn.explode_dn(base.lower())
        base_len = len(base_parts)
        dn_parts = dict((dn, ldap.dn.explode_dn(dn)) for dn in self.directory.iterkeys())

        if scope == ldap.SCOPE_BASE:
            dns = (dn for dn, parts in dn_parts.iteritems() if parts == base_parts)
        elif scope == ldap.SCOPE_ONELEVEL:
            dns = (dn for dn, parts in dn_parts.iteritems() if parts[1:] == base_parts)
        elif scope == ldap.SCOPE_SUBTREE:
            dns = (dn for dn, parts in dn_parts.iteritems() if parts[-base_len:] == base_parts)
        else:
            raise ValueError(u"Unrecognized scope: {0}".format(scope))

        # Apply the filter expression
        try:
            filter_expr = parse(filterstr)
        except UnsupportedOp, e:
            raise SeedRequired(e)

        results = ((dn, self.directory[dn]) for dn in dns
                   if filter_expr.matches(dn, self.directory[dn]))

        # Apply attribute filtering, if any
        if attrlist is not None:
            results = ((dn, dict((attr, values) for attr, values in attrs.iteritems() if attr in attrlist))
                       for dn, attrs in results)

        if attrsonly:
            results = ((dn, dict((attr, []) for attr in attrs.iterkeys()))
                       for dn, attrs in results)

        return list(results)

    def _modify_s(self, dn, mod_attrs):
        self._check_valid_dn(dn)

        for item in mod_attrs:
            op, key, value = item
            try:
                if key not in self.directory[dn]:
                    raise ldap.UNDEFINED_TYPE
            except KeyError:
                raise ldap.NO_SUCH_OBJECT

            entry = self.directory[dn]

            if type(value) is str:
                value = [value]

            if op is ldap.MOD_ADD:
                if not value:
                    raise ldap.PROTOCOL_ERROR
                for subvalue in value:
                    if subvalue not in entry[key]:
                        entry[key].append(subvalue)
            elif op is ldap.MOD_DELETE:
                if not value:
                    entry[key] = []
                else:
                    for subvalue in value:
                        if subvalue in entry[key]:
                            entry[key].remove(subvalue)
            elif op is ldap.MOD_REPLACE:
                if not value:
                    del entry[key]
                else:
                    entry[key] = value

        return (103, [])

    def _add_s(self, dn, record):
        self._check_valid_dn(dn)

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

    def _rename_s(self, dn, newrdn, newsuperior):
        self._check_valid_dn(dn)
        self._check_valid_dn(newrdn)
        if newsuperior:
            self._check_valid_dn(newsuperior)

        try:
            entry = self.directory[dn]
        except KeyError:
            raise ldap.NO_SUCH_OBJECT

        if newsuperior:
            superior = newsuperior
        else:
            superior = ','.join(dn.split(',')[1:])

        newfulldn = '%s,%s' % (newrdn, superior)
        oldattr, oldvalue = dn.split(',')[0].split('=')
        newattr, newvalue = newrdn.split('=')

        try:
            if newvalue not in entry[newattr]:
                entry[newattr].append(newvalue)
        except KeyError:
            entry[newattr] = [newvalue]

        if oldattr == newattr or len(entry[oldattr]) > 1:
            entry[oldattr].remove(oldvalue)
        else:
            del entry[oldattr]

        self.directory[newfulldn] = entry
        del self.directory[dn]

        return (109, [])

    def _delete_s(self, dn):
        self._check_valid_dn(dn)

        try:
            del self.directory[dn]
        except KeyError:
            raise ldap.NO_SUCH_OBJECT

        return (107, [])

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
