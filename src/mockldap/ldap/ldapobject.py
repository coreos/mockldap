from collections import defaultdict
import cidict
import ldap
import re
import sys


class LDAPObject(object):
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
        self.directory = cidict.cidict(directory)

        self.reset()

    def reset(self):
        """
        Resets our recorded API calls and queued return values as well as
        miscellaneous configuration options.
        """
        self.calls = []
        self.return_value_maps = defaultdict(lambda: {})
        self.async_results = []
        self.options = {}
        self.tls_enabled = False

    def set_return_value(self, api_name, arguments, value):
        """
        Stores a preset return value for a given API with a given set of
        arguments.
        """
        self.return_value_maps[api_name][arguments] = value

    def ldap_methods_called_with_arguments(self):
        """
        Returns a list of 2-tuples, one for each API call made since the last
        reset. Each tuple contains the name of the API and a dictionary of
        arguments. Argument defaults are included.
        """
        return self.calls

    def ldap_methods_called(self):
        """
        Returns the list of API names called.
        """
        return [call[0] for call in self.calls]

    #
    # Begin LDAP methods
    #

    def set_option(self, option, invalue):
        self._record_call('set_option', {
            'option': option,
            'invalue': invalue
        })

        self.options[option] = invalue

    def initialize(self, uri, trace_level=0, trace_file=sys.stdout, trace_stack_limit=None):
        """
        XXX: This should be moved to the top level of the module.
        """
        self._record_call('initialize', {
            'uri': uri,
            'trace_level': trace_level,
            'trace_file': trace_file,
            'trace_stack_limit': trace_stack_limit
        })

        value = self._get_return_value('initialize',
            (uri, trace_level, trace_file, trace_stack_limit))
        if value is None:
            value = self

        return value

    def simple_bind_s(self, who='', cred=''):
        self._record_call('simple_bind_s', {
            'who': who,
            'cred': cred
        })

        value = self._get_return_value('simple_bind_s', (who, cred))
        if value is None:
            value = self._simple_bind_s(who, cred)

        return value

    def search(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        self._record_call('search', {
            'base': base,
            'scope': scope,
            'filterstr': filterstr,
            'attrlist': attrlist,
            'attrsonly': attrsonly
        })

        value = self._get_return_value('search_s',
            (base, scope, filterstr, attrlist, attrsonly))
        if value is None:
            value = self._search_s(base, scope, filterstr, attrlist, attrsonly)

        return self._add_async_result(value)

    def result(self, msgid, all=1, timeout=None):
        self._record_call('result', {
            'msgid': msgid,
            'all': all,
            'timeout': timeout,
        })

        return ldap.RES_SEARCH_RESULT, self._pop_async_result(msgid)

    def search_s(self, base, scope, filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        self._record_call('search_s', {
            'base': base,
            'scope': scope,
            'filterstr': filterstr,
            'attrlist': attrlist,
            'attrsonly': attrsonly
        })

        value = self._get_return_value('search_s',
            (base, scope, filterstr, attrlist, attrsonly))
        if value is None:
            value = self._search_s(base, scope, filterstr, attrlist, attrsonly)

        return value

    def start_tls_s(self):
        self.tls_enabled = True

    def compare_s(self, dn, attr, value):
        self._record_call('compare_s', {
            'dn': dn,
            'attr': attr,
            'value': value
        })

        result = self._get_return_value('compare_s', (dn, attr, value))
        if result is None:
            result = self._compare_s(dn, attr, value)

        # print "compare_s('%s', '%s', '%s'): %d" % (dn, attr, value, result)

        return result

    def unbind(self):
        pass

    #
    # Internal implementations
    #

    def _simple_bind_s(self, who='', cred=''):
        success = False

        if(who == '' and cred == ''):
            success = True
        elif self._compare_s(who.lower(), 'userPassword', cred):
            success = True

        if success:
            return (97, []) # python-ldap returns this; I don't know what it means
        else:
            raise ldap.INVALID_CREDENTIALS('%s:%s' % (who, cred))

    def _compare_s(self, dn, attr, value):
        if dn not in self.directory:
            raise ldap.NO_SUCH_OBJECT

        if attr not in self.directory[dn]:
            raise ldap.NO_SUCH_ATTRIBUTE

        return (value in self.directory[dn][attr]) and 1 or 0

    def _search_s(self, base, scope, filterstr, attrlist, attrsonly):
        """
        We can do a search with a filter on the form (attr=value), where value
        can be a string or *. Beyond that, you're on your own.
        """

        valid_filterstr = re.compile(r'\(\w+=([\w@.]+|[*])\)')

        if not valid_filterstr.match(filterstr):
            raise ldap.PresetReturnRequiredError('search_s("%s", %d, "%s", "%s", %d)' %
                (base, scope, filterstr, attrlist, attrsonly))

        def get_results(dn, filterstr, results):
            attrs = self.directory.get(dn)
            attr, value = filterstr[1:-1].split('=')
            if attrs and attr in attrs.keys() and str(value) in attrs[attr] or value == u'*':
                results.append((dn, attrs))

        results = []
        all_dn = self.directory.keys()
        if scope == ldap.SCOPE_BASE:
            get_results(base, filterstr, results)
        elif scope == ldap.SCOPE_ONELEVEL:
            for dn in all_dn:
                if len(dn.split('=')) == len(base.split('=')) + 1 and dn.endswith(base):
                    get_results(dn, filterstr, results)
        elif scope == ldap.SCOPE_SUBTREE:
            for dn in all_dn:
                if dn.endswith(base):
                    get_results(dn, filterstr, results)
        if results:
            return results
        else:
            raise ldap.NO_SUCH_OBJECT()

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

    #
    # Utils
    #

    # TODO: Shouldn't we be able to do this with decorators?
    def _record_call(self, api_name, arguments):
        self.calls.append((api_name, arguments))

    def _get_return_value(self, api_name, arguments):
        try:
            value = self.return_value_maps[api_name][arguments]
        except KeyError:
            value = None

        if isinstance(value, Exception):
            raise value

        return value
