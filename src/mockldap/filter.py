"""
Simple filter expression parser based on funcparserlib.
"""
from functools import partial
import ldap
import re

from funcparserlib.parser import (a, skip, oneplus, finished,
                                  with_forward_decls, NoParseError)


class UnsupportedOp(Exception):
    pass


class Token(object):
    LPAREN = 1
    RPAREN = 2
    AND = 10
    OR = 11
    NOT = 12
    TEST = 100

    def __init__(self, code, content='', start=-1, stop=-1):
        self.code = code
        self.content = content
        self.start = start
        self.stop = stop

    def __eq__(self, other):
        return self.code == other.code

    def __str__(self):
        return "%d-%d: %s %r" % (self.start, self.stop, self.code, self.content)

    def __repr__(self):
        return "%s(%r, %r, %r, %r)" % (self.__class__.__name__, self.code, self.content, self.start, self.stop)

    def matches(self, dn, attrs):
        raise NotImplementedError()


LParen = partial(Token, Token.LPAREN)
RParen = partial(Token, Token.RPAREN)


class And(Token):
    def __init__(self, *args, **kwargs):
        super(And, self).__init__(self.AND, *args, **kwargs)

        self.terms = []

    def unparse(self):
        return u"(&%s)" % (u"".join(t.unparse() for t in self.terms),)

    def matches(self, dn, attrs):
        return all(term.matches(dn, attrs) for term in self.terms)


class Or(Token):
    def __init__(self, *args, **kwargs):
        super(Or, self).__init__(self.OR, *args, **kwargs)

        self.terms = []

    def unparse(self):
        return u"(|%s)" % (u"".join(t.unparse() for t in self.terms),)

    def matches(self, dn, attrs):
        return any(term.matches(dn, attrs) for term in self.terms)


class Not(Token):
    def __init__(self, *args, **kwargs):
        super(Not, self).__init__(self.NOT, *args, **kwargs)

        self.term = None

    def unparse(self):
        return u"(!%s)" % (self.term.unparse(),)

    # For external consistency
    def _get_terms(self):
        return self.term

    def _set_terms(self, terms):
        self.term = terms

    terms = property(_get_terms, _set_terms)

    def matches(self, dn, attrs):
        return (not self.term.matches(dn, attrs))


class Test(Token):
    TEST_RE = re.compile(r'(.+?)([~<>]?=)(.+)')
    UNESCAPE_RE = re.compile(r'\\([0-9a-f]{2})', flags=re.I)

    # Defaults
    attr = None
    op = None
    value = None

    def __init__(self, *args, **kwargs):
        super(Test, self).__init__(self.TEST, *args, **kwargs)

        if self.content:
            self._parse_expression()

    def _parse_expression(self):
        match = self.TEST_RE.match(self.content)

        if match is None:
            raise ldap.FILTER_ERROR(u"Failed to parse filter item '%s' at pos %d" % (self.content, self.start))

        self.attr, self.op, self.value = match.groups()

        if self.op != '=':
            raise UnsupportedOp(u"Operation '%s' is not supported" % (self.op,))

        if (u'*' in self.value) and (self.value != u'*'):
            raise UnsupportedOp(u"Wildcard matches are not supported in '%s'" % (self.value,))

        # Resolve all escaped characters
        self.value = self.UNESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), self.value)

    def unparse(self):
        return u"(%s)" % (self.content,)

    def matches(self, dn, attrs):
        values = attrs.get(self.attr)

        if values is None:
            matches = False
        elif self.value == u'*':
            matches = len(values) > 0
        else:
            matches = self.value in values

        return matches


# Tokens to pull out. The operators contain positive lookbehind assertions to
# make sure that they're only matched after left parens.
_atoms = [
    r'\(',          # (
    r'(?<=\()\&',   # &
    r'(?<=\()\|',   # |
    r'(?<=\()\!',   # !
    r'\)',          # )
]
tokens_re = re.compile(r'(%s)' % r'|'.join(_atoms))


def tokenize(filterstr):
    substrs = tokens_re.split(filterstr)

    return list(gen_tokens(substrs))


def gen_tokens(substrs):
    pos = 0

    for substr in substrs:
        if substr == '':
            continue
        elif substr == '(':
            token = LParen
        elif substr == '&':
            token = And
        elif substr == '|':
            token = Or
        elif substr == '!':
            token = Not
        elif substr == ')':
            token = RParen
        else:
            token = Test

        yield token(substr, pos, pos + len(substr) - 1)

        pos += len(substr)


def parse(filterstr):
    try:
        return ldap_filter.parse(tokenize(filterstr))
    except NoParseError as e:
        raise ldap.FILTER_ERROR(e)


#
# Grammar
#

def grammar():
    lparen = skip(a(LParen()))
    rparen = skip(a(RParen()))

    def collapse(t):
        t[0].terms = t[1]
        return t[0]

    @with_forward_decls
    def ldap_filter():
        return (ldap_and | ldap_or | ldap_not | ldap_test)

    ldap_and = (lparen + a(And()) + oneplus(ldap_filter) + rparen) >> collapse
    ldap_or = (lparen + a(Or()) + oneplus(ldap_filter) + rparen) >> collapse
    ldap_not = (lparen + a(Not()) + ldap_filter + rparen) >> collapse
    ldap_test = lparen + a(Test()) + rparen

    return ldap_filter + skip(finished)


ldap_filter = grammar()


#
# Call this module with filter strings to test the parsing.
#

if __name__ == '__main__':
    from pprint import pprint
    import sys

    for filterstr in sys.argv[1:]:
        pprint(tokenize(filterstr))
        print(parse(filterstr).unparse())
