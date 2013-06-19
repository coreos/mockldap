import sys
from ldapobject import LDAPObject

def initialize(uri,trace_level=0,trace_file=sys.stdout,trace_stack_limit=None):
  """
  Return LDAPObject instance by opening LDAP connection to
  LDAP host specified by LDAP URL

  Parameters:
  uri
        LDAP URL containing at least connection scheme and hostport,
        e.g. ldap://localhost:389
  trace_level
        If non-zero a trace output of LDAP calls is generated.
  trace_file
        File object where to write the trace output to.
        Default is to use stdout.
  """
  return LDAPObject(uri,trace_level,trace_file,trace_stack_limit)
