LDAP Operations
===============

Inside of an individual test, you will be performing some task that involves
LDAP operations and then verifying the outcome. In some cases, you will need to
prepare your mock :class:`~mockldap.LDAPObject` to return specific results for a
given API call.


LDAPObject
----------

.. autoclass:: mockldap.LDAPObject
    :members:

Every LDAP method on :class:`~mockldap.LDAPObject` is actually an instance of
:class:`~mockldap.recording.RecordedMethod`, which allows you to set return
values in advance for different sets of arguments.

.. autoclass:: mockldap.recording.RecordedMethod
    :members:

.. autoexception:: mockldap.SeedRequired
