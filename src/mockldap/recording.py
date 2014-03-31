"""
Tools for recording method calls and seeding return values.
"""
from collections import defaultdict
from copy import deepcopy
from functools import partial


class SeedRequired(Exception):
    """
    An API call must be seeded with a return value.

    This is raised by :class:`~mockldap.LDAPObject` methods when they can't
    satisfy a request internally. The messsage will contain a representation of
    the method call that triggered it, including all arguments.
    """
    pass


class RecordableMethods(object):
    """
    This is a mixin class to be used as a companion with recorded, below. Any
    class that wants to use the recordable decorator must inherit from this.
    """
    def methods_called(self, with_args=False):
        if with_args:
            calls = deepcopy(self._recorded_calls)
        else:
            calls = [call[0] for call in self._recorded_calls]

        return calls

    @property
    def _recorded_calls(self):
        if not hasattr(self, '_recorded_calls_internal'):
            self._recorded_calls_internal = []

        return self._recorded_calls_internal

    @property
    def _seeded_calls(self):
        if not hasattr(self, '_seeded_calls_internal'):
            self._seeded_calls_internal = defaultdict(list)

        return self._seeded_calls_internal


class recorded(object):
    """
    >>> class C(RecordableMethods):
    ...     @recorded
    ...     def plus1(self, n):
    ...         return n + 1
    >>>
    >>> c = C()
    >>> c.plus1(5)
    6
    >>> c.plus1.seed(5)(7)
    >>> c.plus1(5)
    7
    >>> c.plus1(4)
    5
    >>> c.methods_called()
    ['plus1', 'plus1', 'plus1']
    >>> c.methods_called(with_args=True)
    [('plus1', (5,), {}), ('plus1', (5,), {}), ('plus1', (4,), {})]
    >>> c = C()
    >>> c.plus1.seed(n=5)(8)
    >>> c.plus1(5)
    6
    >>> c.plus1(n=5)
    8
    >>> c.methods_called(with_args=True)
    [('plus1', (5,), {}), ('plus1', (), {'n': 5})]
    >>> c = C()
    >>> c.plus1.seed(5)(9)
    >>> c.plus1.seed(5)(10)
    >>> c.plus1(5)
    10
    >>> c.plus1.seed(5)(ValueError())
    >>> c.plus1(5)
    Traceback (most recent call last):
        ...
    ValueError
    >>> c.plus1.seed(5)(ValueError)
    >>> c.plus1(5)
    Traceback (most recent call last):
        ...
    ValueError
    """
    def __init__(self, func):
        self.func = func

    def __get__(self, instance, owner):
        func = self.func
        if instance is not None:
            func = RecordedMethod(self.func, instance)

        return func


class RecordedMethod(object):
    def __init__(self, func, instance):
        self.func = func
        self.instance = instance

    def __call__(self, *args, **kwargs):
        self._record(args, kwargs)

        try:
            value = next(iter(self._seeded_values(args, kwargs)))[1]
        except StopIteration:
            try:
                value = self.func(self.instance, *args, **kwargs)
            except SeedRequired as e:
                raise SeedRequired("Seed required for %s: %s" %
                                   (self._call_repr(*args, **kwargs), e))
        else:
            if self._is_exception(value):
                raise value

        return deepcopy(value)

    def seed(self, *args, **kwargs):
        """
        A convenience wrapper for
        :meth:`~mockldap.recording.RecordedMethod.set_return_value`.

        ``method.seed(arg1, arg2=True)(value)`` is equivalent to
        ``method.set_return_value([arg1], {'arg2': True}, value)``.
        """
        return partial(self.set_return_value, args, kwargs)

    def set_return_value(self, args, kwargs, value):
        """
        Set a method's return value for a set of arguments.

        Subsequent calls to this method will check for a matching set of
        arguments and return the assoiated value. If the value is an exception
        class or instance, it will be raised instead.

        .. warning::

            When the method is called, the arguments must be passed in exactly
            the same form. We don't automatically match equivalent positional
            and keyword arguments.

        If no preset return value is found, the underlying method will be
        called normally. If that method can not handle the request, it may
        raise :exc:`mockldap.SeedRequired`, indicating that the method must be
        seeded with a return value for these arguments.
        """
        args = deepcopy(args)
        kwargs = deepcopy(kwargs)
        value = deepcopy(value)

        self._seeded_calls.insert(0, ((args, kwargs), value))

    def _record(self, args, kwargs):
        self._recorded_calls.append((self.func.__name__, args, kwargs))

    def _seeded_values(self, args, kwargs):
        func = partial(self._seed_matches, args, kwargs)

        return filter(func, self._seeded_calls)

    def _seed_matches(self, args, kwargs, seed):
        return (seed[0] == (args, kwargs))

    @property
    def _seeded_calls(self):
        return self.instance._seeded_calls[self.func.__name__]

    @property
    def _recorded_calls(self):
        return self.instance._recorded_calls

    def _call_repr(self, *args, **kwargs):
        arglist = [repr(arg) for arg in args]
        arglist.extend('%s=%r' % item for item in kwargs.items())

        return "%s(%s)" % (self.func.__name__, ", ".join(arglist))

    def _is_exception(self, value):
        if isinstance(value, Exception):
            return True

        if (isinstance(value, type) and issubclass(value, Exception)):
            return True

        return False
