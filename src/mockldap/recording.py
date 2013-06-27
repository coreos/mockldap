"""
Tools for recording method calls and seeding return values.
"""
from collections import defaultdict
from copy import deepcopy
from functools import partial
from itertools import ifilter


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
    >>> c._recorded_calls
    [('plus1', (5,), {}), ('plus1', (5,), {}), ('plus1', (4,), {})]
    >>> c = C()
    >>> c.plus1.seed(n=5)(8)
    >>> c.plus1(5)
    6
    >>> c.plus1(n=5)
    8
    >>> c._recorded_calls
    [('plus1', (5,), {}), ('plus1', (), {'n': 5})]
    >>> c = C()
    >>> c.plus1.seed(5)(9)
    >>> c.plus1.seed(5)(10)
    >>> c.plus1(5)
    10
    """
    def __init__(self, func):
        self.func = func

    def __get__(self, instance, owner):
        func = self.func
        if instance is not None:
            func = _Bound(self.func, instance)

        return func


class _Bound(object):
    def __init__(self, func, instance):
        self.func = func
        self.instance = instance

    def __call__(self, *args, **kwargs):
        self._record(args, kwargs)

        try:
            value = next(self._seeded_values(args, kwargs))[1]
        except StopIteration:
            value = self.func(self.instance, *args, **kwargs)

        return value

    def seed(self, *args, **kwargs):
        return partial(self.set_return_value, args, kwargs)

    def set_return_value(self, args, kwargs, value):
        self._seeded_calls.insert(0, ((deepcopy(args), deepcopy(kwargs)), deepcopy(value)))

    def _record(self, args, kwargs):
        self._recorded_calls.append((self.func.__name__, args, kwargs))

    def _seeded_values(self, args, kwargs):
        return ifilter(partial(self._seed_matches, args, kwargs), self._seeded_calls)

    def _seed_matches(self, args, kwargs, seed):
        return (seed[0] == (args, kwargs))

    @property
    def _seeded_calls(self):
        return self.instance._seeded_calls[self.func.__name__]

    @property
    def _recorded_calls(self):
        return self.instance._recorded_calls
