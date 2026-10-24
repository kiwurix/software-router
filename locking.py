from collections.abc import Callable


def locked(func: Callable):
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return func(self, *args, **kwargs)

    return wrapper
