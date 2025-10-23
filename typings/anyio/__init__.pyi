from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")

def run(coro: Callable[[], Awaitable[T]]) -> T: ...
