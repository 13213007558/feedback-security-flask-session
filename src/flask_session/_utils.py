"""
MIT License

Copyright (c) 2023 giuppep

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import time
from functools import wraps
from typing import Any, Callable

from flask import current_app

from .exceptions import AmbiguousSessionStateError, RetriableSessionError


def total_seconds(timedelta):
    return int(timedelta.total_seconds())


def retry_query(
    *,
    max_attempts: int = 3,
    delay: float = 0.3,
    backoff: int = 2,
    operation: str = "query",
    idempotent: bool = True,
) -> Callable[..., Any]:
    """Retry a storage call according to a decidable contract.

    The wrapped backend must classify driver failures using the exceptions in
    :mod:`flask_session.exceptions` instead of letting arbitrary exceptions
    escape:

    * :class:`~flask_session.exceptions.RetriableSessionError` means the
      failure happened *before* commit, so nothing changed and the call is
      retried up to ``max_attempts`` times.
    * :class:`~flask_session.exceptions.AmbiguousSessionStateError` means the
      write may already have landed (e.g. a timeout after commit). It is
      never hidden behind blind retries:

      - an idempotent operation (reads, key-based deletes/upserts) is retried
        because replaying it converges to the same state;
      - a non-idempotent write aborts immediately so an ambiguous result is
        not turned into a duplicate or a wrongly resurrected session.
    * any other exception is a definite, non-transient error and propagates
      on the first attempt.

    Args:
        max_attempts: Maximum number of attempts. Defaults to 3.
        delay: Delay between attempts in seconds. Defaults to 0.3.
        backoff: Backoff factor. Defaults to 2.
        operation: Logical operation name recorded on an ambiguous outcome.
        idempotent: Whether replaying the call after an ambiguous result is
            guaranteed to converge to the same state.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            store_id = kwargs.get("store_id")
            if store_id is None and len(args) > 1:
                store_id = args[1]

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except AmbiguousSessionStateError:
                    if idempotent and attempt < max_attempts - 1:
                        sleep_time = delay * backoff**attempt
                        current_app.logger.warning(
                            "Ambiguous result for idempotent %s on %r; "
                            "replaying to converge (%d/%d) in %.2fs.",
                            operation,
                            store_id,
                            attempt + 1,
                            max_attempts,
                            sleep_time,
                        )
                        time.sleep(sleep_time)
                        continue
                    # Non-idempotent, or retries exhausted: do not pretend the
                    # outcome is known. Surface the ambiguous state as-is.
                    raise
                except RetriableSessionError as exc:
                    if attempt == max_attempts - 1:
                        raise
                    sleep_time = delay * backoff**attempt
                    current_app.logger.warning(
                        "Transient storage failure during %s (%s); "
                        "retrying (%d/%d) in %.2fs.",
                        operation,
                        exc,
                        attempt + 1,
                        max_attempts,
                        sleep_time,
                    )
                    time.sleep(sleep_time)
                # Any other exception is a definite error: never retry.

        return wrapper

    return decorator
