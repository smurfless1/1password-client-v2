from time import sleep
from functools import wraps


def retry(exceptions=None, tries=-1, delay=0, logger=None):
    """Executes a function and retries it if it failed.

    :param tuple exceptions: an exception or a tuple of exceptions to catch. default: Exception
    :param integer tries: the maximum number of attempts. default: -1 (infinite)
    :param integer delay: initial delay between attempts. default: 0
    :param logging.Logger logger: logger.warning(fmt, error, delay) will be called \
on failed attempts. default: retry.logging_logger. if None, logging is disabled

    """

    exceptions = exceptions if exceptions else (Exception,)

    def retry_decorator(func):
        """Helper function to allow passing in arguments to the decorator"""

        @wraps(func)
        def retry_wrapper(*args, **kwargs):
            """Executes a function and retries it if it failed.

            :raises Exception: If the function failed

            """
            _tries = tries
            while (_tries):
                try:

                    return func(*args, **kwargs)

                except exceptions as error:  # pylint:disable=broad-except
                    _tries -= 1
                    if (not _tries):
                        raise

                    if (logger):
                        logger.warning('%s, retrying in %s seconds...', error, delay)

                    sleep(delay)

        return retry_wrapper

    return retry_decorator
