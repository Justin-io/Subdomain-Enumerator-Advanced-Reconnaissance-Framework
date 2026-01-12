import resource
import sys
import logging

logger = logging.getLogger(__name__)

def check_ulimit(min_limit=1024):
    """
    Checks the current soft limit for open file descriptors.
    Warns if it appears too low for high-concurrency operations.
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < min_limit:
            logger.warning(
                f"Low file descriptor limit detected: {soft}. "
                f"This may hinder high-concurrency DNS resolution. "
                f"Consider increasing it (e.g., 'ulimit -n 65535')."
            )
            return False
        logger.info(f"File descriptor limit is adequate: {soft}")
        return True
    except Exception as e:
        logger.error(f"Failed to check ulimit: {e}")
        return False
