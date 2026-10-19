"""Bounded UI readiness polling without string evaluation inside the page."""
import time


def wait_for_idle(page, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if page.evaluate('() => !state.busy'):
            return
        page.wait_for_timeout(20)
    raise AssertionError('UI action did not complete within the timeout')
