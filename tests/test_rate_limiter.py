"""Tests for the Rate Limiter."""

import time
import pytest
from app.security.rate_limiter import RateLimiter


def test_rate_limiter_allows_up_to_limit():
    limiter = RateLimiter(max_requests=3, window_seconds=60)
    user_id = 99901

    for i in range(3):
        allowed, remaining, retry_after = limiter.check_limit(user_id)
        assert allowed is True
        assert remaining == 2 - i
        assert retry_after == 0


def test_rate_limiter_blocks_excessive_requests():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    user_id = 99902

    # First 2 succeed
    limiter.check_limit(user_id)
    limiter.check_limit(user_id)

    # 3rd request blocked
    allowed, remaining, retry_after = limiter.check_limit(user_id)
    assert allowed is False
    assert remaining == 0
    assert retry_after > 0


def test_rate_limiter_user_isolation():
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    user_a = 1001
    user_b = 1002

    assert limiter.check_limit(user_a)[0] is True
    assert limiter.check_limit(user_a)[0] is False  # user_a now blocked

    # user_b should still be allowed
    assert limiter.check_limit(user_b)[0] is True
