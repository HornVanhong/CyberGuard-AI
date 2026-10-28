"""CyberGuard AI - Sliding Window Rate Limiter.

Prevents Denial of Service and API quota exhaustion by limiting
scan requests per Telegram user ID.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Dict, List, Tuple


class RateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self, max_requests: int = 5, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._user_timestamps: Dict[int, List[float]] = defaultdict(list)
        self._last_prune = time.monotonic()

    def check_limit(self, user_id: int) -> Tuple[bool, int, int]:
        """Checks if a user is within limits.

        Returns:
            Tuple[bool, int, int]:
                - is_allowed (True if within limit)
                - remaining_requests (requests left in current window)
                - retry_after_seconds (seconds to wait if limited, 0 if allowed)
        """
        now = time.monotonic()
        with self._lock:
            # Periodic prune of stale users
            if now - self._last_prune > 300:
                self._prune_stale(now)

            cutoff = now - self.window_seconds
            # Keep only timestamps in the current window
            timestamps = [t for t in self._user_timestamps[user_id] if t > cutoff]
            self._user_timestamps[user_id] = timestamps

            if len(timestamps) >= self.max_requests:
                earliest = timestamps[0]
                retry_after = max(1, int(self.window_seconds - (now - earliest)))
                return False, 0, retry_after

            # Allow and register this request
            timestamps.append(now)
            remaining = self.max_requests - len(timestamps)
            return True, remaining, 0

    def reset_user(self, user_id: int) -> None:
        """Resets rate limit for a specific user (useful for testing or admin)."""
        with self._lock:
            self._user_timestamps.pop(user_id, None)

    def _prune_stale(self, now: float) -> None:
        """Cleans up inactive users to preserve memory."""
        cutoff = now - self.window_seconds
        stale_keys = [
            uid for uid, t_list in self._user_timestamps.items()
            if not t_list or t_list[-1] <= cutoff
        ]
        for uid in stale_keys:
            del self._user_timestamps[uid]
        self._last_prune = now
