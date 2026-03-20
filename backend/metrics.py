"""Prometheus metrics for monitoring."""
import time
from functools import wraps
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Collect and track metrics for the application."""

    def __init__(self):
        self.counters: Dict[str, int] = {}
        self.timers: Dict[str, list] = {}
        self.gauges: Dict[str, float] = {}

    def increment_counter(self, name: str, value: int = 1):
        """Increment a counter metric."""
        if name not in self.counters:
            self.counters[name] = 0
        self.counters[name] += value

    def record_timer(self, name: str, duration_ms: float):
        """Record a timing metric."""
        if name not in self.timers:
            self.timers[name] = []
        self.timers[name].append(duration_ms)

    def set_gauge(self, name: str, value: float):
        """Set a gauge metric."""
        self.gauges[name] = value

    def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics."""
        metrics = {
            "counters": self.counters.copy(),
            "gauges": self.gauges.copy(),
            "timers": {}
        }

        for name, values in self.timers.items():
            if values:
                metrics["timers"][name] = {
                    "count": len(values),
                    "avg_ms": sum(values) / len(values),
                    "min_ms": min(values),
                    "max_ms": max(values),
                }

        return metrics

    def reset(self):
        """Reset all metrics."""
        self.counters.clear()
        self.timers.clear()
        self.gauges.clear()


# Global metrics instance
metrics = MetricsCollector()


def track_timing(metric_name: str):
    """Decorator to track function execution time."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.time()
            try:
                return await func(*args, **kwargs)
            finally:
                duration_ms = (time.time() - start) * 1000
                metrics.record_timer(metric_name, duration_ms)
                logger.debug(f"{metric_name}: {duration_ms:.2f}ms")

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.time()
            try:
                return func(*args, **kwargs)
            finally:
                duration_ms = (time.time() - start) * 1000
                metrics.record_timer(metric_name, duration_ms)
                logger.debug(f"{metric_name}: {duration_ms:.2f}ms")

        # Return appropriate wrapper
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


import asyncio
