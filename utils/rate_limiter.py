import time
import threading
from collections import deque


class RateLimiter:
    def __init__(self, max_rate: int):
        self.max_rate = max_rate
        self.timestamps = deque()
        self.lock = threading.Lock()

    def wait(self) -> None:
        if self.max_rate <= 0:
            return
        with self.lock:
            now = time.time()
            while self.timestamps and now - self.timestamps[0] >= 1.0:
                self.timestamps.popleft()
            if len(self.timestamps) >= self.max_rate:
                sleep_time = 1.0 - (now - self.timestamps[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                now = time.time()
                while self.timestamps and now - self.timestamps[0] >= 1.0:
                    self.timestamps.popleft()
            self.timestamps.append(now)
