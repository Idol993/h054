import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set
from utils.rate_limiter import RateLimiter


class HostDiscovery:
    def __init__(self, rate_limiter: RateLimiter, timeout: int = 2, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_limiter = rate_limiter
        self.system = platform.system()

    def _ping_host(self, ip: str) -> bool:
        self.rate_limiter.wait()
        if self.system == "Windows":
            command = ["ping", "-n", "1", "-w", str(self.timeout * 1000), ip]
        else:
            command = ["ping", "-c", "1", "-W", str(self.timeout), ip]
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 1
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return False
        except Exception:
            return False

    def discover(self, ip_list: List[str]) -> Set[str]:
        alive_hosts = set()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._ping_host, ip): ip for ip in ip_list}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        alive_hosts.add(ip)
                except Exception:
                    continue
        return alive_hosts
