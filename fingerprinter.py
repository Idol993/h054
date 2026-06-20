import socket
import re
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


SERVER_HEADER_PATTERNS = [
    (r"nginx/([\d.]+)", "nginx"),
    (r"Apache/([\d.]+)", "apache"),
    (r"Microsoft-IIS/([\d.]+)", "microsoft_iis"),
    (r"nginx", "nginx", ""),
    (r"Apache", "apache", ""),
    (r"Microsoft-IIS", "microsoft_iis", ""),
    (r"lighttpd/([\d.]+)", "lighttpd"),
    (r"LiteSpeed", "litespeed"),
    (r"OpenResty/([\d.]+)", "openresty"),
    (r"Tomcat/([\d.]+)", "apache_tomcat"),
    (r"Jetty/([\d.]+)", "jetty"),
    (r"Node\.js", "nodejs"),
    (r"Express", "express"),
    (r"werkzeug/([\d.]+)", "werkzeug"),
]


SERVICE_PROBES = [
    {
        "name": "ssh",
        "ports": [22],
        "probes": [
            {"payload": b"\n", "match": r"SSH-\d+\.\d+-([A-Za-z0-9]+)[_-]([\d.]+)"},
            {"payload": b"", "match": r"SSH-\d+\.\d+-([A-Za-z0-9]+)[_-]([\d.]+)"},
        ],
        "service": "ssh",
        "extract_product": True
    },
    {
        "name": "ftp",
        "ports": [21],
        "probes": [
            {"payload": b"", "match": r"220.*FTP(?: server)?(?: v?([\d.]+))?"},
        ],
        "service": "ftp"
    },
    {
        "name": "smtp",
        "ports": [25, 465, 587],
        "probes": [
            {"payload": b"EHLO test\r\n", "match": r"220 ([\w.-]+) ESMTP(?: Service)?(?: v?([\d.]+))?"},
            {"payload": b"", "match": r"220 ([\w.-]+) ESMTP"},
        ],
        "service": "smtp"
    },
    {
        "name": "mysql",
        "ports": [3306],
        "probes": [
            {"payload": b"", "match": r".*?([\d.]+)-MariaDB|.*?([\d.]+)-community|.*?([\d.]+)-log"},
        ],
        "service": "mysql"
    },
    {
        "name": "redis",
        "ports": [6379],
        "probes": [
            {"payload": b"INFO\r\n", "match": r"redis_version:([\d.]+)"},
            {"payload": b"PING\r\n", "match": r"\+PONG"},
        ],
        "service": "redis"
    },
    {
        "name": "postgresql",
        "ports": [5432],
        "probes": [
            {"payload": b"\x00\x00\x00\x08\x04\xd2\x16\x2f", "match": r"PostgreSQL ([\d.]+)"},
        ],
        "service": "postgresql"
    },
    {
        "name": "telnet",
        "ports": [23],
        "probes": [
            {"payload": b"\n", "match": r"Telnet|Welcome|login:"},
        ],
        "service": "telnet"
    },
    {
        "name": "pop3",
        "ports": [110, 995],
        "probes": [
            {"payload": b"", "match": r"\+OK.*POP3(?: server)?(?: v?([\d.]+))?"},
        ],
        "service": "pop3"
    },
    {
        "name": "imap",
        "ports": [143, 993],
        "probes": [
            {"payload": b"a001 LOGOUT\r\n", "match": r"\* OK.*IMAP(?:4rev1)?(?: service)?(?: v?([\d.]+))?"},
            {"payload": b"", "match": r"\* OK.*IMAP"},
        ],
        "service": "imap"
    },
    {
        "name": "mongodb",
        "ports": [27017, 27018, 27019],
        "probes": [
            {"payload": b"\x3a\x00\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00\x74\x65\x73\x74\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x00\x00\x00\x00\x00\xf0\x3f\x00", "match": r"\"version\"\s*:\s*\"([\d.]+)\""},
        ],
        "service": "mongodb"
    },
    {
        "name": "memcached",
        "ports": [11211],
        "probes": [
            {"payload": b"version\r\n", "match": r"VERSION ([\d.]+)"},
        ],
        "service": "memcached"
    },
]


HTTP_PATHS = ["/", "/index.html", "/favicon.ico", "/robots.txt"]


class ServiceFingerprinter:
    def __init__(self, timeout: int = 5, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers

    def _get_banner(self, ip: str, port: int, probe: bytes = b"\n") -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            if probe:
                sock.sendall(probe)
            banner = b""
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass
            sock.close()
            try:
                return banner.decode("utf-8", errors="ignore").strip()
            except UnicodeDecodeError:
                return banner.decode("latin-1", errors="ignore").strip()
        except Exception:
            return ""

    def _parse_server_header(self, server: str) -> Tuple[str, str]:
        if not server:
            return "http", ""
        server_lower = server.lower()
        for pattern in SERVER_HEADER_PATTERNS:
            if len(pattern) == 3:
                regex, service_name, default_version = pattern
            else:
                regex, service_name = pattern
                default_version = ""
            match = re.search(regex, server, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else default_version
                return service_name, version
        return "http", server

    def _probe_http(self, ip: str, port: int) -> Tuple[str, str]:
        if not HAS_REQUESTS:
            return "http", ""
        for scheme in ["http", "https"]:
            for path in HTTP_PATHS:
                try:
                    url = f"{scheme}://{ip}:{port}{path}"
                    response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                    server = response.headers.get("Server", "")
                    if server:
                        return self._parse_server_header(server)
                    if response.status_code:
                        return "http", f"HTTP {response.status_code}"
                except Exception:
                    continue
        return "http", ""

    def _match_service(self, ip: str, port: int) -> Tuple[str, str]:
        if port in [80, 8080, 8000, 8443, 443, 9090, 9000]:
            return self._probe_http(ip, port)

        for probe_def in SERVICE_PROBES:
            if port in probe_def["ports"]:
                for probe in probe_def["probes"]:
                    banner = self._get_banner(ip, port, probe["payload"])
                    if banner:
                        match = re.search(probe["match"], banner, re.IGNORECASE)
                        if match:
                            if probe_def.get("extract_product", False):
                                product_name = match.group(1).lower() if match.group(1) else ""
                                version = match.group(2) if len(match.groups()) > 1 and match.group(2) else ""
                                if product_name:
                                    return product_name, version
                            else:
                                version = ""
                                for g in match.groups():
                                    if g:
                                        version = g
                                        break
                            return probe_def["service"], version
                return probe_def["service"], ""

        banner = self._get_banner(ip, port, b"\n")
        if banner:
            return "unknown", banner[:50]
        return "unknown", ""

    def fingerprint(self, scan_results: Dict[str, List[int]]) -> Dict[str, List[Dict]]:
        results: Dict[str, List[Dict]] = {}
        tasks = [(ip, port) for ip, ports in scan_results.items() for port in ports]

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._match_service, ip, port): (ip, port)
                for ip, port in tasks
            }
            for future in as_completed(futures):
                ip, port = futures[future]
                try:
                    service, version = future.result()
                    if ip not in results:
                        results[ip] = []
                    results[ip].append({
                        "port": port,
                        "service": service,
                        "version": version
                    })
                except Exception:
                    if ip not in results:
                        results[ip] = []
                    results[ip].append({
                        "port": port,
                        "service": "unknown",
                        "version": ""
                    })

        for ip in results:
            results[ip].sort(key=lambda x: x["port"])

        return results
