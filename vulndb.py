import sqlite3
import os
import re
import csv
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass


@dataclass
class CVE:
    cve_id: str
    service_name: str
    version_start: str
    version_end: str
    cvss_score: float
    cvss_severity: str
    description: str


SAMPLE_CVE_DATA = [
    ("CVE-2023-28531", "openssh", "7.0", "8.0", 9.8, "CRITICAL", "OpenSSH through 8.0 allows remote attackers to execute arbitrary code."),
    ("CVE-2023-38408", "openssh", "8.0", "9.3", 9.8, "CRITICAL", "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path."),
    ("CVE-2024-6387", "openssh", "8.5", "9.8", 10.0, "CRITICAL", "A critical vulnerability in OpenSSH's signal handling could allow remote code execution."),
    ("CVE-2022-30190", "openssh", "5.0", "7.4", 7.8, "HIGH", "OpenSSH 7.4 and earlier has a vulnerability in the server side."),
    ("CVE-2023-44487", "nginx", "1.0", "1.25", 7.5, "HIGH", "HTTP/2 Rapid Reset Attack vulnerability in nginx."),
    ("CVE-2021-23017", "nginx", "0.6", "1.21", 8.1, "HIGH", "A security issue was discovered in nginx resolver."),
    ("CVE-2023-1234", "apache", "2.0", "2.4.55", 7.5, "HIGH", "Apache HTTP Server path traversal vulnerability."),
    ("CVE-2021-41773", "apache", "2.4.49", "2.4.50", 9.8, "CRITICAL", "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49."),
    ("CVE-2022-23960", "apache", "2.4.0", "2.4.52", 7.5, "HIGH", "Apache HTTP Server mod_proxy_ajp vulnerability."),
    ("CVE-2023-0045", "mysql", "5.0", "8.0", 7.5, "HIGH", "MySQL Server unspecified vulnerability."),
    ("CVE-2021-27928", "mysql", "8.0", "8.0.23", 7.2, "HIGH", "MySQL Server privilege escalation vulnerability."),
    ("CVE-2022-21278", "mysql", "5.7", "8.0.29", 4.9, "MEDIUM", "MySQL Server vulnerability in InnoDB."),
    ("CVE-2023-23841", "redis", "6.0", "7.0", 7.5, "HIGH", "Redis heap buffer overflow in CVE-2023-23841."),
    ("CVE-2022-0543", "redis", "2.6", "7.0", 8.8, "HIGH", "Redis Lua sandbox escape vulnerability."),
    ("CVE-2021-23679", "redis", "3.0", "6.2", 8.8, "HIGH", "Redis integer overflow vulnerability."),
    ("CVE-2023-2454", "postgresql", "11.0", "15.0", 9.8, "CRITICAL", "PostgreSQL buffer overflow vulnerability."),
    ("CVE-2022-2625", "postgresql", "10.0", "14.0", 8.0, "HIGH", "PostgreSQL extension script vulnerability."),
    ("CVE-2021-32027", "postgresql", "9.6", "13.0", 8.8, "HIGH", "PostgreSQL array subscripting vulnerability."),
    ("CVE-2023-0286", "openssl", "1.0", "3.0", 7.4, "HIGH", "OpenSSL X.509 certificate verification vulnerability."),
    ("CVE-2022-3602", "openssl", "3.0", "3.0.7", 7.5, "HIGH", "OpenSSL punycode buffer overflow vulnerability."),
    ("CVE-2022-3786", "openssl", "3.0", "3.0.7", 7.5, "HIGH", "OpenSSL punycode buffer overflow vulnerability."),
    ("CVE-2023-28252", "mongodb", "3.0", "6.0", 7.5, "HIGH", "MongoDB Server vulnerability."),
    ("CVE-2021-21309", "mongodb", "4.0", "4.4", 8.8, "HIGH", "MongoDB JavaScript engine vulnerability."),
    ("CVE-2023-1428", "wordpress", "5.0", "6.2", 9.8, "CRITICAL", "WordPress PHP Object Injection vulnerability."),
    ("CVE-2023-27457", "wordpress", "6.0", "6.2", 9.8, "CRITICAL", "WordPress SQL injection vulnerability."),
    ("CVE-2022-41082", "microsoft_iis", "7.0", "10.0", 8.8, "HIGH", "Microsoft IIS Server vulnerability."),
    ("CVE-2023-3519", "citrix", "12.0", "13.0", 9.8, "CRITICAL", "Citrix NetScaler Gateway RCE vulnerability."),
    ("CVE-2023-20867", "vmware", "6.0", "7.0", 9.8, "CRITICAL", "VMware vCenter Server vulnerability."),
    ("CVE-2023-0669", "fortinet", "6.0", "7.0", 9.8, "CRITICAL", "Fortinet FortiOS vulnerability."),
    ("CVE-2022-42889", "apache_tomcat", "8.0", "10.0", 9.8, "CRITICAL", "Apache Commons Text RCE vulnerability affecting Tomcat."),
    ("CVE-2023-20198", "cisco_ios", "15.0", "17.0", 10.0, "CRITICAL", "Cisco IOS XE Software Web UI vulnerability."),
    ("CVE-2023-34362", "movabletype", "7.0", "7.10", 9.8, "CRITICAL", "Progress MOVEit Transfer SQL injection vulnerability."),
    ("CVE-2023-38831", "winrar", "5.0", "6.23", 7.8, "HIGH", "WinRAR code execution vulnerability."),
    ("CVE-2023-46604", "activemq", "5.0", "5.18", 10.0, "CRITICAL", "Apache ActiveMQ OpenWire protocol vulnerability."),
    ("CVE-2021-44228", "log4j", "2.0", "2.15", 10.0, "CRITICAL", "Log4j JNDI injection vulnerability."),
    ("CVE-2022-22965", "spring", "5.3", "5.3.18", 9.8, "CRITICAL", "Spring Framework RCE vulnerability (Spring4Shell)."),
    ("CVE-2022-0778", "openssl", "1.0", "3.0.2", 7.5, "HIGH", "OpenSSL BN_mod_sqrt infinite loop vulnerability."),
    ("CVE-2022-2588", "linux_kernel", "5.0", "5.18", 7.8, "HIGH", "Linux kernel cls_route use-after-free vulnerability."),
    ("CVE-2023-33246", "rocketmq", "4.0", "5.1", 9.8, "CRITICAL", "Apache RocketMQ configuration vulnerability."),
    ("CVE-2023-43642", "curl", "7.0", "8.4", 7.5, "HIGH", "cURL cookie handling vulnerability."),
    ("CVE-2023-38545", "curl", "7.0", "8.4", 7.5, "HIGH", "cURL SOCKS5 heap buffer overflow vulnerability."),
]


class VulnDB:
    def __init__(self, db_path: str = "cve.db", csv_path: Optional[str] = None):
        self.db_path = db_path
        self.conn = None
        self._init_db(csv_path)

    def _init_db(self, csv_path: Optional[str] = None) -> None:
        if not os.path.exists(self.db_path):
            self._create_db(csv_path)
        else:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row

    def _create_db(self, csv_path: Optional[str] = None) -> None:
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                service_name TEXT NOT NULL,
                version_start TEXT NOT NULL,
                version_end TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                cvss_severity TEXT NOT NULL,
                description TEXT
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_service ON cves(service_name, version_start)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score)
        """)

        if csv_path and os.path.exists(csv_path):
            self._import_from_csv(cursor, csv_path)
        else:
            cursor.executemany("""
                INSERT INTO cves (cve_id, service_name, version_start, version_end, cvss_score, cvss_severity, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, SAMPLE_CVE_DATA)

        self.conn.commit()

    def _get_severity_from_score(self, score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "INFO"

    def _parse_nvd_csv_row(self, row: Dict[str, str]) -> Optional[Tuple[str, str, str, str, float, str, str]]:
        try:
            cve_id = row.get("CVE ID", row.get("CVE", row.get("cve_id", ""))).strip()
            description = row.get("Description", row.get("description", "")).strip()
            
            cvss_str = row.get("CVSS Score", row.get("CVSS", row.get("cvss_score", "0")))
            try:
                cvss_score = float(cvss_str) if cvss_str else 0.0
            except (ValueError, TypeError):
                cvss_score = 0.0
            
            cvss_severity = row.get("CVSS Severity", row.get("Severity", row.get("cvss_severity", ""))).strip().upper()
            if not cvss_severity:
                cvss_severity = self._get_severity_from_score(cvss_score)
            
            product = row.get("Product", row.get("Software", row.get("service_name", ""))).strip().lower()
            vendor = row.get("Vendor", row.get("vendor", "")).strip().lower()
            
            if not product:
                cpe = row.get("CPE", row.get("cpe", ""))
                if cpe:
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        product = parts[4].lower()
            
            if not product or not cve_id:
                return None
            
            version_start = row.get("Version Start", row.get("version_start", row.get("Affected Version", "0"))).strip()
            version_end = row.get("Version End", row.get("version_end", row.get("Affected Version End", "9999"))).strip()
            
            if not version_start or version_start in ["*", "-", "n/a"]:
                version_start = "0"
            if not version_end or version_end in ["*", "-", "n/a"]:
                version_end = "9999"
            
            return (cve_id, product, version_start, version_end, cvss_score, cvss_severity, description)
        except Exception:
            return None

    def _import_from_csv(self, cursor: sqlite3.Cursor, csv_path: str) -> int:
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"CSV 文件不存在: {csv_path}")

        count = 0
        batch_size = 1000
        batch_data = []

        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    parsed = self._parse_nvd_csv_row(row)
                    if parsed:
                        batch_data.append(parsed)
                        count += 1
                        
                        if len(batch_data) >= batch_size:
                            cursor.executemany("""
                                INSERT INTO cves (cve_id, service_name, version_start, version_end, cvss_score, cvss_severity, description)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            """, batch_data)
                            batch_data = []

                if batch_data:
                    cursor.executemany("""
                        INSERT INTO cves (cve_id, service_name, version_start, version_end, cvss_score, cvss_severity, description)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, batch_data)

        except Exception as e:
            raise RuntimeError(f"导入 CSV 失败: {e}")

        return count

    def import_csv(self, csv_path: str) -> int:
        if not self.conn:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
        
        cursor = self.conn.cursor()
        count = self._import_from_csv(cursor, csv_path)
        self.conn.commit()
        return count

    def _parse_version(self, version: str) -> List[int]:
        if not version:
            return [0]
        parts = re.findall(r'\d+', version)
        return [int(p) for p in parts] if parts else [0]

    def _version_compare(self, v1: str, v2: str) -> int:
        p1 = self._parse_version(v1)
        p2 = self._parse_version(v2)
        max_len = max(len(p1), len(p2))
        p1.extend([0] * (max_len - len(p1)))
        p2.extend([0] * (max_len - len(p2)))
        for a, b in zip(p1, p2):
            if a < b:
                return -1
            elif a > b:
                return 1
        return 0

    def _version_in_range(self, version: str, start: str, end: str) -> bool:
        if not version:
            return False
        return self._version_compare(version, start) >= 0 and self._version_compare(version, end) <= 0

    def _version_matches(self, service_version: str, cve_version_start: str, cve_version_end: str) -> bool:
        if not service_version:
            return False
        sv_parts = self._parse_version(service_version)
        start_parts = self._parse_version(cve_version_start)
        end_parts = self._parse_version(cve_version_end)
        
        prefix_len = min(len(sv_parts), len(start_parts))
        sv_prefix = sv_parts[:prefix_len]
        start_prefix = start_parts[:prefix_len]
        end_prefix = end_parts[:prefix_len]
        
        if sv_prefix >= start_prefix and sv_prefix <= end_prefix:
            return True
        
        return self._version_in_range(service_version, cve_version_start, cve_version_end)

    def query(self, service_name: str, version: str, limit: int = 20) -> List[CVE]:
        if not self.conn:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row

        cursor = self.conn.cursor()
        query = """
            SELECT cve_id, service_name, version_start, version_end, cvss_score, cvss_severity, description
            FROM cves
            WHERE service_name LIKE ?
            ORDER BY cvss_score DESC
            LIMIT ?
        """
        service_pattern = f"%{service_name.lower()}%"
        cursor.execute(query, (service_pattern, limit))
        rows = cursor.fetchall()

        results = []
        for row in rows:
            if self._version_matches(version, row["version_start"], row["version_end"]):
                results.append(CVE(
                    cve_id=row["cve_id"],
                    service_name=row["service_name"],
                    version_start=row["version_start"],
                    version_end=row["version_end"],
                    cvss_score=row["cvss_score"],
                    cvss_severity=row["cvss_severity"],
                    description=row["description"]
                ))

        return results

    def query_all(self, fingerprint_results: Dict[str, List[Dict]]) -> Dict[str, Dict]:
        all_results: Dict[str, Dict] = {}
        for ip, services in fingerprint_results.items():
            all_results[ip] = {}
            for svc in services:
                service = svc["service"]
                version = svc["version"]
                cves = self.query(service, version)
                all_results[ip][f"{service}:{svc['port']}"] = {
                    "port": svc["port"],
                    "service": service,
                    "version": version,
                    "cves": cves
                }
        return all_results

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None
