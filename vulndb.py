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
    start_inclusive: bool = True
    end_inclusive: bool = True
    matched_service: str = ""
    match_reason: str = ""


SERVICE_ALIASES = {
    "apache": ["http_server", "apache_http_server", "httpd", "apache2"],
    "microsoft_iis": ["internet_information_services", "iis", "internet_information_server"],
    "openssh": ["ssh", "open_ssh"],
    "nginx": ["nginx_web_server", "engine_x"],
    "mysql": ["mysql_server", "mysql_database"],
    "postgresql": ["postgres", "postgresql_database"],
    "redis": ["redis_server", "redis_cache"],
    "apache_tomcat": ["tomcat", "tomcat_server"],
    "mongodb": ["mongo", "mongodb_server"],
    "nodejs": ["node.js", "node_js"],
    "wordpress": ["wordpress_cms", "wp"],
    "curl": ["libcurl", "curl_tool"],
    "openssl": ["open_ssl", "ssl_library"],
}


def normalize_service_name(service_name: str) -> str:
    name = service_name.lower().strip().replace("-", "_").replace(" ", "_")
    for canonical, aliases in SERVICE_ALIASES.items():
        if name == canonical or name in aliases:
            return canonical
    return name


def get_cvss_severity(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0:
        return "LOW"
    else:
        return "INFO"


def normalize_severity(severity: str) -> str:
    if not severity:
        return "NONE"
    sev = severity.strip().upper()
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE", "UNKNOWN"):
        return sev
    return "UNKNOWN"


def severity_rank(severity: str) -> int:
    sev = normalize_severity(severity)
    ranks = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "NONE": 5,
        "UNKNOWN": 6,
    }
    return ranks.get(sev, 6)


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE", "UNKNOWN"]


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
    def __init__(self, db_path: str = "cve.db", csv_path: Optional[str] = None, load_sample: bool = True):
        self.db_path = db_path
        self.conn = None
        self._init_db(csv_path, load_sample)

    def _init_db(self, csv_path: Optional[str] = None, load_sample: bool = True) -> None:
        if not os.path.exists(self.db_path):
            self._create_db(csv_path, load_sample)
        else:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self._ensure_table_exists()

    def _create_db(self, csv_path: Optional[str] = None, load_sample: bool = True) -> None:
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
                start_inclusive INTEGER NOT NULL DEFAULT 1,
                end_inclusive INTEGER NOT NULL DEFAULT 1,
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

        if csv_path:
            if not os.path.exists(csv_path):
                raise FileNotFoundError(f"CSV 文件不存在: {csv_path}")
            self._import_from_csv(cursor, csv_path)
        elif load_sample:
            cursor.executemany("""
                INSERT INTO cves (cve_id, service_name, version_start, version_end, start_inclusive, end_inclusive, cvss_score, cvss_severity, description)
                VALUES (?, ?, ?, ?, 1, 1, ?, ?, ?)
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

    def _parse_version_from_cpe(self, cpe: str) -> Tuple[str, str, bool]:
        if not cpe:
            return "", "", False
        
        cpe = cpe.strip()
        parts = cpe.split(":")
        
        product = ""
        version = ""
        has_exact_version = False
        
        if len(parts) >= 5:
            product = parts[4].lower()
        
        if len(parts) >= 6 and parts[5] and parts[5] not in ["*", "-", ""]:
            version = parts[5]
            has_exact_version = True
        
        return product, version, has_exact_version

    def _parse_nvd_csv_row(self, row: Dict[str, str]) -> Optional[Tuple[str, str, str, str, bool, bool, float, str, str]]:
        try:
            row_lower = {k.lower().replace("-", "_").replace(" ", "_"): v for k, v in row.items()}
            
            cve_id = (row_lower.get("cve_id") or row_lower.get("cve") or "").strip()
            description = (row_lower.get("description") or row_lower.get("summary") or "").strip()
            
            cvss_str = (row_lower.get("cvss_score") or row_lower.get("cvss") 
                       or row_lower.get("basescore") or "0")
            try:
                cvss_score = float(cvss_str) if cvss_str else 0.0
            except (ValueError, TypeError):
                cvss_score = 0.0
            
            cvss_severity = (row_lower.get("cvss_severity") or row_lower.get("severity")
                            or row_lower.get("baseseverity") or "").strip().upper()
            if not cvss_severity:
                cvss_severity = self._get_severity_from_score(cvss_score)
            
            product = (row_lower.get("service_name") or row_lower.get("product") 
                      or row_lower.get("software") or "").strip().lower()
            
            cpe = (row_lower.get("cpe") or row_lower.get("cpe23uri") or row_lower.get("cpe_string") or "")
            cpe_product, cpe_version, cpe_has_exact = self._parse_version_from_cpe(cpe)
            
            if not product and cpe_product:
                product = cpe_product
            
            if not product or not cve_id:
                return None
            
            product = normalize_service_name(product)
            
            version_start = ""
            version_end = ""
            start_inclusive = True
            end_inclusive = True
            
            for key in ["versionstartexcluding", "version_start_excluding"]:
                val = row_lower.get(key)
                if val and val.strip():
                    version_start = val.strip()
                    start_inclusive = False
                    break
            
            if not version_start:
                for key in ["versionstartincluding", "version_start_including", "version_start"]:
                    val = row_lower.get(key)
                    if val and val.strip():
                        version_start = val.strip()
                        start_inclusive = True
                        break
            
            for key in ["versionendexcluding", "version_end_excluding"]:
                val = row_lower.get(key)
                if val and val.strip():
                    version_end = val.strip()
                    end_inclusive = False
                    break
            
            if not version_end:
                for key in ["versionendincluding", "version_end_including", "version_end"]:
                    val = row_lower.get(key)
                    if val and val.strip():
                        version_end = val.strip()
                        end_inclusive = True
                        break
            
            affected_version = (row_lower.get("affected_version") or row_lower.get("version") or "").strip()
            if not version_start and not version_end and affected_version and affected_version not in ["*", "-", "n/a"]:
                version_start = affected_version
                version_end = affected_version
                start_inclusive = True
                end_inclusive = True
            
            if cpe_has_exact and not version_start and not version_end:
                version_start = cpe_version
                version_end = cpe_version
                start_inclusive = True
                end_inclusive = True
            
            if not version_start or version_start in ["*", "-", "n/a", ""]:
                version_start = "0"
                start_inclusive = True
            if not version_end or version_end in ["*", "-", "n/a", ""]:
                version_end = "9999"
                end_inclusive = True
            
            if version_start == version_end and version_start == "0":
                return None
            
            return (cve_id, product, version_start, version_end, start_inclusive, end_inclusive, cvss_score, cvss_severity, description)
        except Exception as e:
            return None

    def _import_from_csv(self, cursor: sqlite3.Cursor, csv_path: str) -> Tuple[int, int]:
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"CSV 文件不存在: {csv_path}")

        imported = 0
        skipped = 0
        batch_size = 1000
        batch_data = []

        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    parsed = self._parse_nvd_csv_row(row)
                    if parsed:
                        batch_data.append(parsed)
                        imported += 1
                        
                        if len(batch_data) >= batch_size:
                            cursor.executemany("""
                                INSERT INTO cves (cve_id, service_name, version_start, version_end, start_inclusive, end_inclusive, cvss_score, cvss_severity, description)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, batch_data)
                            batch_data = []
                    else:
                        skipped += 1

                if batch_data:
                    cursor.executemany("""
                        INSERT INTO cves (cve_id, service_name, version_start, version_end, start_inclusive, end_inclusive, cvss_score, cvss_severity, description)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, batch_data)

        except Exception as e:
            raise RuntimeError(f"导入 CSV 失败: {e}")

        return imported, skipped

    def _ensure_table_exists(self) -> None:
        if not self.conn:
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
                start_inclusive INTEGER NOT NULL DEFAULT 1,
                end_inclusive INTEGER NOT NULL DEFAULT 1,
                cvss_score REAL NOT NULL,
                cvss_severity TEXT NOT NULL,
                description TEXT
            )
        """)
        
        cursor.execute("PRAGMA table_info(cves)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'start_inclusive' not in columns:
            cursor.execute("ALTER TABLE cves ADD COLUMN start_inclusive INTEGER NOT NULL DEFAULT 1")
        if 'end_inclusive' not in columns:
            cursor.execute("ALTER TABLE cves ADD COLUMN end_inclusive INTEGER NOT NULL DEFAULT 1")
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_service ON cves(service_name, version_start)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score)
        """)
        self.conn.commit()

    def import_csv(self, csv_path: str) -> Tuple[int, int]:
        if not self.conn:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
        
        self._ensure_table_exists()
        
        cursor = self.conn.cursor()
        imported, skipped = self._import_from_csv(cursor, csv_path)
        self.conn.commit()
        return imported, skipped

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

    def _version_in_range(self, version: str, start: str, end: str, 
                         start_inclusive: bool = True, end_inclusive: bool = True) -> bool:
        if not version:
            return False
        
        start_cmp = self._version_compare(version, start)
        end_cmp = self._version_compare(version, end)
        
        start_ok = start_cmp > 0 or (start_inclusive and start_cmp == 0)
        end_ok = end_cmp < 0 or (end_inclusive and end_cmp == 0)
        
        return start_ok and end_ok

    def _version_matches(self, service_version: str, cve_version_start: str, cve_version_end: str,
                         start_inclusive: bool = True, end_inclusive: bool = True) -> bool:
        if not service_version:
            return False
        sv_parts = self._parse_version(service_version)
        start_parts = self._parse_version(cve_version_start)
        end_parts = self._parse_version(cve_version_end)
        
        prefix_len = min(len(sv_parts), len(start_parts))
        sv_prefix = sv_parts[:prefix_len]
        start_prefix = start_parts[:prefix_len]
        end_prefix = end_parts[:prefix_len]
        
        start_cmp = 0
        for a, b in zip(sv_prefix, start_prefix):
            if a < b:
                start_cmp = -1
                break
            elif a > b:
                start_cmp = 1
                break
        
        end_cmp = 0
        for a, b in zip(sv_prefix, end_prefix):
            if a < b:
                end_cmp = -1
                break
            elif a > b:
                end_cmp = 1
                break
        
        start_ok = start_cmp > 0 or (start_inclusive and start_cmp == 0)
        end_ok = end_cmp < 0 or (end_inclusive and end_cmp == 0)
        
        if start_ok and end_ok:
            return True
        
        return self._version_in_range(service_version, cve_version_start, cve_version_end, 
                                      start_inclusive, end_inclusive)

    def _get_match_reason(self, service_version: str, cve_version_start: str, cve_version_end: str,
                          start_inclusive: bool, end_inclusive: bool) -> str:
        start_op = ">=" if start_inclusive else ">"
        end_op = "<=" if end_inclusive else "<"
        return f"版本 {service_version} 满足 {start_op} {cve_version_start} 且 {end_op} {cve_version_end}"

    def _get_service_search_names(self, service_name: str) -> List[str]:
        normalized = normalize_service_name(service_name)
        names = {normalized}
        names.add(service_name.lower())
        
        if normalized in SERVICE_ALIASES:
            for alias in SERVICE_ALIASES[normalized]:
                names.add(alias)
        
        for canonical, aliases in SERVICE_ALIASES.items():
            if service_name.lower() in aliases:
                names.add(canonical)
                for a in aliases:
                    names.add(a)
        
        return list(names)

    def _ensure_conn(self) -> None:
        if not self.conn:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self._ensure_table_exists()

    def query(self, service_name: str, version: str, limit: int = 20, min_severity: Optional[str] = None) -> List[CVE]:
        self._ensure_conn()
        cursor = self.conn.cursor()
        
        search_names = self._get_service_search_names(service_name)
        
        all_rows = []
        for name in search_names:
            query = """
                SELECT cve_id, service_name, version_start, version_end, start_inclusive, end_inclusive, 
                       cvss_score, cvss_severity, description
                FROM cves
                WHERE service_name LIKE ?
            """
            cursor.execute(query, (f"%{name}%",))
            all_rows.extend(cursor.fetchall())
        
        seen = set()
        unique_rows = []
        for row in all_rows:
            key = row["cve_id"]
            if key not in seen:
                seen.add(key)
                unique_rows.append(row)

        matched = []
        for row in unique_rows:
            start_inclusive = bool(row["start_inclusive"]) if "start_inclusive" in row.keys() else True
            end_inclusive = bool(row["end_inclusive"]) if "end_inclusive" in row.keys() else True
            
            if self._version_matches(version, row["version_start"], row["version_end"],
                                    start_inclusive, end_inclusive):
                cve = CVE(
                    cve_id=row["cve_id"],
                    service_name=row["service_name"],
                    version_start=row["version_start"],
                    version_end=row["version_end"],
                    cvss_score=row["cvss_score"],
                    cvss_severity=row["cvss_severity"],
                    description=row["description"],
                    start_inclusive=start_inclusive,
                    end_inclusive=end_inclusive,
                    matched_service=service_name,
                    match_reason=self._get_match_reason(version, row["version_start"], 
                                                        row["version_end"], 
                                                        start_inclusive, end_inclusive)
                )
                matched.append(cve)

        if min_severity:
            min_rank = severity_rank(min_severity)
            matched = [c for c in matched if severity_rank(c.cvss_severity) <= min_rank]

        matched.sort(key=lambda x: x.cvss_score, reverse=True)
        
        return matched[:limit]

    def check_database(self) -> Dict:
        self._ensure_conn()
        cursor = self.conn.cursor()
        
        stats = {}
        
        cursor.execute("SELECT COUNT(*) as total FROM cves")
        total = cursor.fetchone()["total"]
        stats["total_cves"] = total
        
        cursor.execute("SELECT COUNT(DISTINCT service_name) as services FROM cves")
        stats["unique_services"] = cursor.fetchone()["services"] or 0
        
        cursor.execute("""
            SELECT cvss_severity, COUNT(*) as count 
            FROM cves 
            GROUP BY cvss_severity 
            ORDER BY COUNT(*) DESC
        """)
        raw_severity_dist = {}
        for row in cursor.fetchall():
            sev = row["cvss_severity"]
            normalized = normalize_severity(sev)
            raw_severity_dist[normalized] = raw_severity_dist.get(normalized, 0) + row["count"]
        
        all_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE", "UNKNOWN"]
        severity_dist = {}
        for sev in all_levels:
            severity_dist[sev] = raw_severity_dist.get(sev, 0)
        stats["severity_distribution"] = severity_dist
        
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE version_start = '0' OR version_end = '9999' OR version_start IS NULL OR version_end IS NULL")
        stats["missing_version_range"] = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE cvss_score = 0 OR cvss_severity IS NULL OR cvss_severity = ''")
        stats["missing_cvss"] = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE description IS NULL OR description = ''")
        stats["missing_description"] = cursor.fetchone()["count"]
        
        cursor.execute("""
            SELECT service_name, COUNT(*) as count, MAX(cvss_score) as max_score
            FROM cves 
            GROUP BY service_name 
            ORDER BY count DESC, max_score DESC
            LIMIT 10
        """)
        top_services = []
        for row in cursor.fetchall():
            max_cvss = row["max_score"] or 0.0
            top_services.append({
                "service_name": row["service_name"],
                "cve_count": row["count"],
                "max_cvss": max_cvss,
                "max_severity": get_cvss_severity(max_cvss)
            })
        stats["top_services"] = top_services
        
        cursor.execute("SELECT MAX(cvss_score) as max_score FROM cves")
        max_row = cursor.fetchone()
        stats["max_cvss_score"] = max_row["max_score"] if max_row and max_row["max_score"] is not None else 0.0
        
        return stats

    def query_all(self, fingerprint_results: Dict[str, List[Dict]], 
                  min_severity: Optional[str] = None, cve_only: bool = False) -> Dict[str, Dict]:
        all_results: Dict[str, Dict] = {}
        for ip, services in fingerprint_results.items():
            all_results[ip] = {}
            for svc in services:
                service = svc["service"]
                version = svc["version"]
                cves = self.query(service, version, min_severity=min_severity)
                
                if cve_only and not cves:
                    continue
                    
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
