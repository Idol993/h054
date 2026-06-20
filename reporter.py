import os
from typing import Dict, List, Set, Tuple
from datetime import datetime
from dataclasses import dataclass
from vulndb import CVE

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "blue",
    "UNKNOWN": "white"
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


@dataclass
class ScanResult:
    target: str
    scan_time: datetime
    alive_hosts: Set[str]
    open_ports: Dict[str, List[int]]
    fingerprints: Dict[str, List[Dict]]
    vulnerabilities: Dict[str, Dict]

    def get_severity_for_service(self, svc_data: Dict) -> str:
        cves = svc_data.get("cves", [])
        if not cves:
            return "INFO"
        max_score = max(c.cvss_score for c in cves)
        if max_score >= 9.0:
            return "CRITICAL"
        elif max_score >= 7.0:
            return "HIGH"
        elif max_score >= 4.0:
            return "MEDIUM"
        elif max_score > 0:
            return "LOW"
        return "INFO"


class Reporter:
    def __init__(self):
        if RICH_AVAILABLE:
            self.console = Console()
        else:
            self.console = None

    def _sort_by_severity(self, items: List[Tuple[str, Dict]]) -> List[Tuple[str, Dict]]:
        def get_severity_key(item):
            svc_data = item[1]
            severity = self._get_severity_for_service(svc_data)
            return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 999
        return sorted(items, key=get_severity_key)

    def _get_severity_for_service(self, svc_data: Dict) -> str:
        cves = svc_data.get("cves", [])
        if not cves:
            return "INFO"
        max_score = max(c.cvss_score for c in cves)
        if max_score >= 9.0:
            return "CRITICAL"
        elif max_score >= 7.0:
            return "HIGH"
        elif max_score >= 4.0:
            return "MEDIUM"
        elif max_score > 0:
            return "LOW"
        return "INFO"

    def _get_risk_summary(self, vulnerabilities: Dict[str, Dict]) -> Dict[str, int]:
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for ip, services in vulnerabilities.items():
            for svc_key, svc_data in services.items():
                severity = self._get_severity_for_service(svc_data)
                summary[severity] = summary.get(severity, 0) + 1
        return summary

    def print_terminal_report(self, result: ScanResult) -> None:
        if not RICH_AVAILABLE:
            self._print_simple_report(result)
            return

        console = self.console

        console.print(Panel.fit(
            Text("内网安全评估报告", style="bold blue"),
            border_style="blue"
        ))

        info_table = Table(title="扫描信息", show_header=True, header_style="bold magenta")
        info_table.add_column("项目", style="cyan")
        info_table.add_column("内容", style="white")
        info_table.add_row("目标网段", result.target)
        info_table.add_row("扫描时间", result.scan_time.strftime("%Y-%m-%d %H:%M:%S"))
        info_table.add_row("存活主机", str(len(result.alive_hosts)))
        total_services = sum(len(svcs) for svcs in result.vulnerabilities.values())
        info_table.add_row("开放服务", str(total_services))
        console.print(info_table)

        if result.alive_hosts:
            host_table = Table(title="存活主机", show_header=True, header_style="bold green")
            host_table.add_column("IP 地址", style="green")
            host_table.add_column("开放端口", style="yellow")
            host_table.add_column("服务数量", style="cyan")
            for ip in sorted(result.alive_hosts):
                ports = [str(p) for p in result.open_ports.get(ip, [])]
                svc_count = len(result.fingerprints.get(ip, []))
                host_table.add_row(ip, ", ".join(ports) if ports else "无", str(svc_count))
            console.print(host_table)

        risk_summary = self._get_risk_summary(result.vulnerabilities)
        risk_table = Table(title="风险统计", show_header=True, header_style="bold yellow")
        risk_table.add_column("风险等级", style="bold")
        risk_table.add_column("数量", justify="right")
        for severity in SEVERITY_ORDER:
            count = risk_summary.get(severity, 0)
            if count > 0:
                color = SEVERITY_COLORS.get(severity, "white")
                risk_table.add_row(
                    Text(severity, style=color),
                    Text(str(count), style=color)
                )
        console.print(risk_table)

        vuln_table = Table(title="漏洞详情", show_header=True, header_style="bold red")
        vuln_table.add_column("IP", style="cyan")
        vuln_table.add_column("端口", justify="right")
        vuln_table.add_column("服务", style="green")
        vuln_table.add_column("版本", style="yellow")
        vuln_table.add_column("风险等级", style="bold")
        vuln_table.add_column("CVE 数量", justify="right")

        all_services = []
        for ip, services in result.vulnerabilities.items():
            for svc_key, svc_data in services.items():
                all_services.append((ip, svc_key, svc_data))

        sorted_services = sorted(
            all_services,
            key=lambda x: SEVERITY_ORDER.index(self._get_severity_for_service(x[2]))
        )

        for ip, svc_key, svc_data in sorted_services:
            severity = self._get_severity_for_service(svc_data)
            color = SEVERITY_COLORS.get(severity, "white")
            cve_count = len(svc_data.get("cves", []))

            severity_text = Text(severity, style=f"bold {color}")
            if severity == "CRITICAL":
                severity_text.stylize("blink")

            vuln_table.add_row(
                ip,
                str(svc_data["port"]),
                svc_data["service"],
                svc_data["version"] or "未知",
                severity_text,
                str(cve_count)
            )
        console.print(vuln_table)

        for ip, svc_key, svc_data in sorted_services:
            cves = svc_data.get("cves", [])
            if cves:
                severity = self._get_severity_for_service(svc_data)
                color = SEVERITY_COLORS.get(severity, "white")
                console.print(Panel.fit(
                    f"[bold {color}]{ip}:{svc_data['port']} - {svc_data['service']} {svc_data['version']}[/bold {color}]",
                    border_style=color
                ))
                for cve in cves[:5]:
                    cve_table = Table(show_header=False, border_style=color)
                    cve_table.add_column(style="bold cyan", width=15)
                    cve_table.add_column(style="white")
                    cve_table.add_row("CVE ID", f"[bold]{cve.cve_id}[/bold]")
                    cve_table.add_row("CVSS", f"[bold]{cve.cvss_score}[/bold] ({cve.cvss_severity})")
                    cve_table.add_row("影响版本", f"{cve.version_start} - {cve.version_end}")
                    cve_table.add_row("描述", cve.description)
                    console.print(cve_table)

    def _print_simple_report(self, result: ScanResult) -> None:
        print("=" * 60)
        print("内网安全评估报告")
        print("=" * 60)
        print(f"目标网段: {result.target}")
        print(f"扫描时间: {result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"存活主机: {len(result.alive_hosts)}")
        print(f"存活主机列表: {', '.join(sorted(result.alive_hosts))}")
        print("-" * 60)

        for ip in sorted(result.alive_hosts):
            print(f"\n[+] {ip}")
            services = result.vulnerabilities.get(ip, {})
            for svc_key, svc_data in sorted(services.items()):
                severity = self._get_severity_for_service(svc_data)
                cves = svc_data.get("cves", [])
                print(f"    Port {svc_data['port']}: {svc_data['service']} {svc_data['version']} "
                      f"- {severity} - {len(cves)} CVEs")
                for cve in cves[:3]:
                    print(f"        - {cve.cve_id} (CVSS: {cve.cvss_score})")

    def generate_html_report(self, result: ScanResult, output_path: str) -> bool:
        if not JINJA2_AVAILABLE:
            print("错误: jinja2 未安装，无法生成 HTML 报告")
            return False

        try:
            template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
            env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(["html", "xml"])
            )
            template = env.get_template("report.html")

            all_services = []
            for ip, services in result.vulnerabilities.items():
                for svc_key, svc_data in services.items():
                    severity = self._get_severity_for_service(svc_data)
                    all_services.append({
                        "ip": ip,
                        "port": svc_data["port"],
                        "service": svc_data["service"],
                        "version": svc_data["version"],
                        "severity": severity,
                        "severity_lower": severity.lower(),
                        "cves": svc_data.get("cves", []),
                        "cve_count": len(svc_data.get("cves", []))
                    })

            all_services.sort(
                key=lambda x: SEVERITY_ORDER.index(x["severity"]) if x["severity"] in SEVERITY_ORDER else 999
            )

            risk_summary = self._get_risk_summary(result.vulnerabilities)

            html_content = template.render(
                target=result.target,
                scan_time=result.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                alive_hosts=sorted(result.alive_hosts),
                alive_count=len(result.alive_hosts),
                open_ports=result.open_ports,
                services=all_services,
                risk_summary=risk_summary,
                SEVERITY_COLORS=SEVERITY_COLORS,
                SEVERITY_ORDER=SEVERITY_ORDER
            )

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            return True
        except Exception as e:
            print(f"生成 HTML 报告失败: {e}")
            return False
