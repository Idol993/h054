#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
内网安全评估命令行工具
扫描指定 IP 段，发现在线主机、开放端口、服务版本，并与 CVE 漏洞库联动做风险评级
"""

import sys
import os
from datetime import datetime
from typing import List, Dict, Set, Optional

import click

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from utils.iprange import parse_target
from utils.rate_limiter import RateLimiter
from discovery import HostDiscovery
from scanner import PortScanner, get_top_ports
from fingerprinter import ServiceFingerprinter
from vulndb import VulnDB
from reporter import Reporter, ScanResult


if RICH_AVAILABLE:
    console = Console()
else:
    console = None


def print_banner() -> None:
    if RICH_AVAILABLE:
        banner = Panel.fit(
            Text("🔒 内网安全评估工具", style="bold blue", justify="center"),
            subtitle="Internal Network Security Assessment Tool",
            border_style="blue"
        )
        console.print(banner)
    else:
        print("=" * 60)
        print("内网安全评估工具")
        print("Internal Network Security Assessment Tool")
        print("=" * 60)


def print_status(message: str, style: str = "info") -> None:
    if RICH_AVAILABLE:
        styles = {
            "info": "blue",
            "success": "green",
            "warning": "yellow",
            "error": "red",
            "critical": "bold red"
        }
        console.print(f"[{styles.get(style, 'white')}][*] {message}[/{styles.get(style, 'white')}]")
    else:
        print(f"[*] {message}")


@click.group()
def cli():
    """内网安全评估命令行工具"""
    pass


@cli.command()
@click.argument('target')
@click.option('--top-ports', default=1000, help='扫描前 N 个常用端口 (默认: 1000)')
@click.option('--rate', default=100, help='每秒最大发包数 (默认: 100)')
@click.option('--output', '-o', default=None, help='HTML 报告输出路径')
@click.option('--timeout', default=2, help='连接超时时间(秒) (默认: 2)')
@click.option('--max-workers', default=50, help='最大并发线程数 (默认: 50)')
@click.option('--db-path', default='cve.db', help='CVE 数据库路径 (默认: cve.db)')
@click.option('--severity', 'min_severity', default=None, 
              type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], case_sensitive=False),
              help='只显示指定严重等级及以上的漏洞 (终端输出)')
@click.option('--cve-only', is_flag=True, default=False, 
              help='只显示有 CVE 漏洞的服务 (终端输出)')
def scan(target: str, top_ports: int, rate: int, output: str, timeout: int, max_workers: int, 
         db_path: str, min_severity: Optional[str], cve_only: bool):
    """扫描指定目标网段 (支持 CIDR 格式)"""
    print_banner()
    print_status(f"开始扫描目标: {target}", "info")
    print_status(f"配置: 前 {top_ports} 端口 | 速率 {rate} 包/秒 | 超时 {timeout}s | {max_workers} 线程", "info")

    start_time = datetime.now()

    try:
        print_status("解析目标网段...", "info")
        ip_list = parse_target(target)
        print_status(f"共解析出 {len(ip_list)} 个 IP 地址", "success")
    except ValueError as e:
        print_status(f"目标解析失败: {e}", "error")
        sys.exit(1)

    rate_limiter = RateLimiter(rate)

    print_status("\n[1/4] 正在进行主机发现...", "info")
    alive_hosts = set()

    try:
        discovery = HostDiscovery(rate_limiter=rate_limiter, timeout=timeout, max_workers=max_workers)
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("ICMP Ping 扫描中...", total=len(ip_list))
                for i, ip in enumerate(ip_list):
                    progress.update(task, advance=1, description=f"正在检测 {ip}...")
                alive_hosts = discovery.discover(ip_list)
        else:
            alive_hosts = discovery.discover(ip_list)

        print_status(f"发现 {len(alive_hosts)} 台存活主机", "success")
        for host in sorted(alive_hosts):
            print_status(f"  - {host}", "success")
    except Exception as e:
        print_status(f"主机发现出错: {e}", "error")
        sys.exit(1)

    if not alive_hosts:
        print_status("未发现存活主机，扫描结束", "warning")
        sys.exit(0)

    print_status("\n[2/4] 正在进行端口扫描...", "info")
    ports_to_scan = get_top_ports(top_ports)
    print_status(f"将扫描 {len(ports_to_scan)} 个端口", "info")

    open_ports: Dict[str, List[int]] = {}
    try:
        scanner = PortScanner(rate_limiter=rate_limiter, timeout=timeout, max_workers=max_workers)
        
        if RICH_AVAILABLE:
            total_tasks = len(alive_hosts) * len(ports_to_scan)
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("TCP 端口扫描中...", total=total_tasks)
                open_ports = scanner.scan(alive_hosts, ports_to_scan)
                progress.update(task, completed=total_tasks)
        else:
            open_ports = scanner.scan(alive_hosts, ports_to_scan)

        total_open = sum(len(ports) for ports in open_ports.values())
        print_status(f"发现 {total_open} 个开放端口", "success")
        for host in sorted(alive_hosts):
            ports = open_ports.get(host, [])
            if ports:
                print_status(f"  - {host}: {', '.join(map(str, sorted(ports)))}", "success")
    except Exception as e:
        print_status(f"端口扫描出错: {e}", "error")
        sys.exit(1)

    scan_targets = {ip: ports for ip, ports in open_ports.items() if ports}
    if not scan_targets:
        print_status("未发现开放端口，扫描结束", "warning")
        sys.exit(0)

    print_status("\n[3/4] 正在进行服务指纹识别...", "info")
    fingerprints: Dict[str, List[Dict]] = {}
    try:
        fingerprinter = ServiceFingerprinter(timeout=timeout, max_workers=max_workers)
        
        if RICH_AVAILABLE:
            total_services = sum(len(ports) for ports in scan_targets.values())
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("服务识别中...", total=total_services)
                fingerprints = fingerprinter.fingerprint(scan_targets)
                progress.update(task, completed=total_services)
        else:
            fingerprints = fingerprinter.fingerprint(scan_targets)

        print_status("服务指纹识别完成", "success")
        for host in sorted(fingerprints.keys()):
            services = fingerprints[host]
            for svc in services:
                version_str = f" v{svc['version']}" if svc['version'] else ""
                print_status(f"  - {host}:{svc['port']} - {svc['service']}{version_str}", "info")
    except Exception as e:
        print_status(f"服务识别出错: {e}", "error")
        sys.exit(1)

    print_status("\n[4/4] 正在查询 CVE 漏洞数据库...", "info")
    vulnerabilities: Dict[str, Dict] = {}
    vuln_db = None
    try:
        vuln_db = VulnDB(db_path=db_path)
        vulnerabilities = vuln_db.query_all(fingerprints)
        print_status("CVE 漏洞查询完成", "success")
        
        total_cves = sum(
            len(svc_data.get("cves", []))
            for services in vulnerabilities.values()
            for svc_data in services.values()
        )
        print_status(f"共发现 {total_cves} 个相关 CVE 漏洞", "warning")
    except Exception as e:
        print_status(f"CVE 查询出错: {e}", "error")
    finally:
        if vuln_db:
            vuln_db.close()

    scan_result = ScanResult(
        target=target,
        scan_time=start_time,
        alive_hosts=alive_hosts,
        open_ports=open_ports,
        fingerprints=fingerprints,
        vulnerabilities=vulnerabilities
    )

    print_status("\n" + "=" * 60, "info")
    print_status("扫描完成，生成报告...", "success")
    print_status("=" * 60 + "\n", "info")

    reporter = Reporter()
    
    if min_severity or cve_only:
        from copy import deepcopy
        terminal_vulns = deepcopy(vulnerabilities)
        SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if min_severity:
            min_idx = SEVERITY_ORDER.index(min_severity.upper())
            for ip in list(terminal_vulns.keys()):
                for svc_key in list(terminal_vulns[ip].keys()):
                    svc_data = terminal_vulns[ip][svc_key]
                    filtered_cves = []
                    for cve in svc_data.get("cves", []):
                        cve_idx = SEVERITY_ORDER.index(cve.cvss_severity)
                        if cve_idx <= min_idx:
                            filtered_cves.append(cve)
                    svc_data["cves"] = filtered_cves
        
        if cve_only:
            for ip in list(terminal_vulns.keys()):
                for svc_key in list(terminal_vulns[ip].keys()):
                    if not terminal_vulns[ip][svc_key].get("cves", []):
                        del terminal_vulns[ip][svc_key]
                if not terminal_vulns[ip]:
                    del terminal_vulns[ip]
        
        terminal_result = ScanResult(
            target=target,
            scan_time=start_time,
            alive_hosts=alive_hosts,
            open_ports=open_ports,
            fingerprints=fingerprints,
            vulnerabilities=terminal_vulns
        )
        
        filter_info = []
        if min_severity:
            filter_info.append(f"严重等级 >= {min_severity.upper()}")
        if cve_only:
            filter_info.append("仅显示有 CVE 的服务")
        if filter_info:
            print_status(f"终端报告过滤条件: {', '.join(filter_info)}", "info")
            print_status("HTML 报告将包含完整结果\n", "info")
        
        reporter.print_terminal_report(terminal_result)
    else:
        reporter.print_terminal_report(scan_result)

    if output:
        print_status(f"\n正在生成 HTML 报告: {output}", "info")
        if reporter.generate_html_report(scan_result, output):
            print_status(f"HTML 报告已生成: {output}", "success")
        else:
            print_status("HTML 报告生成失败", "error")

    elapsed = datetime.now() - start_time
    print_status(f"\n扫描总耗时: {elapsed}", "info")

    critical_count = sum(
        1 for services in vulnerabilities.values()
        for svc_data in services.values()
        if reporter._get_severity_for_service(svc_data) == "CRITICAL"
    )
    if critical_count > 0:
        print_status(f"⚠️  发现 {critical_count} 个严重漏洞，建议立即处理！", "critical")


@cli.command()
@click.option('--db-path', default='cve.db', help='CVE 数据库路径')
@click.option('--csv', 'csv_path', default=None, help='NVD CSV 文件路径，用于导入 CVE 数据')
def initdb(db_path: str, csv_path: Optional[str]):
    """初始化 CVE 数据库"""
    print_banner()
    print_status(f"初始化 CVE 数据库: {db_path}", "info")
    if csv_path:
        print_status(f"将从 CSV 文件导入: {csv_path}", "info")
    
    try:
        if os.path.exists(db_path):
            if not click.confirm(f"数据库已存在，是否覆盖?", default=False):
                print_status("已取消", "warning")
                return
            os.remove(db_path)
        
        if csv_path:
            if not os.path.exists(csv_path):
                print_status(f"CSV 文件不存在: {csv_path}", "error")
                sys.exit(1)
            
            vuln_db = VulnDB(db_path=db_path, load_sample=False)
            try:
                imported, skipped = vuln_db.import_csv(csv_path)
                print_status(f"CSV 导入完成", "success")
                print_status(f"  成功导入: {imported} 条", "success")
                print_status(f"  跳过: {skipped} 条", "warning")
            finally:
                vuln_db.close()
        else:
            vuln_db = VulnDB(db_path=db_path)
            vuln_db.close()
            print_status("CVE 数据库初始化完成", "success")
            print_status("数据库包含常见服务的示例 CVE 数据", "info")
        
    except Exception as e:
        print_status(f"数据库初始化失败: {e}", "error")
        sys.exit(1)


@cli.command()
@click.argument('service')
@click.argument('version')
@click.option('--db-path', default='cve.db', help='CVE 数据库路径')
@click.option('--limit', default=20, help='返回结果数量')
@click.option('--severity', 'min_severity', default=None, 
              type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], case_sensitive=False),
              help='只显示指定严重等级及以上的漏洞')
def query(service: str, version: str, db_path: str, limit: int, min_severity: Optional[str]):
    """查询指定服务版本的 CVE 漏洞"""
    print_banner()
    filter_info = f" (严重等级 >= {min_severity.upper()})" if min_severity else ""
    print_status(f"查询 {service} {version} 的 CVE 漏洞{filter_info}...", "info")
    
    try:
        vuln_db = VulnDB(db_path=db_path)
        cves = vuln_db.query(service, version, limit=limit, min_severity=min_severity)
        vuln_db.close()
        
        if not cves:
            print_status("未发现相关 CVE 漏洞", "success")
            return
        
        severity_groups = {}
        for cve in cves:
            sev = cve.cvss_severity
            if sev not in severity_groups:
                severity_groups[sev] = []
            severity_groups[sev].append(cve)
        
        SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in SEVERITY_ORDER:
            if sev not in severity_groups:
                continue
            sev_cves = severity_groups[sev]
            if RICH_AVAILABLE:
                color_map = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "blue"}
                console.print(f"\n  [{color_map.get(sev, 'white')}]▌ {sev} - {len(sev_cves)} 个 CVE[/{color_map.get(sev, 'white')}]")
            else:
                print(f"\n  ▌ {sev} - {len(sev_cves)} 个 CVE")
            
            for cve in sev_cves:
                if RICH_AVAILABLE:
                    console.print(f"    [bold]{cve.cve_id}[/bold] "
                                 f"[cyan](CVSS: {cve.cvss_score})[/cyan]")
                    if cve.match_reason:
                        console.print(f"      [dim]🎯 命中依据: {cve.match_reason}[/dim]")
                    if cve.matched_service and cve.matched_service != cve.service_name:
                        console.print(f"      [dim]🔗 服务匹配: {cve.matched_service} → {cve.service_name}[/dim]")
                    console.print(f"      [dim]版本范围: {cve.version_start} ({'包含' if cve.start_inclusive else '排除'}) "
                                 f"→ {cve.version_end} ({'包含' if cve.end_inclusive else '排除'})[/dim]")
                    console.print(f"      {cve.description}")
                else:
                    print(f"    {cve.cve_id} (CVSS: {cve.cvss_score} - {cve.cvss_severity})")
                    if cve.match_reason:
                        print(f"      命中依据: {cve.match_reason}")
                    if cve.matched_service and cve.matched_service != cve.service_name:
                        print(f"      服务匹配: {cve.matched_service} → {cve.service_name}")
                    print(f"      版本范围: {cve.version_start} ({'包含' if cve.start_inclusive else '排除'}) "
                          f"→ {cve.version_end} ({'包含' if cve.end_inclusive else '排除'})")
                    print(f"      {cve.description}")
    except Exception as e:
        print_status(f"查询失败: {e}", "error")
        sys.exit(1)


@cli.command()
@click.option('--db-path', default='cve.db', help='CVE 数据库路径')
@click.option('--top', default=10, help='显示 Top N 风险服务 (默认: 10)')
def checkdb(db_path: str, top: int):
    """检查漏洞库质量统计"""
    print_banner()
    print_status(f"检查漏洞库质量: {db_path}", "info")
    
    if not os.path.exists(db_path):
        print_status(f"数据库不存在: {db_path}", "error")
        print_status("请先运行 initdb 命令初始化数据库", "warning")
        sys.exit(1)
    
    try:
        vuln_db = VulnDB(db_path=db_path, load_sample=False)
        stats = vuln_db.check_database()
        vuln_db.close()
        
        if RICH_AVAILABLE:
            from rich.table import Table
            from rich.panel import Panel
            from rich.text import Text
            
            console.print(Panel.fit(
                Text("📊 漏洞库质量检测报告", style="bold blue", justify="center"),
                border_style="blue"
            ))
            
            info_table = Table(show_header=False, box=None, padding=(0, 2))
            info_table.add_column("指标", style="bold cyan")
            info_table.add_column("数值", style="white")
            
            info_table.add_row("CVE 总数", str(stats['total_cves']))
            info_table.add_row("唯一服务数", str(stats['unique_services']))
            info_table.add_row("最高 CVSS 分数", f"{stats['max_cvss_score']:.1f}")
            
            console.print(info_table)
            console.print()
            
            sev_table = Table(title="严重等级分布", box=None, padding=(0, 2))
            sev_table.add_column("等级", style="bold")
            sev_table.add_column("数量", justify="right")
            sev_table.add_column("占比", justify="right")
            
            total = stats['total_cves']
            SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            color_map = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
            
            for sev in SEVERITY_ORDER:
                count = stats['severity_distribution'].get(sev, 0)
                percent = (count / total * 100) if total > 0 else 0
                sev_table.add_row(
                    f"[{color_map[sev]}]{sev}[/{color_map[sev]}]",
                    str(count),
                    f"{percent:.1f}%"
                )
            
            console.print(sev_table)
            console.print()
            
            if stats['missing_version_range'] > 0 or stats['missing_cvss'] > 0 or stats['missing_description'] > 0:
                warn_table = Table(title="⚠️  数据缺失警告", box=None, padding=(0, 2))
                warn_table.add_column("缺失项", style="bold yellow")
                warn_table.add_column("数量", justify="right", style="yellow")
                
                if stats['missing_version_range'] > 0:
                    warn_table.add_row("缺版本范围", str(stats['missing_version_range']))
                if stats['missing_cvss'] > 0:
                    warn_table.add_row("缺 CVSS 分数", str(stats['missing_cvss']))
                if stats['missing_description'] > 0:
                    warn_table.add_row("缺描述信息", str(stats['missing_description']))
                
                console.print(warn_table)
                console.print()
            
            top_table = Table(title=f"🔥 Top {top} 风险服务 (按 CVE 数量)", box=None, padding=(0, 2))
            top_table.add_column("#", justify="right", style="dim")
            top_table.add_column("服务名", style="bold cyan")
            top_table.add_column("CVE 数量", justify="right")
            top_table.add_column("最高 CVSS", justify="right")
            top_table.add_column("严重等级", style="bold")
            
            for i, svc in enumerate(stats['top_services'][:top], 1):
                sev = svc['max_severity']
                sev_color = color_map.get(sev, "white")
                top_table.add_row(
                    str(i),
                    svc['service_name'],
                    str(svc['cve_count']),
                    f"{svc['max_cvss']:.1f}",
                    f"[{sev_color}]{sev}[/{sev_color}]"
                )
            
            console.print(top_table)
            
            quality_score = 100
            if stats['missing_version_range'] > 0:
                quality_score -= min(30, stats['missing_version_range'] / total * 100 if total > 0 else 30)
            if stats['missing_cvss'] > 0:
                quality_score -= min(30, stats['missing_cvss'] / total * 100 if total > 0 else 30)
            if stats['missing_description'] > 0:
                quality_score -= min(10, stats['missing_description'] / total * 100 if total > 0 else 10)
            
            quality_score = max(0, quality_score)
            
            if quality_score >= 80:
                quality_color = "green"
                quality_text = "优秀"
            elif quality_score >= 60:
                quality_color = "yellow"
                quality_text = "良好"
            elif quality_score >= 40:
                quality_color = "orange"
                quality_text = "一般"
            else:
                quality_color = "red"
                quality_text = "较差"
            
            console.print()
            console.print(f"🎯 漏洞库质量评分: [{quality_color}]{quality_score:.0f}/100 ({quality_text})[/{quality_color}]")
            
            if stats['severity_distribution'].get('CRITICAL', 0) > 0 or stats['severity_distribution'].get('HIGH', 0) > 0:
                console.print(f"✅ 适合内网评估: 包含 CRITICAL/HIGH 风险数据")
            else:
                console.print(f"⚠️  注意: 漏洞库缺少高风险数据，可能不适合内网评估")
                
        else:
            print("\n" + "=" * 60)
            print("漏洞库质量检测报告")
            print("=" * 60)
            print(f"CVE 总数: {stats['total_cves']}")
            print(f"唯一服务数: {stats['unique_services']}")
            print(f"最高 CVSS 分数: {stats['max_cvss_score']:.1f}")
            
            print("\n严重等级分布:")
            total = stats['total_cves']
            SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            for sev in SEVERITY_ORDER:
                count = stats['severity_distribution'].get(sev, 0)
                percent = (count / total * 100) if total > 0 else 0
                print(f"  {sev}: {count} ({percent:.1f}%)")
            
            print(f"\nTop {top} 风险服务:")
            for i, svc in enumerate(stats['top_services'][:top], 1):
                print(f"  {i}. {svc['service_name']}: {svc['cve_count']} CVEs, 最高 CVSS {svc['max_cvss']:.1f} ({svc['max_severity']})")
            
            missing = []
            if stats['missing_version_range'] > 0:
                missing.append(f"缺版本范围: {stats['missing_version_range']}")
            if stats['missing_cvss'] > 0:
                missing.append(f"缺 CVSS: {stats['missing_cvss']}")
            if stats['missing_description'] > 0:
                missing.append(f"缺描述: {stats['missing_description']}")
            
            if missing:
                print("\n⚠️  数据缺失警告:")
                for m in missing:
                    print(f"  - {m}")
            
    except Exception as e:
        print_status(f"数据库检查失败: {e}", "error")
        sys.exit(1)


def main():
    try:
        cli()
    except KeyboardInterrupt:
        print_status("\n扫描被用户中断", "warning")
        sys.exit(130)
    except Exception as e:
        print_status(f"\n发生未处理的错误: {e}", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()
