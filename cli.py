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
def scan(target: str, top_ports: int, rate: int, output: str, timeout: int, max_workers: int, db_path: str):
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
def query(service: str, version: str, db_path: str, limit: int):
    """查询指定服务版本的 CVE 漏洞"""
    print_banner()
    print_status(f"查询 {service} {version} 的 CVE 漏洞...", "info")
    
    try:
        vuln_db = VulnDB(db_path=db_path)
        cves = vuln_db.query(service, version, limit=limit)
        vuln_db.close()
        
        if not cves:
            print_status("未发现相关 CVE 漏洞", "success")
            return
        
        print_status(f"发现 {len(cves)} 个相关 CVE:", "warning")
        for cve in cves:
            if RICH_AVAILABLE:
                console.print(f"  [bold]{cve.cve_id}[/bold] "
                             f"[cyan](CVSS: {cve.cvss_score} - {cve.cvss_severity})[/cyan]")
                console.print(f"    {cve.description}")
            else:
                print(f"  {cve.cve_id} (CVSS: {cve.cvss_score} - {cve.cvss_severity})")
                print(f"    {cve.description}")
    except Exception as e:
        print_status(f"查询失败: {e}", "error")
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
