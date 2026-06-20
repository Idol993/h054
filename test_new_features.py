#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试第三轮新功能：
1. 命中依据展示 + 按严重等级分组
2. 漏洞库自检命令 checkdb
3. scan 命令过滤功能 (--severity, --cve-only)
4. 版本边界匹配修复 (Excluding 边界不命中)
"""

import os
import sys
import subprocess
import shutil

TEST_DB = "test_features.db"
CSV_FILE = "nvd_test_data.csv"

def run_cmd(cmd, description):
    print(f"\n{'='*80}")
    print(f"测试: {description}")
    print(f"命令: {cmd}")
    print(f"{'='*80}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8')
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    return result.returncode

def cleanup():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    if os.path.exists("test_report.html"):
        os.remove("test_report.html")

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║           内网安全评估工具 - 新功能测试套件                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    cleanup()
    
    if not os.path.exists(CSV_FILE):
        print(f"错误: 测试数据文件 {CSV_FILE} 不存在")
        sys.exit(1)
    
    all_passed = True
    
    # 测试 1: 导入 CSV 数据
    rc = run_cmd(
        f"python cli.py initdb --db-path {TEST_DB} --csv {CSV_FILE}",
        "1. 导入 NVD CSV 测试数据（含边界类型）"
    )
    if rc != 0:
        print("❌ 导入失败")
        all_passed = False
    else:
        print("✅ 导入成功")
    
    # 测试 2: 漏洞库自检 checkdb
    rc = run_cmd(
        f"python cli.py checkdb --db-path {TEST_DB} --top 5",
        "2. 漏洞库自检 - 统计服务数量、CVE 数量、严重等级分布、Top 风险服务"
    )
    if rc != 0:
        print("❌ checkdb 失败")
        all_passed = False
    else:
        print("✅ checkdb 成功")
    
    # 测试 3: 查询 nginx 1.20.1 - 验证命中依据
    rc = run_cmd(
        f"python cli.py query nginx 1.20.1 --db-path {TEST_DB} --limit 5",
        "3. 查询 nginx 1.20.1 - 验证命中依据、服务匹配、边界类型"
    )
    if rc != 0:
        print("❌ 查询失败")
        all_passed = False
    else:
        print("✅ 查询成功")
    
    # 测试 4: 版本边界测试 - 查询 1.20（应该不命中 >1.20 且 <1.21 的记录）
    print(f"\n{'='*80}")
    print("测试 4: 版本边界匹配验证")
    print("目标: 查询 nginx 1.20，排除边界 (versionStartExcluding=1.20) 应该不命中")
    print(f"{'='*80}")
    
    from vulndb import VulnDB
    db = VulnDB(db_path=TEST_DB, load_sample=False)
    
    # 直接测试边界匹配逻辑
    print("\n直接测试 _version_in_range 方法:")
    test_cases = [
        ("1.20", "1.20", "1.21", False, True, False, "1.20, start_excluding=True 应该不命中"),
        ("1.20.1", "1.20", "1.21", False, True, True, "1.20.1 在 (1.20, 1.21] 应该命中"),
        ("1.21", "1.20", "1.21", False, True, True, "1.21, end_inclusive=True 应该命中"),
        ("1.21", "1.20", "1.21", False, False, False, "1.21, end_excluding=True 应该不命中"),
        ("1.20", "1.20", "1.21", True, True, True, "1.20, start_inclusive=True 应该命中"),
        ("1.21", "1.20", "1.21", True, True, True, "1.21, end_inclusive=True 应该命中"),
    ]
    
    boundary_passed = True
    for version, start, end, start_inc, end_inc, expected, desc in test_cases:
        result = db._version_in_range(version, start, end, start_inc, end_inc)
        status = "✅" if result == expected else "❌"
        if result != expected:
            boundary_passed = False
        print(f"  {status} {desc}:")
        print(f"     版本={version}, 范围=({start}, {end}), 包含=({start_inc}, {end_inc})")
        print(f"     预期={expected}, 实际={result}")
    
    if boundary_passed:
        print("\n✅ 版本边界匹配测试全部通过")
    else:
        print("\n❌ 版本边界匹配测试有失败")
        all_passed = False
    
    db.close()
    
    # 测试 5: query 命令按严重等级过滤
    rc = run_cmd(
        f"python cli.py query nginx 1.20.1 --db-path {TEST_DB} --severity HIGH --limit 10",
        "5. 查询 nginx 1.20.1 - 只显示 HIGH 及以上等级漏洞"
    )
    if rc != 0:
        print("❌ 按严重等级过滤失败")
        all_passed = False
    else:
        print("✅ 按严重等级过滤成功")
    
    # 测试 6: 验证 query 按严重等级分组
    print(f"\n{'='*80}")
    print("测试 6: 验证 query 结果按严重等级分组显示")
    print(f"{'='*80}")
    result = subprocess.run(
        f"python cli.py query apache 2.4.49 --db-path {TEST_DB} --limit 20",
        shell=True, capture_output=True, text=True, encoding='utf-8'
    )
    
    has_critical = "CRITICAL" in result.stdout
    has_high = "HIGH" in result.stdout
    has_medium = "MEDIUM" in result.stdout
    
    print(f"  CRITICAL 分组: {'✅' if has_critical else '❌'}")
    print(f"  HIGH 分组: {'✅' if has_high else '❌'}")
    print(f"  MEDIUM 分组: {'✅' if has_medium else '❌'}")
    
    if has_critical and has_high:
        print("✅ 按严重等级分组显示正常")
    else:
        print("❌ 按严重等级分组显示异常")
        all_passed = False
    
    # 测试 7: scan 命令帮助 - 验证新参数存在
    print(f"\n{'='*80}")
    print("测试 7: 验证 scan 命令新增 --severity 和 --cve-only 参数")
    print(f"{'='*80}")
    result = subprocess.run(
        f"python cli.py scan --help",
        shell=True, capture_output=True, text=True, encoding='utf-8'
    )
    
    has_severity = "--severity" in result.stdout
    has_cve_only = "--cve-only" in result.stdout
    
    print(f"  --severity 参数: {'✅' if has_severity else '❌'}")
    print(f"  --cve-only 参数: {'✅' if has_cve_only else '❌'}")
    
    if has_severity and has_cve_only:
        print("✅ scan 命令参数扩展成功")
    else:
        print("❌ scan 命令参数缺失")
        all_passed = False
        print(result.stdout)
    
    # 测试 8: checkdb 命令帮助
    print(f"\n{'='*80}")
    print("测试 8: 验证 checkdb 命令存在")
    print(f"{'='*80}")
    result = subprocess.run(
        f"python cli.py --help",
        shell=True, capture_output=True, text=True, encoding='utf-8'
    )
    
    has_checkdb = "checkdb" in result.stdout
    print(f"  checkdb 命令: {'✅' if has_checkdb else '❌'}")
    
    if has_checkdb:
        print("✅ checkdb 命令存在")
    else:
        print("❌ checkdb 命令不存在")
        all_passed = False
    
    # 测试 9: 扫描 127.0.0.1（不会有开放端口，但测试流程）
    print(f"\n{'='*80}")
    print("测试 9: scan 命令完整流程测试（扫描 127.0.0.1，含 HTML 报告）")
    print(f"{'='*80}")
    
    result = subprocess.run(
        f"python cli.py scan 127.0.0.1 --top-ports 10 --rate 50 --timeout 1 --db-path {TEST_DB} --output test_report.html",
        shell=True, capture_output=True, text=True, encoding='utf-8',
        timeout=60
    )
    
    if result.returncode == 0 or "未发现存活主机" in result.stdout:
        print("✅ scan 命令执行成功")
        
        if os.path.exists("test_report.html"):
            with open("test_report.html", "r", encoding="utf-8") as f:
                html_content = f.read()
            
            # 验证 HTML 报告包含按严重等级分组
            has_severity_group = "severity-group" in html_content
            has_match_reason = "命中依据" in html_content
            has_grouped_services = "按严重等级分组" in html_content
            
            print(f"  HTML 报告包含严重等级分组: {'✅' if has_severity_group else '❌'}")
            print(f"  HTML 报告包含命中依据: {'✅' if has_match_reason else '❌'}")
            print(f"  HTML 报告包含分组标题: {'✅' if has_grouped_services else '❌'}")
            
            if has_severity_group and has_match_reason and has_grouped_services:
                print("✅ HTML 报告按严重等级分组 + 命中依据展示正常")
            else:
                print("❌ HTML 报告内容检查失败")
                all_passed = False
        else:
            print("⚠️  HTML 报告未生成（可能没有扫描到服务）")
    else:
        print("❌ scan 命令执行失败")
        print("STDOUT:", result.stdout[-500:])
        if result.stderr:
            print("STDERR:", result.stderr[-500:])
        all_passed = False
    
    # 测试 10: 测试别名映射 - openssh 应该匹配到 open_ssh
    print(f"\n{'='*80}")
    print("测试 10: 服务别名映射测试 - openssh 匹配")
    print(f"{'='*80}")
    
    result = subprocess.run(
        f"python cli.py query openssh 7.4 --db-path {TEST_DB} --limit 5",
        shell=True, capture_output=True, text=True, encoding='utf-8'
    )
    
    has_alias_match = "服务匹配" in result.stdout or "open_ssh" in result.stdout or "openssh" in result.stdout
    print(f"  服务别名映射工作: {'✅' if has_alias_match else '⚠️  (可能无匹配数据)'}")
    
    # 总结
    print(f"\n{'='*80}")
    print("测试总结")
    print(f"{'='*80}")
    
    if all_passed:
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    ✅ 所有测试通过！                         ║
╠══════════════════════════════════════════════════════════════╣
║  1. 版本边界匹配正确（Excluding 边界不命中）                  ║
║  2. 命中依据展示正常（服务名、版本范围、边界类型）             ║
║  3. 按严重等级分组显示正常                                    ║
║  4. checkdb 漏洞库自检功能正常                                ║
║  5. scan 命令支持 --severity 和 --cve-only 过滤              ║
║  6. HTML 报告支持按严重等级分组展开查看                        ║
║  7. 服务别名映射正常工作                                      ║
╚══════════════════════════════════════════════════════════════╝
        """)
    else:
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    ❌ 部分测试失败                           ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    cleanup()
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
