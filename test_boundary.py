#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试版本边界匹配逻辑
"""
from vulndb import VulnDB

# 创建一个临时数据库进行测试
db = VulnDB(db_path=":memory:", load_sample=False)

print("""
╔══════════════════════════════════════════════════════════════╗
║                版本边界匹配测试                                 ║
╚══════════════════════════════════════════════════════════════╝
""")

# 插入测试数据，包含各种边界组合
test_data = [
    # (cve_id, service, start, end, start_inc, end_inc, cvss, severity, desc
    ("CVE-TEST-001", "nginx", "1.20", "1.21", 0, 1, 7.5, "HIGH", "Excluding start, Including end: (1.20, 1.21]"),
    ("CVE-TEST-002", "nginx", "1.20", "1.21", 0, 0, 7.5, "HIGH", "Excluding both: (1.20, 1.21)"),
    ("CVE-TEST-003", "nginx", "1.20", "1.21", 1, 1, 7.5, "HIGH", "Including both: [1.20, 1.21]"),
    ("CVE-TEST-004", "nginx", "1.20", "1.21", 1, 0, 7.5, "HIGH", "Including start, Excluding end: [1.20, 1.21)"),
]

db.conn.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        service_name TEXT,
        version_start TEXT,
        version_end TEXT,
        cvss_score REAL,
        cvss_severity TEXT,
        description TEXT,
        start_inclusive INTEGER DEFAULT 1,
        end_inclusive INTEGER DEFAULT 1
    )
""")

for cve_id, service, start, end, start_inc, end_inc, cvss, severity, desc in test_data:
    db.conn.execute("""
        INSERT INTO cves (cve_id, service_name, version_start, version_end, 
                         cvss_score, cvss_severity, description, start_inclusive, end_inclusive)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (cve_id, service, start, end, cvss, severity, desc, start_inc, end_inc))

db.conn.commit()

test_versions = ["1.19", "1.20", "1.20.1", "1.20.5", "1.21", "1.21.1"]

print("测试版本边界匹配:")
print("-" * 100)

for version in test_versions:
    print(f"\n测试版本: [bold]{version}[/bold]")
    cves = db.query("nginx", version, limit=10)
    
    expected = {
        "1.19": [],
        "1.20": ["CVE-TEST-003", "CVE-TEST-004"],  # 只应该命中包含start的
        "1.20.1": ["CVE-TEST-001", "CVE-TEST-002", "CVE-TEST-003", "CVE-TEST-004"],
        "1.20.5": ["CVE-TEST-001", "CVE-TEST-002", "CVE-TEST-003", "CVE-TEST-004"],
        "1.21": ["CVE-TEST-001", "CVE-TEST-003"],  # 只应该命中包含end的
        "1.21.1": [],
    }
    
    expected_list = expected.get(version, [])
    actual_list = [c.cve_id for c in cves]
    
    print(f"  预期命中: {expected_list}")
    print(f"  实际命中: {actual_list}")
    
    all_match = sorted(expected_list) == sorted(actual_list)
    status = "✅" if all_match else "❌"
    print(f"  结果: {status}")
    
    for cve in cves:
        print(f"    - {cve.cve_id}: {cve.description}")
        print(f"      命中依据: {cve.match_reason}")
        print(f"      边界: start_inc={cve.start_inclusive}, end_inc={cve.end_inclusive}")

print("\n" + "=" * 100)

# 直接测试 _version_in_range 方法
print("\n直接测试 _version_in_range 方法:")
print("-" * 100)

test_cases = [
    # (version, start, end, start_inc, end_inc, expected),
    ("1.20", "1.20", "1.21", False, True, False, "1.20 > 1.20 (start_excluding)"),
    ("1.20.1", "1.20", "1.21", False, True, True, "1.20.1 在 (1.20, 1.21]"),
    ("1.21", "1.20", "1.21", False, True, True, "1.21 <= 1.21 (end_including)"),
    ("1.21", "1.20", "1.21", False, False, False, "1.21 < 1.21 (end_excluding)"),
    ("1.20", "1.20", "1.21", True, True, True, "1.20 >= 1.20 (start_including)"),
    ("1.21", "1.20", "1.21", True, True, True, "1.21 <= 1.21 (end_including)"),
    ("1.20", "1.20", "1.21", True, False, True, "1.20 in [1.20, 1.21)"),
    ("1.21", "1.20", "1.21", True, False, False, "1.21 in [1.20, 1.21) - no"),
    ("1.20.5", "1.20", "1.21", False, False, True, "1.20.5 in (1.20, 1.21)"),
]

all_passed = True
for version, start, end, start_inc, end_inc, expected, desc in test_cases:
    result = db._version_in_range(version, start, end, start_inc, end_inc)
    status = "✅" if result == expected else "❌"
    if result != expected:
        all_passed = False
    print(f"  {status} {desc}")
    print(f"     版本={version}, 范围=({start}, {end}), 包含=({start_inc}, {end_inc})")
    print(f"     预期={expected}, 实际={result}")

if all_passed:
    print("\n✅ 所有边界测试通过！")
else:
    print("\n❌ 部分边界测试失败！")

db.close()
