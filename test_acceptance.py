#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验收测试脚本 - 直接导入模块测试（避免 Windows 控制台编码问题）

场景清单:
1. 旧库兼容 - 旧表结构（无边界字段）自动升级，查询不报错
2. 空库自检 - checkdb 空库正常输出 0 条，不崩溃
3. NONE/UNKNOWN 严重等级过滤 - query --severity HIGH 时不中断
4. 排除边界版本 - versionStartExcluding/versionEndExcluding 边界不命中
5. 大小写不一致严重等级 - high 能被正确识别为 HIGH
6. checkdb 严重等级分布包含 INFO/NONE/UNKNOWN
"""

import os
import sys
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vulndb import VulnDB, normalize_severity, severity_rank, get_cvss_severity
from reporter import Reporter, ScanResult
from datetime import datetime

DB_OLD = "test_old.db"
DB_NEW = "test_new.db"
DB_EMPTY = "test_empty.db"
CSV_FILE = "acceptance_test_data.csv"

passed_tests = 0
failed_tests = 0
all_results = []


def test(name, condition, detail=""):
    global passed_tests, failed_tests
    status = "✅ PASS" if condition else "❌ FAIL"
    if condition:
        passed_tests += 1
    else:
        failed_tests += 1
    all_results.append((name, condition, detail))
    print(f"  {status}  {name}")
    if detail and not condition:
        print(f"         → {detail}")


def create_old_format_db(db_path):
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE cves (
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
    sample = [
        ("CVE-OLD-001", "nginx", "1.0", "2.0", 7.5, "HIGH", "Old format nginx CVE"),
        ("CVE-OLD-002", "openssh", "7.0", "8.0", 9.8, "CRITICAL", "Old format openssh CVE"),
        ("CVE-OLD-003", "apache", "2.0", "2.5", 5.0, "MEDIUM", "Old format apache CVE"),
    ]
    conn.executemany(
        "INSERT INTO cves (cve_id, service_name, version_start, version_end, cvss_score, cvss_severity, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
        sample
    )
    conn.commit()
    conn.close()


def create_empty_db(db_path):
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE cves (
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
    conn.commit()
    conn.close()


def main():
    global passed_tests, failed_tests
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║             内网安全评估工具 - 验收测试套件                    ║
╠══════════════════════════════════════════════════════════════╣
║  覆盖: 旧库升级 / 空库自检 / NONE等级 / 排除边界 / 大小写       ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    for f in [DB_OLD, DB_NEW, DB_EMPTY]:
        if os.path.exists(f):
            os.remove(f)
    
    # ============================================================
    # 场景 1: 旧库兼容测试
    # ============================================================
    print("\n" + "="*60)
    print("🧪 场景 1: 旧库兼容 - 自动识别旧表结构并补齐边界字段")
    print("="*60)
    
    create_old_format_db(DB_OLD)
    conn = sqlite3.connect(DB_OLD)
    cols = [row[1] for row in conn.execute("PRAGMA table_info(cves)")]
    conn.close()
    has_old = "start_inclusive" not in cols and "end_inclusive" not in cols
    test("旧库创建后确实没有边界字段", has_old, f"列: {cols}")
    
    try:
        db = VulnDB(db_path=DB_OLD, load_sample=False)
        cves = db.query("nginx", "1.5", limit=10)
        db.close()
        
        test("旧库 query 不报错", True)
        test("查询返回正确数量", len(cves) == 1, f"返回 {len(cves)} 条，期望 1 条")
        if cves:
            test("返回正确的 CVE", cves[0].cve_id == "CVE-OLD-001", f"实际: {cves[0].cve_id}")
            test("边界字段默认值正确", cves[0].start_inclusive == True and cves[0].end_inclusive == True)
        
        conn = sqlite3.connect(DB_OLD)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(cves)")]
        conn.close()
        has_new = "start_inclusive" in cols and "end_inclusive" in cols
        test("表结构已自动升级", has_new, f"列: {cols}")
        
        # checkdb 也能跑
        db = VulnDB(db_path=DB_OLD, load_sample=False)
        stats = db.check_database()
        db.close()
        test("旧库 checkdb 正常执行", stats is not None)
        test("旧库 CVE 总数正确", stats["total_cves"] == 3, f"实际: {stats['total_cves']}")
        
    except Exception as e:
        test("旧库操作异常", False, str(e))
        import traceback
        traceback.print_exc()
    
    # ============================================================
    # 场景 2: 空库自检
    # ============================================================
    print("\n" + "="*60)
    print("🧪 场景 2: 空库自检 - checkdb 空库正常输出，不崩溃")
    print("="*60)
    
    create_empty_db(DB_EMPTY)
    
    try:
        db = VulnDB(db_path=DB_EMPTY, load_sample=False)
        stats = db.check_database()
        db.close()
        
        test("空库 checkdb 不崩溃", True)
        test("空库 CVE 总数为 0", stats["total_cves"] == 0, f"实际: {stats['total_cves']}")
        test("空库服务数为 0", stats["unique_services"] == 0, f"实际: {stats['unique_services']}")
        test("空库最高 CVSS 为 0.0", stats["max_cvss_score"] == 0.0, f"实际: {stats['max_cvss_score']}")
        test("空库 top_services 为空列表", isinstance(stats["top_services"], list) and len(stats["top_services"]) == 0)
        
        sev_dist = stats["severity_distribution"]
        test("空库各等级均为 0", all(v == 0 for v in sev_dist.values()), f"实际: {sev_dist}")
        
    except Exception as e:
        test("空库 checkdb 异常", False, str(e))
        import traceback
        traceback.print_exc()
    
    # ============================================================
    # 场景 3: NONE/UNKNOWN 严重等级过滤
    # ============================================================
    print("\n" + "="*60)
    print("🧪 场景 3: NONE/UNKNOWN 严重等级 - 过滤时不中断命令")
    print("="*60)
    
    try:
        db = VulnDB(db_path=DB_NEW, load_sample=False)
        imported, skipped = db.import_csv(CSV_FILE)
        db.close()
        test(f"CSV 导入成功 ({imported} 条)", imported > 0, f"导入 {imported} 条，跳过 {skipped} 条")
    except Exception as e:
        test("CSV 导入失败", False, str(e))
        import traceback
        traceback.print_exc()
        imported = 0
    
    if imported > 0:
        try:
            db = VulnDB(db_path=DB_NEW, load_sample=False)
            
            # 7.5 版本在 TEST-007 (7.0-8.0, NONE) 范围内
            # 6.0 版本在 TEST-008 (5.0-7.0, UNKNOWN) 范围内
            cves_75 = db.query("openssh", "7.5", limit=20)
            cves_60 = db.query("openssh", "6.0", limit=20)
            
            has_none = any(c.cvss_severity.upper() == "NONE" for c in cves_75)
            has_unknown = any(c.cvss_severity.upper() == "UNKNOWN" for c in cves_60)
            test("7.5 版本查到 NONE 等级 CVE", has_none, f"7.5 找到 {len(cves_75)} 条")
            test("6.0 版本查到 UNKNOWN 等级 CVE", has_unknown, f"6.0 找到 {len(cves_60)} 条")
            
            # 按 HIGH 过滤
            high_cves = db.query("openssh", "6.0", limit=20, min_severity="HIGH")
            no_none = all(severity_rank(c.cvss_severity) <= severity_rank("HIGH") for c in high_cves)
            test("HIGH 过滤不包含 NONE/UNKNOWN", no_none,
                 f"返回 {len(high_cves)} 条，等级: {[c.cvss_severity for c in high_cves]}")
            
            # 按 LOW 过滤
            low_cves = db.query("openssh", "6.0", limit=20, min_severity="LOW")
            test("LOW 过滤也不报错", True)
            
            db.close()
            
        except Exception as e:
            test("等级过滤异常", False, str(e))
            import traceback
            traceback.print_exc()
    
    # ============================================================
    # 场景 4: 排除边界版本测试
    # ============================================================
    print("\n" + "="*60)
    print("🧪 场景 4: 排除边界版本 - Excluding 边界不命中")
    print("="*60)
    
    if imported > 0:
        try:
            db = VulnDB(db_path=DB_NEW, load_sample=False)
            
            # 查询 1.20 (start_excluding 边界)
            cves_120 = db.query("nginx", "1.20", limit=20)
            cve_ids_120 = {c.cve_id for c in cves_120}
            
            # CVE-TEST-001: [1.20, 1.21] 包含两端 -> 应该命中
            # CVE-TEST-002: (1.20, 1.21] 排除开头 -> 不应该命中
            # CVE-TEST-003: (1.20, 1.21) 排除两端 -> 不应该命中
            # CVE-TEST-004: [1.20, 1.21) 排除结尾 -> 应该命中
            test("1.20 命中 TEST-001 (start_including)", "CVE-TEST-001" in cve_ids_120)
            test("1.20 未命中 TEST-002 (start_excluding)", "CVE-TEST-002" not in cve_ids_120)
            test("1.20 未命中 TEST-003 (both_excluding)", "CVE-TEST-003" not in cve_ids_120)
            test("1.20 命中 TEST-004 (start_incl+end_excl)", "CVE-TEST-004" in cve_ids_120)
            
            # 查询 1.21 (end_excluding 边界)
            cves_121 = db.query("nginx", "1.21", limit=20)
            cve_ids_121 = {c.cve_id for c in cves_121}
            
            # CVE-TEST-001: [1.20, 1.21] 包含两端 -> 应该命中
            # CVE-TEST-002: (1.20, 1.21] 排除开头 -> 应该命中
            # CVE-TEST-003: (1.20, 1.21) 排除两端 -> 不应该命中
            # CVE-TEST-004: [1.20, 1.21) 排除结尾 -> 不应该命中
            test("1.21 命中 TEST-001 (end_including)", "CVE-TEST-001" in cve_ids_121)
            test("1.21 命中 TEST-002 (end_including)", "CVE-TEST-002" in cve_ids_121)
            test("1.21 未命中 TEST-003 (end_excluding)", "CVE-TEST-003" not in cve_ids_121)
            test("1.21 未命中 TEST-004 (end_excluding)", "CVE-TEST-004" not in cve_ids_121)
            
            # 查询 1.20.5 (中间版本) 应该命中所有 4 条边界测试 CVE
            cves_mid = db.query("nginx", "1.20.5", limit=20)
            cve_ids_mid = {c.cve_id for c in cves_mid}
            test("1.20.5 命中 4 条边界测试 CVE", 
                 len(cve_ids_mid & {"CVE-TEST-001", "CVE-TEST-002", "CVE-TEST-003", "CVE-TEST-004"}) == 4,
                 f"实际命中边界相关: {cve_ids_mid & {'CVE-TEST-001', 'CVE-TEST-002', 'CVE-TEST-003', 'CVE-TEST-004'}}")
            
            db.close()
            
        except Exception as e:
            test("边界测试异常", False, str(e))
            import traceback
            traceback.print_exc()
    
    # ============================================================
    # 场景 5: 大小写不一致严重等级
    # ============================================================
    print("\n" + "="*60)
    print("🧪 场景 5: 大小写不一致 - high 能正确识别为 HIGH")
    print("="*60)
    
    if imported > 0:
        try:
            db = VulnDB(db_path=DB_NEW, load_sample=False)
            
            # normalize_severity 测试
            test("normalize_severity('high') -> HIGH", normalize_severity("high") == "HIGH")
            test("normalize_severity('HIGH') -> HIGH", normalize_severity("HIGH") == "HIGH")
            test("normalize_severity('none') -> NONE", normalize_severity("none") == "NONE")
            test("normalize_severity('unknown') -> UNKNOWN", normalize_severity("unknown") == "UNKNOWN")
            test("normalize_severity('') -> NONE", normalize_severity("") == "NONE")
            test("normalize_severity(None) -> NONE", normalize_severity(None) == "NONE")
            test("normalize_severity('foo') -> UNKNOWN", normalize_severity("foo") == "UNKNOWN")
            
            # severity_rank 测试
            test("severity_rank('CRITICAL') < 'HIGH'", severity_rank("CRITICAL") < severity_rank("HIGH"))
            test("severity_rank('high') == severity_rank('HIGH')", severity_rank("high") == severity_rank("HIGH"))
            test("severity_rank('none') > severity_rank('LOW')", severity_rank("none") > severity_rank("LOW"))
            
            # 查询 apache 2.4.5，验证 CVE-TEST-005 (小写 high) 和 CVE-TEST-009 (大写 HIGH) 都能被 HIGH 过滤包含
            high_cves = db.query("apache", "2.4.5", limit=10, min_severity="HIGH")
            cve_ids = {c.cve_id for c in high_cves}
            
            test("HIGH 过滤包含小写 high 的 CVE", "CVE-TEST-005" in cve_ids,
                 f"2.4.5 版本命中: {cve_ids}")
            
            db.close()
            
        except Exception as e:
            test("大小写等级测试异常", False, str(e))
            import traceback
            traceback.print_exc()
    
    # ============================================================
    # 场景 6: checkdb 严重等级分布完整性
    # ============================================================
    print("\n" + "="*60)
    print("🧪 场景 6: checkdb 严重等级分布包含 INFO/NONE/UNKNOWN")
    print("="*60)
    
    if imported > 0:
        try:
            db = VulnDB(db_path=DB_NEW, load_sample=False)
            stats = db.check_database()
            db.close()
            
            sev_dist = stats["severity_distribution"]
            required_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE", "UNKNOWN"]
            
            all_present = all(lvl in sev_dist for lvl in required_levels)
            test("严重等级分布包含 7 个等级", all_present, f"实际有: {list(sev_dist.keys())}")
            
            test("CRITICAL > 0", sev_dist.get("CRITICAL", 0) > 0)
            test("HIGH > 0", sev_dist.get("HIGH", 0) > 0)
            test("MEDIUM > 0", sev_dist.get("MEDIUM", 0) > 0)
            test("LOW > 0", sev_dist.get("LOW", 0) > 0)
            test("NONE > 0", sev_dist.get("NONE", 0) > 0)
            test("UNKNOWN > 0", sev_dist.get("UNKNOWN", 0) > 0)
            
            total = sev_dist.get("CRITICAL", 0) + sev_dist.get("HIGH", 0) + sev_dist.get("MEDIUM", 0) + \
                    sev_dist.get("LOW", 0) + sev_dist.get("INFO", 0) + sev_dist.get("NONE", 0) + sev_dist.get("UNKNOWN", 0)
            test("各等级数量之和等于总 CVE 数", total == stats["total_cves"],
                 f"等级总和={total}, 总数={stats['total_cves']}")
            
            test("缺失版本范围数量正确", isinstance(stats["missing_version_range"], int))
            test("缺失 CVSS 数量正确", isinstance(stats["missing_cvss"], int))
            test("缺失描述数量正确", isinstance(stats["missing_description"], int))
            
        except Exception as e:
            test("checkdb 等级分布测试异常", False, str(e))
            import traceback
            traceback.print_exc()
    
    # ============================================================
    # 场景 7: reporter 对异常等级的处理
    # ============================================================
    print("\n" + "="*60)
    print("🧪 场景 7: reporter 对异常等级的处理（不崩溃）")
    print("="*60)
    
    try:
        from vulndb import CVE
        
        cves_with_odd = [
            CVE("CVE-TEST-A", "test_svc", "1.0", "2.0", 9.0, "critical", "test"),  # 小写
            CVE("CVE-TEST-B", "test_svc", "1.0", "2.0", 5.0, "NONE", "test"),
            CVE("CVE-TEST-C", "test_svc", "1.0", "2.0", 0.0, "unknown", "test"),  # 小写
            CVE("CVE-TEST-D", "test_svc", "1.0", "2.0", 7.0, "FOOBAR", "test"),  # 完全未知
        ]
        
        reporter = Reporter()
        grouped = reporter._group_cves_by_severity(cves_with_odd)
        
        test("reporter 分组异常等级不崩溃", True)
        test("CRITICAL 组包含小写 critical", "CRITICAL" in grouped and len(grouped["CRITICAL"]) >= 1)
        test("NONE 组正确", "NONE" in grouped and len(grouped["NONE"]) >= 1)
        test("UNKNOWN 组包含 unknown 和 FOOBAR", 
             "UNKNOWN" in grouped and len(grouped["UNKNOWN"]) >= 2,
             f"UNKNOWN 组数量: {len(grouped.get('UNKNOWN', []))}")
        
    except Exception as e:
        test("reporter 异常等级测试异常", False, str(e))
        import traceback
        traceback.print_exc()
    
    # ============================================================
    # 总结
    # ============================================================
    print("\n" + "="*60)
    print("📋 验收测试总结")
    print("="*60)
    
    for name, ok, detail in all_results:
        status = "✅" if ok else "❌"
        print(f"  {status} {name}")
    
    total = passed_tests + failed_tests
    print(f"\n  总计: {passed_tests}/{total} 通过")
    
    if failed_tests == 0:
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    ✅ 所有验收测试通过！                      ║
╠══════════════════════════════════════════════════════════════╣
║  1. ✅ 旧库自动升级 - 打开旧库时自动补齐边界字段               ║
║  2. ✅ 空库自检正常 - 0条记录也能正常输出，不崩溃               ║
║  3. ✅ NONE/UNKNOWN 过滤稳定 - 异常等级不中断命令              ║
║  4. ✅ 排除边界正确 - Excluding 边界版本不命中                 ║
║  5. ✅ 大小写兼容 - high/HIGH 都能正确识别                    ║
║  6. ✅ 等级分布完整 - checkdb 展示所有 7 个等级                ║
║  7. ✅ reporter 兼容 - 异常等级正确归类不崩溃                  ║
╚══════════════════════════════════════════════════════════════╝
        """)
    else:
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    ❌ 部分测试未通过                          ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    # 清理
    for f in [DB_OLD, DB_NEW, DB_EMPTY]:
        if os.path.exists(f):
            os.remove(f)
    
    return 0 if failed_tests == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
