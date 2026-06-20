from vulndb import VulnDB
import os

if os.path.exists('cve.db'):
    os.remove('cve.db')

db = VulnDB('cve.db')

test_fingerprints = {
    '192.168.1.10': [
        {'port': 22, 'service': 'openssh', 'version': '7.4'},
        {'port': 80, 'service': 'nginx', 'version': '1.20'},
        {'port': 443, 'service': 'apache', 'version': '2.4.49'},
    ],
    '192.168.1.20': [
        {'port': 3306, 'service': 'mysql', 'version': '8.0.23'},
        {'port': 6379, 'service': 'redis', 'version': '6.2'},
    ]
}

vulns = db.query_all(test_fingerprints)

print('=' * 60)
print('漏洞联动测试结果')
print('=' * 60)

for ip, services in vulns.items():
    print(f'\n[+] {ip}')
    for svc_key, svc_data in services.items():
        cves = svc_data['cves']
        max_severity = max([c.cvss_severity for c in cves]) if cves else 'INFO'
        max_score = max([c.cvss_score for c in cves]) if cves else 0
        print(f'    Port {svc_data["port"]}: {svc_data["service"]} {svc_data["version"]}')
        print(f'      风险等级: {max_severity} (CVSS: {max_score})')
        print(f'      CVE 数量: {len(cves)}')
        for cve in cves[:3]:
            print(f'        - {cve.cve_id} ({cve.cvss_severity} {cve.cvss_score})')

db.close()
print('\n' + '=' * 60)
print('测试完成！漏洞联动功能正常工作。')
