AGGRESSION_PROFILES = {
    'stealth': {
        'nmap_args': '-sS -T2 -Pn --max-retries 1 --host-timeout 5m',
        'ports': '80,443,22,21,53',
        'scripts': '',
        'udp': False,
        'version_intensity': 0,
        'bruteforce': False,
        'safe_only': True,
        'max_workers': 10,
        'timeout': 5
    },
    'normal': {
        'nmap_args': '-sS -T4 -O --script banner,smb-os-discovery,http-title',
        'ports': '1-1000',
        'scripts': 'default',
        'udp': False,
        'version_intensity': 3,
        'bruteforce': False,
        'safe_only': True,
        'max_workers': 30,
        'timeout': 3
    },
    'aggressive': {
        'nmap_args': '-sS -sU -T4 -O -sV --script vuln,exploit,discovery',
        'ports': '1-65535',
        'scripts': 'vuln,exploit',
        'udp': True,
        'version_intensity': 7,
        'bruteforce': True,
        'safe_only': False,
        'max_workers': 100,
        'timeout': 1
    },
    'destructive': {
        'nmap_args': '-sS -sU -A -T5 --script all --max-hostgroup 1',
        'ports': '1-65535',
        'scripts': 'all',
        'udp': True,
        'version_intensity': 9,
        'bruteforce': True,
        'safe_only': False,
        'max_workers': 200,
        'timeout': 0.5,
        'enable_fuzzing': True
    }
}