#!/usr/bin/env python3
"""
AD Stealth Enum - Version discrète pour CTF
Inclut des fonctionnalités OPSEC pour minimiser la détection
"""

import argparse
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
import time
import random
import sys
from datetime import datetime

class StealthADEnum:
    def __init__(self, domain, username, password, dc_ip, use_ldaps=False, delay_min=1, delay_max=3):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.use_ldaps = use_ldaps
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.conn = None
        self.domain_dn = ','.join([f'DC={part}' for part in domain.split('.')])
        self.query_count = 0
        
    def log(self, message, level="INFO"):
        """Log avec timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def stealth_delay(self):
        """Délai aléatoire entre requêtes pour OPSEC"""
        if self.delay_min > 0:
            delay = random.uniform(self.delay_min, self.delay_max)
            self.log(f"Waiting {delay:.2f}s before next query...", "STEALTH")
            time.sleep(delay)
    
    def connect(self):
        """Connexion LDAP/LDAPS"""
        protocol = 'ldaps' if self.use_ldaps else 'ldap'
        port = 636 if self.use_ldaps else 389
        
        self.log(f"Connecting to {protocol}://{self.dc_ip}:{port}", "CONNECT")
        
        server = Server(f'{protocol}://{self.dc_ip}:{port}', get_info=ALL)
        user_dn = f'{self.domain}\\{self.username}'
        
        try:
            self.conn = Connection(
                server,
                user=user_dn,
                password=self.password,
                authentication=NTLM,
                auto_bind=True
            )
            self.log(f"Connected as: {self.username}", "SUCCESS")
            self.log(f"Domain DN: {self.domain_dn}", "INFO")
            return True
        except Exception as e:
            self.log(f"Connection failed: {e}", "ERROR")
            return False
    
    def query_ldap(self, search_base, search_filter, attributes, scope=SUBTREE):
        """Wrapper LDAP avec compteur et délai"""
        self.query_count += 1
        self.log(f"Query #{self.query_count}: {search_filter[:50]}...", "QUERY")
        
        try:
            self.conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attributes
            )
            results = len(self.conn.entries)
            self.log(f"Found {results} result(s)", "RESULT")
            self.stealth_delay()
            return self.conn.entries
        except Exception as e:
            self.log(f"Query failed: {e}", "ERROR")
            return []
    
    def find_user(self, username):
        """Rechercher un utilisateur spécifique"""
        self.log(f"Searching for user: {username}", "TARGET")
        
        user_filter = f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))'
        entries = self.query_ldap(
            self.domain_dn,
            user_filter,
            ['distinguishedName', 'sAMAccountName', 'memberOf', 'userAccountControl']
        )
        
        if entries:
            entry = entries[0]
            self.log(f"Found: {entry.distinguishedName}", "SUCCESS")
            
            if 'memberOf' in entry:
                self.log("Group memberships:", "INFO")
                for group in entry.memberOf:
                    print(f"  → {group}")
            
            return entry
        else:
            self.log(f"User {username} not found", "WARNING")
            return None
    
    def check_acl_on_object(self, target_dn, target_name):
        """Vérifier les ACLs sur un objet (simplifié)"""
        self.log(f"Checking ACLs on: {target_name}", "ACL")
        
        # Requête pour obtenir le security descriptor
        entries = self.query_ldap(
            target_dn,
            '(objectClass=*)',
            ['nTSecurityDescriptor', 'distinguishedName'],
            scope=ldap3.BASE
        )
        
        if entries:
            self.log("Security descriptor retrieved", "SUCCESS")
            self.log("⚠ Full ACL parsing requires complex binary parsing", "INFO")
            self.log("Recommended: Use BloodHound for detailed ACL analysis", "TIP")
            return True
        return False
    
    def find_interesting_users(self):
        """Chercher des utilisateurs intéressants avec approche discrète"""
        self.log("Searching for users with elevated privileges...", "ENUM")
        
        # Chercher les administrateurs du domaine
        admin_filter = '(&(objectCategory=person)(objectClass=user)(adminCount=1))'
        entries = self.query_ldap(
            self.domain_dn,
            admin_filter,
            ['sAMAccountName', 'distinguishedName', 'description']
        )
        
        if entries:
            self.log(f"Found {len(entries)} privileged users", "RESULT")
            for entry in entries:
                print(f"  [ADMIN] {entry.sAMAccountName}")
                if 'description' in entry and entry.description:
                    print(f"    Description: {entry.description}")
    
    def find_spn_accounts(self):
        """Trouver les comptes avec SPN (Kerberoastable)"""
        self.log("Searching for Kerberoastable accounts...", "KERBEROS")
        
        spn_filter = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'
        entries = self.query_ldap(
            self.domain_dn,
            spn_filter,
            ['sAMAccountName', 'servicePrincipalName', 'distinguishedName']
        )
        
        if entries:
            self.log(f"Found {len(entries)} Kerberoastable accounts", "VULN")
            for entry in entries:
                print(f"  [SPN] {entry.sAMAccountName}")
                for spn in entry.servicePrincipalName:
                    print(f"    → {spn}")
                print(f"    ⚡ Exploit: GetUserSPNs.py {self.domain}/{self.username} -request -dc-ip {self.dc_ip}")
    
    def find_asrep_users(self):
        """Trouver les comptes AS-REP Roastable"""
        self.log("Searching for AS-REP Roastable accounts...", "KERBEROS")
        
        # userAccountControl avec DONT_REQ_PREAUTH (0x400000 = 4194304)
        asrep_filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        entries = self.query_ldap(
            self.domain_dn,
            asrep_filter,
            ['sAMAccountName', 'distinguishedName']
        )
        
        if entries:
            self.log(f"Found {len(entries)} AS-REP Roastable accounts", "VULN")
            for entry in entries:
                print(f"  [ASREP] {entry.sAMAccountName}")
                print(f"    ⚡ Exploit: GetNPUsers.py {self.domain}/ -dc-ip {self.dc_ip} -usersfile users.txt")
    
    def find_delegation(self):
        """Chercher les délégations"""
        self.log("Searching for delegation configurations...", "DELEGATION")
        
        # Unconstrained Delegation
        uncon_filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
        entries = self.query_ldap(
            self.domain_dn,
            uncon_filter,
            ['sAMAccountName', 'distinguishedName', 'objectClass']
        )
        
        if entries:
            self.log(f"Found {len(entries)} accounts with unconstrained delegation", "VULN")
            for entry in entries:
                obj_type = "Computer" if "computer" in str(entry.objectClass) else "User"
                print(f"  [UNCONSTRAINED-{obj_type}] {entry.sAMAccountName}")
        
        # Constrained Delegation
        con_filter = '(msDS-AllowedToDelegateTo=*)'
        entries = self.query_ldap(
            self.domain_dn,
            con_filter,
            ['sAMAccountName', 'msDS-AllowedToDelegateTo']
        )
        
        if entries:
            self.log(f"Found {len(entries)} accounts with constrained delegation", "VULN")
            for entry in entries:
                print(f"  [CONSTRAINED] {entry.sAMAccountName}")
                if 'msDS-AllowedToDelegateTo' in entry:
                    for target in entry['msDS-AllowedToDelegateTo']:
                        print(f"    → Can delegate to: {target}")
    
    def find_weak_passwords_indicators(self):
        """Chercher des indicateurs de mots de passe faibles"""
        self.log("Searching for password policy indicators...", "PASSWORD")
        
        # Comptes avec mot de passe qui n'expire jamais
        noexpire_filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))'
        entries = self.query_ldap(
            self.domain_dn,
            noexpire_filter,
            ['sAMAccountName', 'pwdLastSet']
        )
        
        if entries:
            self.log(f"Found {len(entries)} accounts with non-expiring passwords", "INFO")
            for entry in entries[:5]:  # Limiter à 5 pour la discrétion
                print(f"  [NOEXPIRE] {entry.sAMAccountName}")
    
    def targeted_enum(self, target_user):
        """Énumération ciblée d'un seul utilisateur (plus discret)"""
        self.log("=== TARGETED ENUMERATION MODE ===", "MODE")
        self.log(f"Target: {target_user}", "TARGET")
        
        user_entry = self.find_user(target_user)
        if user_entry:
            self.check_acl_on_object(
                user_entry.distinguishedName.value,
                user_entry.sAMAccountName.value
            )
    
    def broad_enum(self):
        """Énumération large (plus de bruit)"""
        self.log("=== BROAD ENUMERATION MODE ===", "MODE")
        self.log("⚠ This will generate multiple LDAP queries", "WARNING")
        
        self.find_interesting_users()
        self.find_spn_accounts()
        self.find_asrep_users()
        self.find_delegation()
        self.find_weak_passwords_indicators()
    
    def minimal_enum(self):
        """Énumération minimale (très discret)"""
        self.log("=== MINIMAL ENUMERATION MODE ===", "MODE")
        self.log("Only querying essential information", "STEALTH")
        
        # Juste vérifier notre propre compte
        self.find_user(self.username)
    
    def run(self, mode="broad", target=None):
        """Exécuter l'énumération selon le mode"""
        if not self.connect():
            return
        
        print("\n" + "="*70)
        self.log("Starting stealth enumeration", "START")
        print("="*70 + "\n")
        
        start_time = time.time()
        
        if mode == "targeted" and target:
            self.targeted_enum(target)
        elif mode == "minimal":
            self.minimal_enum()
        else:
            self.broad_enum()
        
        elapsed = time.time() - start_time
        
        print("\n" + "="*70)
        self.log(f"Enumeration complete", "DONE")
        self.log(f"Total queries: {self.query_count}", "STATS")
        self.log(f"Time elapsed: {elapsed:.2f}s", "STATS")
        print("="*70)
        
        self.conn.unbind()

def main():
    parser = argparse.ArgumentParser(
        description='Stealth AD Enumeration Tool - CTF/Authorized Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Enumeration Modes:
  minimal   - Très discret, requête minimale (1-2 queries)
  targeted  - Moyen, focus sur un utilisateur spécifique (2-5 queries)
  broad     - Complet, énumération large (10-20 queries)

OPSEC Features:
  --delay-min/max  - Délai aléatoire entre requêtes
  --ldaps          - Utilise LDAPS (chiffré)
  --no-delay       - Désactive les délais (plus rapide, moins discret)

Examples:
  # Minimal (très discret)
  %(prog)s -d example.local -u user -p pass -dc 10.10.10.10 --mode minimal
  
  # Ciblé sur un utilisateur
  %(prog)s -d example.local -u user -p pass -dc 10.10.10.10 --mode targeted -t Administrator
  
  # Énumération complète avec LDAPS
  %(prog)s -d example.local -u user -p pass -dc 10.10.10.10 --mode broad --ldaps
  
  # Rapide sans délai
  %(prog)s -d example.local -u user -p pass -dc 10.10.10.10 --no-delay
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Domain name')
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-dc', '--dc-ip', required=True, help='Domain Controller IP')
    parser.add_argument('--mode', choices=['minimal', 'targeted', 'broad'], 
                       default='broad', help='Enumeration mode (default: broad)')
    parser.add_argument('-t', '--target', help='Target user for targeted mode')
    parser.add_argument('--ldaps', action='store_true', help='Use LDAPS (port 636)')
    parser.add_argument('--delay-min', type=float, default=1.0, 
                       help='Minimum delay between queries in seconds (default: 1.0)')
    parser.add_argument('--delay-max', type=float, default=3.0,
                       help='Maximum delay between queries in seconds (default: 3.0)')
    parser.add_argument('--no-delay', action='store_true', 
                       help='Disable delays (faster but less stealthy)')
    
    args = parser.parse_args()
    
    if args.mode == 'targeted' and not args.target:
        parser.error("--target is required when using targeted mode")
    
    if args.no_delay:
        delay_min = 0
        delay_max = 0
    else:
        delay_min = args.delay_min
        delay_max = args.delay_max
    
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║     AD Stealth Enumeration Tool v1.0                  ║
    ║     Optimized for OPSEC & CTF                         ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    enumerator = StealthADEnum(
        domain=args.domain,
        username=args.username,
        password=args.password,
        dc_ip=args.dc_ip,
        use_ldaps=args.ldaps,
        delay_min=delay_min,
        delay_max=delay_max
    )
    
    enumerator.run(mode=args.mode, target=args.target)

if __name__ == '__main__':
    main()
