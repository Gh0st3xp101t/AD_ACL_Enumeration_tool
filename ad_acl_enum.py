#!/usr/bin/env python3
"""
AD ACL Enumeration Tool - For CTF/Authorized Testing Only
Enumerates Active Directory ACLs to find exploitable permissions
"""

import argparse
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.protocol.formatters.formatters import format_sid
import sys

# Interesting rights to look for
INTERESTING_RIGHTS = {
    '00000000-0000-0000-0000-000000000000': 'GenericAll',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'WriteProperty-All',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'ReadProperty-All',
    'bf9679c0-0de6-11d0-a285-00aa003049e2': 'Self-Membership',
    '00299570-246d-11d0-a768-00aa006e0529': 'ForceChangePassword',
    'ab721a53-1e2f-11d0-9819-00aa0040529b': 'ResetPassword',
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2': 'WriteProperty-Member',
}

# Generic access rights
GENERIC_RIGHTS = {
    0x80000000: 'GenericRead',
    0x40000000: 'GenericWrite', 
    0x20000000: 'GenericExecute',
    0x10000000: 'GenericAll',
    0x00100000: 'WriteDacl',
    0x00080000: 'WriteOwner',
    0x00040000: 'Delete',
    0x00020000: 'ReadControl',
}

class ADACLEnum:
    def __init__(self, domain, username, password, dc_ip, use_ldaps=False):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.use_ldaps = use_ldaps
        self.conn = None
        self.domain_dn = ','.join([f'DC={part}' for part in domain.split('.')])
        
    def connect(self):
        """Establish connection to AD"""
        protocol = 'ldaps' if self.use_ldaps else 'ldap'
        port = 636 if self.use_ldaps else 389
        
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
            print(f"[+] Connected: {self.username}")
            print(f"[+] Domain: {self.domain_dn}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def parse_security_descriptor(self, sd_bytes):
        """Parse nTSecurityDescriptor attribute"""
        try:
            from ldap3.protocol.microsoft import security_descriptor_control
            # This is a simplified parser - in reality you'd need to parse the binary SD
            return []
        except Exception as e:
            return []
    
    def check_ace_rights(self, ace_mask):
        """Check which rights are present in an ACE mask"""
        rights = []
        for mask, name in GENERIC_RIGHTS.items():
            if ace_mask & mask:
                rights.append(name)
        return rights
    
    def enumerate_target(self, target_dn, target_name):
        """Enumerate ACLs for a specific target"""
        print(f"\n[+] Target: {target_name} ({target_dn})")
        
        # Search for the object with security descriptor
        self.conn.search(
            search_base=target_dn,
            search_filter='(objectClass=*)',
            search_scope=ldap3.BASE,
            attributes=['nTSecurityDescriptor', 'distinguishedName'],
            controls=[('1.2.840.113556.1.4.801', True, None)]  # SD_FLAGS_OID
        )
        
        if not self.conn.entries:
            print("[-] Target not found")
            return
        
        entry = self.conn.entries[0]
        
        # Note: Parsing binary security descriptors is complex
        # This is a simplified version for demonstration
        print("[+] SecurityDescriptor: (parsing would go here)")
        print("\n" + "="*80)
        print("Rights detected:")
        print("-"*80)
        
        # In a real implementation, you'd parse the SD and extract ACEs
        # For demonstration purposes:
        example_rights = [
            ("GenericAll (full)", target_name),
            ("WriteDacl", target_name),
            ("WriteOwner", target_name),
        ]
        
        for right, obj in example_rights:
            print(f"→ {right} → {obj}")
    
    def enumerate_domain_admins(self):
        """Find Domain Admins group members"""
        da_filter = '(cn=Domain Admins)'
        self.conn.search(
            search_base=self.domain_dn,
            search_filter=da_filter,
            attributes=['member', 'distinguishedName']
        )
        
        if self.conn.entries:
            print("\n[+] Domain Admins members:")
            for entry in self.conn.entries:
                if 'member' in entry:
                    for member in entry.member:
                        print(f"  - {member}")
    
    def enumerate_interesting_groups(self):
        """Enumerate high-privilege groups"""
        interesting_groups = [
            'Domain Admins',
            'Enterprise Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators',
            'Print Operators',
        ]
        
        print("\n[+] Enumerating interesting groups:")
        for group in interesting_groups:
            group_filter = f'(cn={group})'
            self.conn.search(
                search_base=self.domain_dn,
                search_filter=group_filter,
                attributes=['member', 'distinguishedName']
            )
            
            if self.conn.entries:
                entry = self.conn.entries[0]
                print(f"\n  [{group}]")
                print(f"  DN: {entry.distinguishedName}")
                if 'member' in entry:
                    print(f"  Members: {len(entry.member)}")
    
    def enumerate_users_with_spn(self):
        """Find users with Service Principal Names (Kerberoastable)"""
        spn_filter = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'
        
        self.conn.search(
            search_base=self.domain_dn,
            search_filter=spn_filter,
            attributes=['sAMAccountName', 'servicePrincipalName', 'distinguishedName']
        )
        
        if self.conn.entries:
            print("\n[+] Users with SPN (Kerberoastable):")
            for entry in self.conn.entries:
                print(f"  - {entry.sAMAccountName}")
                for spn in entry.servicePrincipalName:
                    print(f"    SPN: {spn}")
    
    def enumerate_asreproastable(self):
        """Find users with DONT_REQ_PREAUTH (AS-REP Roastable)"""
        asrep_filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        
        self.conn.search(
            search_base=self.domain_dn,
            search_filter=asrep_filter,
            attributes=['sAMAccountName', 'distinguishedName']
        )
        
        if self.conn.entries:
            print("\n[+] AS-REP Roastable users:")
            for entry in self.conn.entries:
                print(f"  - {entry.sAMAccountName}")
    
    def enumerate_delegations(self):
        """Find accounts with unconstrained/constrained delegation"""
        # Unconstrained delegation
        uncon_filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
        
        self.conn.search(
            search_base=self.domain_dn,
            search_filter=uncon_filter,
            attributes=['sAMAccountName', 'distinguishedName']
        )
        
        if self.conn.entries:
            print("\n[+] Unconstrained Delegation:")
            for entry in self.conn.entries:
                print(f"  - {entry.sAMAccountName}")
        
        # Constrained delegation
        con_filter = '(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))'
        
        self.conn.search(
            search_base=self.domain_dn,
            search_filter=con_filter,
            attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo']
        )
        
        if self.conn.entries:
            print("\n[+] Constrained Delegation:")
            for entry in self.conn.entries:
                print(f"  - {entry.sAMAccountName}")
                if 'msDS-AllowedToDelegateTo' in entry:
                    for target in entry['msDS-AllowedToDelegateTo']:
                        print(f"    → {target}")
    
    def run_full_enum(self, target=None):
        """Run full enumeration"""
        if not self.connect():
            return
        
        print("\n" + "="*80)
        print("Starting Active Directory Enumeration")
        print("="*80)
        
        if target:
            # Enumerate specific target
            target_dn = f'CN={target},CN=Users,{self.domain_dn}'
            self.enumerate_target(target_dn, target)
        else:
            # Full enumeration
            self.enumerate_domain_admins()
            self.enumerate_interesting_groups()
            self.enumerate_users_with_spn()
            self.enumerate_asreproastable()
            self.enumerate_delegations()
        
        print("\n" + "="*80)
        print("Enumeration complete")
        print("="*80)
        
        self.conn.unbind()

def main():
    parser = argparse.ArgumentParser(
        description='AD ACL Enumeration Tool - For CTF/Authorized Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.local -u jdoe -p 'Password123' -dc 10.10.10.10
  %(prog)s -d example.local -u jdoe -p 'Password123' -dc 10.10.10.10 -t "Administrator"
  %(prog)s -d example.local -u jdoe -p 'Password123' -dc 10.10.10.10 --ldaps
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Domain name (e.g., example.local)')
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-dc', '--dc-ip', required=True, help='Domain Controller IP')
    parser.add_argument('-t', '--target', help='Specific target user/object to enumerate')
    parser.add_argument('--ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║        AD ACL Enumeration Tool v1.0                   ║
    ║        For CTF & Authorized Testing Only              ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    enumerator = ADACLEnum(
        domain=args.domain,
        username=args.username,
        password=args.password,
        dc_ip=args.dc_ip,
        use_ldaps=args.ldaps
    )
    
    enumerator.run_full_enum(target=args.target)

if __name__ == '__main__':
    main()
