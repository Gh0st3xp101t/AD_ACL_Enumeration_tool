# AD Enumeration & Exploitation Toolkit

**⚠️ Pour utilisation en CTF et tests autorisés uniquement ⚠️**

## Description

Suite complète d'outils pour l'énumération et l'exploitation Active Directory dans un environnement autorisé. Ce toolkit comprend trois outils principaux optimisés pour différents scénarios d'attaque.

## 📦 Contenu du Toolkit

### 🎯 ad_stealth_enum.py (Recommandé)
**Outil d'énumération furtive avec fonctionnalités OPSEC avancées**

Caractéristiques :
- ✅ 3 modes d'opération (minimal, targeted, broad)
- ✅ Délais aléatoires entre requêtes pour éviter la détection
- ✅ Support LDAPS (chiffré) sur port 636
- ✅ Logging détaillé avec timestamps
- ✅ Compteur de requêtes LDAP
- ✅ Détection de Kerberoasting, AS-REP Roasting, délégations

**Idéal pour :** CTF où la discrétion compte, environnements avec monitoring

### 🔍 ad_acl_enum.py
**Outil d'énumération basique et rapide**

Caractéristiques :
- ✅ Énumération complète des ACLs
- ✅ Détection des permissions dangereuses (GenericAll, WriteDacl, etc.)
- ✅ Identification des groupes à privilèges
- ✅ Recherche d'utilisateurs Kerberoastables/AS-REP Roastables
- ✅ Détection des délégations

**Idéal pour :** Reconnaissance rapide, premiers tests

### ⚔️ ad_exploit_helper.py
**Générateur de commandes d'exploitation**

Caractéristiques :
- ✅ Menu interactif pour choisir le type d'exploitation
- ✅ Génère les commandes exactes prêtes à l'emploi
- ✅ Couvre 12 techniques d'exploitation différentes
- ✅ Inclut commandes Impacket, PowerView, net rpc
- ✅ Guide étape par étape pour chaque attaque

**Idéal pour :** Phase d'exploitation après énumération

## Installation

### Installation automatique (recommandé)
```bash
chmod +x install.sh
./install.sh
```

### Installation manuelle
```bash
# Installer les dépendances
pip3 install -r requirements.txt

# Rendre les scripts exécutables
chmod +x ad_acl_enum.py ad_stealth_enum.py ad_exploit_helper.py
```

## 🚀 Guide d'Utilisation

### ad_stealth_enum.py - Énumération Furtive

#### Mode Minimal (Très discret - 1-2 requêtes)
```bash
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode minimal --ldaps
```

#### Mode Targeted (Moyen - 2-5 requêtes sur un utilisateur)
```bash
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode targeted -t N.Thompson --ldaps
```

#### Mode Broad (Complet - 10-20 requêtes)
```bash
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode broad --ldaps
```

#### Sans délai (Rapide mais moins discret)
```bash
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode broad --no-delay
```

#### Avec délais personnalisés
```bash
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --delay-min 2 --delay-max 5
```

### ad_acl_enum.py - Énumération Rapide

#### Énumération basique
```bash
./ad_acl_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' -dc 10.129.2.171
```

#### Énumération d'un utilisateur spécifique
```bash
./ad_acl_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 -t "N.Thompson"
```

#### Avec LDAPS
```bash
./ad_acl_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --ldaps
```

### ad_exploit_helper.py - Génération de Commandes

#### Mode interactif
```bash
./ad_exploit_helper.py -d delegate.vl -dc 10.129.2.171 \
  -u A.Briggs -p 'P4ssw0rd1#123'
```

Le menu vous proposera :
```
1)  GenericAll on User/Object
2)  WriteDacl on User/Object
3)  WriteOwner on User/Object
4)  Self-Membership on Group
5)  ForceChangePassword on User
6)  Kerberoasting
7)  AS-REP Roasting
8)  Unconstrained Delegation
9)  Constrained Delegation
10) BloodHound Analysis
11) Lateral Movement
12) Persistence Techniques
13) All Commands (print everything)
```

## 🎓 Workflow Recommandé pour CTF

### Phase 1 : Reconnaissance Discrète
```bash
# 1. Commencer en mode minimal pour tester la connectivité
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode minimal --ldaps

# 2. Si aucune alerte, passer en mode broad
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode broad --ldaps
```

### Phase 2 : Analyse Approfondie
```bash
# 3. Cibler des utilisateurs/objets intéressants découverts
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode targeted -t Administrator --ldaps
```

### Phase 3 : Exploitation
```bash
# 5. Générer les commandes d'exploitation
./ad_exploit_helper.py -d delegate.vl -dc 10.129.2.171 \
  -u A.Briggs -p 'P4ssw0rd1#123'

# Sélectionner l'option correspondant à la vulnérabilité trouvée
# Les commandes exactes seront affichées, prêtes à copier-coller
```


## 📊 Comparaison des Outils

| Fonctionnalité | ad_stealth_enum.py | ad_acl_enum.py | ad_exploit_helper.py |
|----------------|-------------------|----------------|---------------------|
| **Modes d'opération** | 3 modes (minimal/targeted/broad) | Mode unique | Menu interactif |
| **Délais OPSEC** | ✅ Configurables | ❌ Non | N/A |
| **LDAPS** | ✅ Oui | ✅ Oui | N/A |
| **Logging détaillé** | ✅ Avec timestamps | ✅ Basique | ✅ Oui |
| **Compteur requêtes** | ✅ Oui | ❌ Non | N/A |
| **Énumération ACL** | ⚠️ Simplifiée | ✅ Complète | N/A |
| **Kerberoasting** | ✅ Détection | ✅ Détection | ✅ Commandes |
| **AS-REP Roasting** | ✅ Détection | ✅ Détection | ✅ Commandes |
| **Délégations** | ✅ Détection | ✅ Détection | ✅ Commandes |
| **Génération exploits** | ❌ Non | ❌ Non | ✅ 12 techniques |
| **Discrétion** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | N/A |
| **Vitesse** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | N/A |

**Recommandation :** Commencez avec `ad_stealth_enum.py` en mode minimal, puis utilisez `ad_exploit_helper.py` pour l'exploitation.

## Ce que l'outil détecte

### 1. **Permissions ACL dangereuses**
- **GenericAll** : Contrôle total sur l'objet
- **WriteDacl** : Peut modifier les permissions
- **WriteOwner** : Peut devenir propriétaire
- **WriteProperty** : Peut modifier des attributs
- **Self-Membership** : Peut s'ajouter à un groupe

### 2. **Utilisateurs Kerberoastables**
Utilisateurs avec un SPN configuré → vulnérables à Kerberoasting  
Utilisez **ad_exploit_helper.py** pour générer les commandes d'exploitation

### 3. **Utilisateurs AS-REP Roastables**
Comptes avec DONT_REQUIRE_PREAUTH → vulnérables à AS-REP Roasting  
Utilisez **ad_exploit_helper.py** pour générer les commandes d'exploitation

### 4. **Délégations dangereuses**
- **Unconstrained Delegation** : Machine peut usurper n'importe quel utilisateur
- **Constrained Delegation** : Peut usurper vers services spécifiques

### 5. **Groupes à privilèges élevés**
- Domain Admins
- Enterprise Admins
- Account Operators
- Backup Operators
- etc.

## Exploitation post-énumération

Utilisez **ad_exploit_helper.py** pour générer automatiquement les commandes d'exploitation :

```bash
./ad_exploit_helper.py -d delegate.vl -dc 10.129.2.171 -u A.Briggs -p 'P4ssw0rd1#123'
```

L'outil vous proposera un menu interactif pour sélectionner le type de vulnérabilité détectée et générera les commandes exactes prêtes à copier-coller.

Techniques supportées : GenericAll, WriteDacl, WriteOwner, Self-Membership, ForceChangePassword, Kerberoasting, AS-REP Roasting, Delegations, BloodHound, Lateral Movement, Persistence.

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

## Chemins d'attaque courants détectés par les outils

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

## Conseils OPSEC pour CTF

### Niveau de discrétion

**🟢 Maximum (Recommandé si monitoring détecté)**
```bash
./ad_stealth_enum.py --mode minimal --ldaps --delay-min 2 --delay-max 5
```

**🟡 Normal (CTF standard)**
```bash
./ad_stealth_enum.py --mode broad --ldaps
```

**🔴 Rapide (Pas de monitoring / Time pressure)**
```bash
./ad_stealth_enum.py --mode broad --no-delay
```

### Techniques pour minimiser la détection

1. **Toujours utiliser LDAPS** (port 636, chiffré)
2. **Espacer les requêtes** avec délais aléatoires
3. **Limiter les requêtes** au strict nécessaire
4. **Utiliser le mode targeted** pour cibler uniquement les objets intéressants

## 💡 Exemple Pratique CTF

### Scénario : Delegate.vl (VulnLab)

Basé sur votre screenshot, voici comment utiliser le toolkit :

```bash
# 1. Énumération initiale discrète
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode minimal --ldaps

# 2. Si vous trouvez que A.Briggs a des droits intéressants, énumérer largement
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode broad --ldaps

# Output possible :
# [ADMIN] N.Thompson
# [GenericAll] A.Briggs → N.Thompson

# 3. Cibler N.Thompson spécifiquement
./ad_stealth_enum.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  -dc 10.129.2.171 --mode targeted -t N.Thompson --ldaps

# 4. Générer la commande d'exploitation
./ad_exploit_helper.py -d delegate.vl -dc 10.129.2.171 \
  -u A.Briggs -p 'P4ssw0rd1#123'
# Choisir : 1) GenericAll on User/Object
# Entrer : N.Thompson

# La commande générée sera prête à copier-coller
```

### Résultat Attendu
```
[10:44] [INFO] Connected as: A.Briggs
[10:44] [INFO] Domain DN: DC=delegate,DC=vl
[10:44] [ENUM] Searching for privileged users...
[10:44] [RESULT] Found 3 privileged users
  [ADMIN] N.Thompson
  [ADMIN] Administrator
  [ADMIN] krbtgt
[10:44] [ACL] Checking ACLs on: N.Thompson
[10:44] [SUCCESS] Security descriptor retrieved
[10:44] [VULN] GenericAll detected: A.Briggs → N.Thompson
```

## 🔐 Techniques d'Exploitation Supportées

### ad_exploit_helper.py génère des commandes pour :

1. **GenericAll** - Contrôle total (reset password, shadow credentials)
2. **WriteDacl** - Modification de permissions (grant yourself rights)
3. **WriteOwner** - Prise de propriété (become owner)
4. **Self-Membership** - Ajout aux groupes (join Domain Admins)
5. **ForceChangePassword** - Reset de mot de passe
6. **Kerberoasting** - Extraction de tickets TGS (crack service accounts)
7. **AS-REP Roasting** - Extraction AS-REP (users sans preauth)
8. **Unconstrained Delegation** - Capture de TGT (printer bug)
9. **Constrained Delegation** - S4U2Self/Proxy (impersonation)
10. **BloodHound** - Cartographie du domaine
11. **Lateral Movement** - PSExec, WMI, SMB, RDP
12. **Persistence** - Golden/Silver tickets, backdoors

## 📋 Résumé des Fonctionnalités

### ad_stealth_enum.py
- Énumération avec 3 niveaux de discrétion
- Détection : Kerberoasting, AS-REP Roasting, Délégations, Groupes privilégiés
- OPSEC : Délais configurables, LDAPS, logging détaillé

### ad_acl_enum.py  
- Énumération rapide et complète
- Focus sur les ACLs et permissions
- Détection des mêmes vulnérabilités

### ad_exploit_helper.py
- Menu interactif pour 12 techniques d'exploitation
- Génère les commandes exactes prêtes à l'emploi
- Inclut Impacket, PowerView, net rpc, et plus

## Disclaimer

Cet outil est destiné uniquement à être utilisé dans des environnements CTF et des tests de pénétration autorisés. L'utilisation non autorisée sur des systèmes que vous ne possédez pas ou pour lesquels vous n'avez pas l'autorisation explicite est illégale.

## License

MIT License - Usage éducatif et CTF uniquement
