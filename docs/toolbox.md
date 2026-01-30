# 🧰 Darkmoon Toolbox 

## 1. À quoi sert ce projet ?

Ce projet sert à :

* Construire une **toolbox de cybersécurité**.
* Mettre beaucoup d’outils dans **une seule image Docker**.
* Avoir une image :

  * fiable,
  * reproductible,
  * facile à maintenir,
  * facile à étendre.

Cette image est destinée :

* aux **pentesters**,
* aux **ingénieurs sécurité**,
* aux **chercheurs**,
* à la **communauté Open Source**.

---

## 2. Principe général (idée simple)

Ce projet utilise **Docker** avec **deux étapes** :

### Étape 1 : Builder

* On **compile**.
* On **installe**.
* On **prépare** tous les outils.
* Rien n’est encore destiné à l’utilisateur final.

### Étape 2 : Runtime

* On **copie seulement le résultat utile**.
* On enlève tout ce qui n’est pas nécessaire.
* L’image finale est **plus petite** et **plus propre**.

👉 Cette séparation est volontaire.
👉 Elle évite les erreurs et réduit les risques.

---

## 3. Pourquoi cette architecture est intelligente

### 3.1 Séparation claire des rôles

Chaque fichier a **un seul rôle** :

* `Dockerfile`

  * Gère le système.
  * Installe les langages.
  * Copie les résultats.
* `setup.sh`

  * Installe les outils **binaires** (Go, GitHub releases, compilation C).
* `setup_ruby.sh`

  * Installe les outils **Ruby**.
* `setup_py.sh`

  * Installe les outils **Python**.
  * Crée des commandes simples (`netexec`, `sqlmap`, etc.).

👉 Cela évite les scripts “magiques”.
👉 Tout est lisible et vérifiable.

---

### 3.2 Sortie standardisée

Tous les outils compilés sortent **au même endroit** :

```
/out/bin
```

Puis ils sont exposés dans :

```
/usr/local/bin
```

👉 Une règle simple :

* **si un outil est dans `/out/bin`, il sera utilisable**.

---

### 3.3 Optimisations importantes

* Suppression des caches APT.
* Suppression de `apt` et `dpkg` en runtime.
* Pas de compilateur dans l’image finale.
* Langages compilés une seule fois.

👉 Résultat :

* image plus petite,
* surface d’attaque réduite,
* comportement stable.

---

## 4. Que contient l’image ?

### 4.1 Système de base

* OS : Debian Bookworm (version slim)
* Outils système essentiels :

  * `bash`
  * `curl`
  * `jq`
  * `dnsutils`
  * `openssh-client`
  * `hydra`
  * `snmp`

---

### 4.2 Langages intégrés

* **Go**

  * utilisé pour compiler beaucoup d’outils réseau et sécurité
* **Python** (version compilée)

  * installé dans `/opt/darkmoon/python`
* **Ruby** (version compilée)

  * installé dans `/opt/darkmoon/ruby`

👉 Les versions sont **fixées** pour éviter les surprises.

---

### 4.3 Wordlists

* **SecLists**

  * accessibles via :

    * `/usr/share/seclists`
    * `/usr/share/wordlists/seclists`
* Wordlists **DIRB**

  * accessibles via `/usr/share/dirb/wordlists`

---

### 4.4 Outils installés (exemples)

Les outils sont installés via les scripts :

* Scan réseau
* Scan web
* Kubernetes
* Active Directory
* HTTP / DNS / RPC

Exemples (non exhaustifs) :

* `nuclei`
* `naabu`
* `httpx`
* `ffuf`
* `dirb`
* `kubectl`
* `kubeletctl`
* `kubescape`
* `netexec`
* `sqlmap`
* `wafw00f`

👉 Tous sont accessibles directement dans le terminal.

---

## 5. Comment utiliser l’image

### 5.1 Construire l’image

```bash
docker build -t darkmoon .
```

### 5.2 Lancer un shell

```bash
docker run -it darkmoon bash
```

### 5.3 Utiliser un outil

```bash
nuclei -h
naabu -h
netexec -h
```

👉 Aucun chemin compliqué n’est nécessaire.

---

## 6. Comment ajouter un nouvel outil (pour la communauté)

### 6.1 Choisir le bon endroit

| Type d’outil        | Où l’ajouter         |
| ------------------- | -------------------- |
| Outil Go / binaire  | `setup.sh`           |
| Outil Python        | `setup_py.sh`        |
| Lib système runtime | Dockerfile (runtime) |
| Lib de compilation  | Dockerfile (builder) |

---

### 6.2 Règles à respecter

* Un outil = un bloc clair.
* Toujours afficher un message :

  * `msg "outil …"`
* Toujours vérifier l’installation :

  * `tool -h` ou `tool --version`
* Toujours installer dans :

  * `/out/bin` (pour les binaires)
* Ne pas mélanger les responsabilités.

---

### 6.3 Exemple simple (outil Go)

```bash
msg "exampletool …"
go install github.com/example/exampletool@latest
install -m 755 "$(go env GOPATH)/bin/exampletool" "$BIN_OUT/exampletool"
```

---

## 7. Comment maintenir le projet

### En cas d’erreur :

* Lire le log.
* Identifier si le problème vient :

  * de Go,
  * de Python,
  * d’APT,
  * d’une compilation C.

### Bonnes pratiques :

* Ne pas ajouter de dépendance inutile.
* Ne pas casser la structure existante.
* Tester avant de proposer une contribution.

---

## 8. Pour la communauté Open Source

Ce projet est fait pour :

* être **lu**,
* être **compris**,
* être **amélioré**.

Si vous proposez une contribution :

* soyez clair,
* soyez factuel,
* respectez l’architecture.

---

## 9. Résumé très court

* Deux étapes : **builder → runtime**
* Scripts séparés et clairs
* Outils centralisés dans `/out/bin`
* Exécution simple via `/usr/local/bin`
* Image propre, stable et maintenable

---

## 10. Liste de la toolbox:

Voici **tous les outils réellement installés / présents dans l’image finale** via **Dockerfile + setup.sh + setup_py.sh** (et les symlinks/wrappers), dans un tableau.

> ⚠️ Je **n’inclus pas** les *libs* (libssl, zlib, etc.) ni les *outils de build* du stage `builder` (gcc, make…), car ils ne sont pas dans l’image runtime finale.
> ⚠️ `docker-compose` installe/contient aussi **ZAP** dans un autre container (`ghcr.io/zaproxy/zaproxy:weekly`) → **pas inclus ici** car ce n’est **pas** “installé via le Dockerfile darkmoon”.

### Outils installés dans l’image runtime `darkmoon`

| Outil (commande)                 | Source / méthode d’installation              | Emplacement (binaire)                                                   | Notes                                                                          |
| -------------------------------- | -------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `bash`                           | `apt-get install`                            | `/bin/bash`                                                             | Shell runtime                                                                  |
| `ca-certificates`                | `apt-get install`                            | (système)                                                               | Certificats TLS                                                                |
| `tzdata`                         | `apt-get install`                            | (système)                                                               | Timezone                                                                       |
| `dig` / `nslookup`… (`dnsutils`) | `apt-get install dnsutils`                   | `/usr/bin/dig`                                                          | DNS tooling                                                                    |
| `curl` (Debian)                  | `apt-get install curl`                       | `/usr/bin/curl`                                                         | Curl système                                                                   |
| `curl` (custom 8.15.0)           | build + `COPY /out/curl` + `PATH`            | `/opt/darkmoon/curl/bin/curl`                                           | **Prioritaire** dans le `PATH`                                                 |
| `jq`                             | `apt-get install jq`                         | `/usr/bin/jq`                                                           | JSON CLI                                                                       |
| `hydra`                          | `apt-get install hydra`                      | `/usr/bin/hydra`                                                        | Brute force                                                                    |
| `snmp*` (`snmp`)                 | `apt-get install snmp`                       | `/usr/bin/snmpwalk` etc.                                                | Suite SNMP                                                                     |
| `ssh` (client)                   | `apt-get install openssh-client`             | `/usr/bin/ssh`                                                          | SSH client                                                                     |
| `dirb`                           | build depuis sources + copy                  | `/usr/local/bin/dirb`                                                   | Wordlists copiées aussi                                                        |
| Wordlists DIRB                   | copy                                         | `/usr/share/wordlists/dirb/`                                            | + symlink compat `/usr/share/dirb/wordlists`                                   |
| `waybackurls`                    | Go build (`setup.sh`) + copy                 | `/usr/local/bin/waybackurls`                                            | Recon URLs archive.org                                                         |
| `kubectl`                        | download binaire officiel (dl.k8s.io) + copy | `/usr/local/bin/kubectl`                                                | v1.34.2 (ARG)                                                                  |
| `kube-bench`                     | `go install` + copy                          | `/usr/local/bin/kube-bench`                                             | v0.14.0                                                                        |
| `grpcurl`                        | build depuis sources + copy                  | `/usr/local/bin/grpcurl`                                                | deps Go patchées                                                               |
| `ruby`                           | build Ruby 3.3.5 + copy                      | `/opt/darkmoon/ruby/bin/ruby`                                           | Ruby embarqué                                                                  |
| `gem`                            | Ruby install                                 | `/opt/darkmoon/ruby/bin/gem`                                            | RubyGems                                                                       |
| `bundler`                        | `gem install bundler:2.7.2`                  | `/opt/darkmoon/ruby/bin/bundle`                                         | Utilisé pour WhatWeb                                                           |
| `whatweb`                        | git clone + gems bundler + wrapper           | `/usr/local/bin/whatweb`                                                | Wrapper lance `/opt/darkmoon/whatweb/whatweb` avec bundler                     |
| `python3`                        | build Python 3.12.6 + copy                   | `/opt/darkmoon/python/bin/python3`                                      | Python embarqué                                                                |
| `pip3`                           | `--with-ensurepip`                           | `/opt/darkmoon/python/bin/pip3`                                         | Pip embarqué                                                                   |
| `impacket`                       | `pip install impacket==0.12.0`               | (site-packages)                                                         | Lib + entrypoints impacket                                                     |
| `impacket-smbclient`             | wrapper custom                               | `/usr/local/bin/impacket-smbclient`                                     | `python -m impacket.smbclient`                                                 |
| `rpcdump.py`                     | wrapper custom                               | `/usr/local/bin/rpcdump.py`                                             | `python -m impacket.examples.rpcdump`                                          |
| `NetExec` (`nxc` / `netexec`)    | `pip install git+...NetExec@v1.4.0`          | `/opt/darkmoon/python/bin/nxc` (ou `netexec`)                           | Install depuis GitHub                                                          |
| `netexec`                        | wrapper custom                               | `/usr/local/bin/netexec`                                                | Appelle `nxc` ou `netexec`                                                     |
| `crackmapexec`                   | wrapper custom                               | `/usr/local/bin/crackmapexec`                                           | Alias compat → `netexec`                                                       |
| `bloodhound` (ingestor python)   | `pip install bloodhound==1.7.2`              | `/opt/darkmoon/python/bin/bloodhound`                                   | Ingestor Python                                                                |
| `bloodhound-python`              | wrapper custom                               | `/usr/local/bin/bloodhound-python`                                      | Alias explicite                                                                |
| `wafw00f`                        | `pip install wafw00f`                        | `/opt/darkmoon/python/bin/wafw00f` + wrapper                            | Wrapper `/usr/local/bin/wafw00f`                                               |
| `sqlmap`                         | `pip install sqlmap`                         | `/opt/darkmoon/python/bin/sqlmap` + wrapper                             | Wrapper `/usr/local/bin/sqlmap`                                                |
| `arjun`                          | `pip install arjun`                          | `/opt/darkmoon/python/bin/arjun` + wrapper                              | Wrapper `/usr/local/bin/arjun`                                                 |
| `aws` (AWS CLI)                  | `pip install awscli`                         | `/opt/darkmoon/python/bin/aws` + wrapper                                | Wrapper `/usr/local/bin/aws`                                                   |
| `naabu`                          | build Go (setup.sh) + copy                   | `/opt/darkmoon/kube/naabu` + `/usr/local/bin/naabu`                     | Port scanner                                                                   |
| `httpx`                          | build Go (setup.sh) + copy                   | `/opt/darkmoon/kube/httpx` + `/usr/local/bin/httpx`                     | HTTP probing                                                                   |
| `nuclei`                         | `go install` (setup.sh) + copy               | `/opt/darkmoon/kube/nuclei` + `/usr/local/bin/nuclei`                   | Scanner templates                                                              |
| `nuclei-templates`               | `nuclei -update-templates` + copy            | `/opt/darkmoon/nuclei-templates`                                        | + copie init `/root/nuclei-templates`                                          |
| `zgrab2`                         | `go install` (setup.sh) + copy               | `/opt/darkmoon/kube/zgrab2` + `/usr/local/bin/zgrab2`                   | Banner grabber                                                                 |
| `katana`                         | `go install` (setup.sh) + copy               | `/opt/darkmoon/kube/katana` + `/usr/local/bin/katana`                   | Crawler                                                                        |
| `kubescape`                      | build Go (setup.sh, v3.0.9) + copy           | `/opt/darkmoon/kube/kubescape` + `/usr/local/bin/kubescape`             | K8s security scanner                                                           |
| `kubectl-who-can`                | build Go (setup.sh) + copy                   | `/opt/darkmoon/kube/kubectl-who-can` + `/usr/local/bin/kubectl-who-can` | K8s RBAC                                                                       |
| `kubeletctl`                     | build Go (setup.sh) + copy                   | `/opt/darkmoon/kube/kubeletctl` + `/usr/local/bin/kubeletctl`           | Kubelet tooling                                                                |
| `rbac-police`                    | build Go (setup.sh) + copy                   | `/opt/darkmoon/kube/rbac-police` + `/usr/local/bin/rbac-police`         | Peut être un **stub** si build échoue                                          |
| `ffuf`                           | build Go (setup.sh)                          | `/out/bin/ffuf` (builder)                                               | /usr/local/bin/ |
| `acl` (`setfacl`)                | `apt-get install acl`                        | `/usr/bin/setfacl`                                                      | Pour permissions par défaut `/opt/darkmoon/scripts`                            |
| Subfinder | go install | énumération sous-domaines |
| vulnx | go install | Modern CLI for exploring vulnerability |
| lightpanda | téléchargé via lasted release | Lightpanda: the headless browser designed for AI and automation |


## “outils” installés par `pip install impacket==0.12.0` (scripts fournis par Impacket)

Ces scripts sont installés comme commandes dans `/opt/darkmoon/python/bin/` (donc dans le `PATH`).

| Outil (commande)     | Source / méthode | Emplacement                                   | Notes                               |
| -------------------- | ---------------- | --------------------------------------------- | ----------------------------------- |
| `secretsdump.py`     | pip (impacket)   | `/opt/darkmoon/python/bin/secretsdump.py`     | Dump secrets AD                     |
| `wmiexec.py`         | pip (impacket)   | `/opt/darkmoon/python/bin/wmiexec.py`         | Exec WMI                            |
| `psexec.py`          | pip (impacket)   | `/opt/darkmoon/python/bin/psexec.py`          | Exec via SMB service                |
| `smbexec.py`         | pip (impacket)   | `/opt/darkmoon/python/bin/smbexec.py`         | Exec SMB                            |
| `atexec.py`          | pip (impacket)   | `/opt/darkmoon/python/bin/atexec.py`          | Exec via AT scheduler               |
| `dcomexec.py`        | pip (impacket)   | `/opt/darkmoon/python/bin/dcomexec.py`        | Exec DCOM                           |
| `mssqlclient.py`     | pip (impacket)   | `/opt/darkmoon/python/bin/mssqlclient.py`     | Client MSSQL                        |
| `smbclient.py`       | pip (impacket)   | `/opt/darkmoon/python/bin/smbclient.py`       | SMB client (en plus de ton wrapper) |
| `lookupsid.py`       | pip (impacket)   | `/opt/darkmoon/python/bin/lookupsid.py`       | RID/SID enum                        |
| `GetADUsers.py`      | pip (impacket)   | `/opt/darkmoon/python/bin/GetADUsers.py`      | Enum users AD                       |
| `GetNPUsers.py`      | pip (impacket)   | `/opt/darkmoon/python/bin/GetNPUsers.py`      | AS-REP roast                        |
| `GetUserSPNs.py`     | pip (impacket)   | `/opt/darkmoon/python/bin/GetUserSPNs.py`     | Kerberoast                          |
| `ticketer.py`        | pip (impacket)   | `/opt/darkmoon/python/bin/ticketer.py`        | Golden/Silver tickets               |
| `raiseChild.py`      | pip (impacket)   | `/opt/darkmoon/python/bin/raiseChild.py`      | Trust abuse                         |
| `addcomputer.py`     | pip (impacket)   | `/opt/darkmoon/python/bin/addcomputer.py`     | Add machine account                 |
| `changepasswd.py`    | pip (impacket)   | `/opt/darkmoon/python/bin/changepasswd.py`    | Change password                     |
| `getPac.py`          | pip (impacket)   | `/opt/darkmoon/python/bin/getPac.py`          | Kerberos PAC                        |
| `getTGT.py`          | pip (impacket)   | `/opt/darkmoon/python/bin/getTGT.py`          | Kerberos TGT                        |
| `getST.py`           | pip (impacket)   | `/opt/darkmoon/python/bin/getST.py`           | Kerberos ST                         |
| `klistattack.py`     | pip (impacket)   | `/opt/darkmoon/python/bin/klistattack.py`     | Kerberos attack helper              |
| `samrdump.py`        | pip (impacket)   | `/opt/darkmoon/python/bin/samrdump.py`        | SAMR enum                           |
| `reg.py`             | pip (impacket)   | `/opt/darkmoon/python/bin/reg.py`             | Remote registry ops                 |
| `netview.py`         | pip (impacket)   | `/opt/darkmoon/python/bin/netview.py`         | Network view                        |
| `services.py`        | pip (impacket)   | `/opt/darkmoon/python/bin/services.py`        | Service control                     |
| `eventquery.py`      | pip (impacket)   | `/opt/darkmoon/python/bin/eventquery.py`      | Event logs                          |
| `dpapi.py`           | pip (impacket)   | `/opt/darkmoon/python/bin/dpapi.py`           | DPAPI ops                           |
| `ntlmrelayx.py`      | pip (impacket)   | `/opt/darkmoon/python/bin/ntlmrelayx.py`      | NTLM relay                          |
| `smbserver.py`       | pip (impacket)   | `/opt/darkmoon/python/bin/smbserver.py`       | SMB server                          |
| `rbcd.py`            | pip (impacket)   | `/opt/darkmoon/python/bin/rbcd.py`            | RBCD abuse                          |
| `findDelegation.py`  | pip (impacket)   | `/opt/darkmoon/python/bin/findDelegation.py`  | Delegation enum                     |
| `GetLAPSPassword.py` | pip (impacket)   | `/opt/darkmoon/python/bin/GetLAPSPassword.py` | LAPS retrieval                      |
| `keylistattack.py`   | pip (impacket)   | `/opt/darkmoon/python/bin/keylistattack.py`   | Keylist attack                      |
| `ping.py`            | pip (impacket)   | `/opt/darkmoon/python/bin/ping.py`            | Ping PoC (impacket)                 |
| `sniffer.py`         | pip (impacket)   | `/opt/darkmoon/python/bin/sniffer.py`         | Sniffer helper                      |

---

# BONUS: Laboratoire de pentester pour entrainer DarkMoon

---

## 1. WEB / API / GRAPHQL / FRONTEND

| Infrastructure | Protocoles     | Services / Tech        | Engine Darkmoon        | Labs équivalents                       |
| -------------- | -------------- | ---------------------- | ---------------------- | -------------------------------------- |
| Web classique  | HTTP / HTTPS   | Apache, Nginx, IIS     | engine_infra_web       | **OWASP Juice Shop**                   |
| API REST       | HTTP / JSON    | Express, Spring, Flask | engine_web_api         | **OWASP crAPI**, **VAPI**              |
| GraphQL        | HTTP / GraphQL | Apollo, Graphene       | engine_web_graphql     | **DVGA**, **GraphQL-Goat**             |
| Auth Web       | HTTP / JWT     | OAuth2, SSO            | engine_web_auth        | **AuthLab**, **JWT-Goat**              |
| CMS            | HTTP           | WordPress, Joomla      | engine_web_cms         | **WPScan VulnLab**, **HackTheBox CMS** |
| Frontend JS    | HTTP           | React, Angular         | engine_web_frontend_js | **DOM XSS Labs**, **PortSwigger**      |
| File Upload    | HTTP multipart | PHP, Node              | engine_web_upload      | **Upload Vulnerable Labs**             |
| WAF / Proxy    | HTTP           | Cloudflare, Akamai     | engine_web_waf_bypass  | **WAF Evasion Labs**                   |
| CI/CD Web      | HTTP / Git     | GitLab CI              | engine_web_ci_cd       | **GitHub Actions Labs**                |

---

## 2. ACTIVE DIRECTORY / WINDOWS

| Infrastructure | Protocoles   | Services    | Engine Darkmoon    | Labs équivalents                      |
| -------------- | ------------ | ----------- | ------------------ | ------------------------------------- |
| Domaine AD     | Kerberos     | KDC         | engine_ad_kerberos | **AttackDefense AD**, **HTB AD Labs** |
| SMB            | SMBv1/v2     | File Shares | engine_ad_smb      | **VulnAD**, **GOAD**                  |
| LDAP           | LDAP / LDAPS | Directory   | engine_ad_ldap     | **LDAP Injection Labs**               |
| DNS AD         | DNS          | SRV records | engine_ad_dns_srv  | **AD DNS Labs**                       |
| ADCS           | RPC / HTTP   | PKI         | engine_ad_adcs     | **ADCS Abuse Labs**                   |
| GPO            | SMB          | SYSVOL      | engine_ad_gpo      | **BloodHound Labs**                   |
| Lateral Move   | RPC          | WinRM / WMI | engine_ad_privesc  | **Proving Grounds AD**                |

---

## 3. NETWORK / INFRASTRUCTURE

| Infrastructure | Protocoles    | Services    | Engine Darkmoon            | Labs équivalents                 |
| -------------- | ------------- | ----------- | -------------------------- | -------------------------------- |
| DNS            | UDP/TCP 53    | Bind        | engine_proto_dns           | **DNSGoat**, **PortSwigger DNS** |
| FTP            | TCP 21        | vsftpd      | engine_proto_ftp           | **VulnFTP**, **HTB FTP**         |
| SSH            | TCP 22        | OpenSSH     | engine_proto_ssh_telnet    | **SSH Weak Labs**                |
| SNMP           | UDP 161       | SNMPv2      | engine_proto_snmp          | **SNMP Labs**                    |
| Mail           | SMTP/IMAP     | Postfix     | engine_proto_mail_services | **MailGoat**                     |
| VPN            | IPsec/OpenVPN | VPN Gateway | engine_proto_vpn_access    | **VPN Labs**                     |
| Wi-Fi          | 802.11        | WPA2        | engine_proto_wifi          | **WiFi Pineapple Labs**          |
| RDP/VNC        | TCP 3389      | RDP         | engine_proto_rdp_vnc       | **BlueKeep Labs**                |
| ICMP           | ICMP          | Tunnel      | engine_proto_icmp_tunnel   | **ICMP Tunnel Labs**             |
| BGP/OSPF       | TCP/UDP       | Routing     | engine_proto_bgp_ospf      | **Routing Attack Labs**          |

---

## 4. CLOUD (AWS / AZURE / GCP / OVH)

| Infrastructure | Protocoles   | Services         | Engine Darkmoon                | Labs équivalents               |
| -------------- | ------------ | ---------------- | ------------------------------ | ------------------------------ |
| IAM            | HTTPS        | Roles / Policies | engine_cloud_iam               | **Flaws.cloud**, **CloudGoat** |
| Compute        | HTTPS        | EC2 / VM         | engine_cloud_compute           | **AWSGoat**                    |
| Storage        | HTTPS        | S3 / Blob        | engine_cloud_storage           | **S3Goat**                     |
| Metadata       | HTTP 169.254 | IMDS             | engine_cloud_metadata_exposure | **IMDS Labs**                  |
| Containers     | HTTPS        | EKS / GKE        | engine_cloud_containers        | **KubeGoat**                   |
| CI/CD          | HTTPS        | Pipelines        | engine_cloud_ci_cd             | **CI/CD Goat**                 |
| Serverless     | HTTPS        | Lambda           | engine_cloud_serverless        | **LambdaGoat**                 |
| Secrets        | HTTPS        | Vault            | engine_cloud_secret_management | **Secrets Goat**               |
| Billing Abuse  | HTTPS        | Billing API      | engine_cloud_billing_abuse     | **Cloud Abuse Labs**           |

---

## 5. IOT / EMBEDDED / SCADA / ICS

| Infrastructure | Protocoles | Services   | Engine Darkmoon             | Labs équivalents           |
| -------------- | ---------- | ---------- | --------------------------- | -------------------------- |
| PLC            | Modbus/TCP | Automation | engine_proto_modbus         | **ModbusPal**, **ICSGoat** |
| SCADA          | DNP3       | Energy     | engine_proto_dnp3           | **DNP3 Labs**              |
| MQTT           | TCP 1883   | Broker     | engine_proto_mqtt           | **MQTTGoat**               |
| CoAP           | UDP        | IoT        | engine_proto_coap           | **CoAP Labs**              |
| ZigBee         | 802.15.4   | Mesh       | engine_proto_zigbee         | **ZigBee Labs**            |
| BLE            | BLE        | GATT       | engine_proto_ble            | **BLEGoat**                |
| Firmware       | Raw        | Binwalk    | engine_firmware_binwalk     | **OWASP IoT Goat**         |
| Hardware       | UART/JTAG  | Debug      | engine_hw_jtag_uart         | **Hardware Hacking Labs**  |
| ICS Auth       | Custom     | HMI        | engine_scada_authentication | **ICS Auth Labs**          |

---

## 6. ORCHESTRATION MULTI-INFRA (RARE & CRITIQUE)

| Infrastructure mixte | Déclenchement  | Engine                           | Labs                  |
| -------------------- | -------------- | -------------------------------- | --------------------- |
| Web + AD             | LDAP leak      | engine_infra_global_orchestrator | **HTB Hybrid Labs**   |
| Web + Cloud          | SSRF → IMDS    | engine_infra_global_orchestrator | **SSRF → AWS Labs**   |
| VPN + AD             | Split tunnel   | engine_infra_network + AD        | **Corp Network Labs** |
| IoT + Cloud          | MQTT bridge    | engine_infra_embedded + cloud    | **IoT Cloud Labs**    |
| CI/CD + Cloud        | Pipeline abuse | engine_global                    | **Supply Chain Labs** |

---
