# ThreatHunter Platform
 
> **Threat Hunting Réseau** — Analyse de trafic et détection de comportements suspects via Wireshark/Zeek, enrichie par des flux CTI open-source (MISP + OpenCTI connectés · matching amont + enrichissement aval)
 
![Status](https://img.shields.io/badge/Status-Pipeline%20complet-blue)
![Phase](https://img.shields.io/badge/Phase-Développement%20avancé-blueviolet)
![Stage](https://img.shields.io/badge/Stage-Cybersécurité-navy)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)
![Zeek](https://img.shields.io/badge/Zeek-6.x%20LTS-orange)
![Engines](https://img.shields.io/badge/Engines-50%20%2F%2050-informational)
![MISP](https://img.shields.io/badge/MISP-connecté-red)
![OpenCTI](https://img.shields.io/badge/OpenCTI-connecté%20·%20amont%20%2B%20aval-brightgreen)
![MongoDB](https://img.shields.io/badge/MongoDB-déployé%20·%20mongo%3A7.0-brightgreen)
![Dashboard](https://img.shields.io/badge/Dashboard-8%20pages%20·%20auth-success)
![License](https://img.shields.io/badge/License-Open%20Source-brightgreen)
 
---
 
## 📋 Table des matières
 
- [Vue d'ensemble](#-vue-densemble)
- [Statut d'avancement](#-statut-davancement)
- [Architecture](#-architecture)
- [Pipeline en 10 étapes (architecture figée)](#-pipeline-en-10-étapes-architecture-figée)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
  - [Étape 1 — Réseau VMware Fusion](#étape-1--réseau-vmware-fusion)
  - [Étape 2 — VM ThreatHunter Server](#étape-2--vm-threathunter-server-10)
  - [Étape 3 — VM MISP Server](#étape-3--vm-misp-server-20)
  - [Étape 4 — VM Victim Server](#étape-4--vm-victim-server-30)
  - [Étape 5 — VM Kali Linux](#étape-5--vm-kali-linux-40)
  - [Étape 6 — VM OpenCTI Server](#étape-6--vm-opencti-server-50)
  - [Étape 7 — Durcissement SSH (clés)](#étape-7--durcissement-ssh-clés)
  - [Étape 8 — Validation du lab](#étape-8--validation-du-lab)
- [Structure du projet](#-structure-du-projet)
- [Couches de traitement](#-couches-de-traitement)
- [Modules de détection](#-modules-de-détection)
- [Threat Intelligence Layer](#-threat-intelligence-layer)
- [Utilisation](#-utilisation)
- [Dashboard Streamlit](#-dashboard-streamlit)
- [Scénarios de démonstration](#-scénarios-de-démonstration)
- [Roadmap](#-roadmap)
- [Glossaire](#-glossaire)
---
 
## 🎯 Vue d'ensemble
 
**ThreatHunter Platform** est une plateforme de Threat Hunting réseau développée dans le cadre d'un stage en cybersécurité. Elle permet de :
 
- **Capturer et analyser le trafic réseau** via tcpdump (PCAP/PCAPng), Zeek et Wireshark
- **Calculer des caractéristiques comportementales** (entropie, jitter, ports, volume) dans une couche *Feature Extraction* dédiée
- **Détecter proactivement** des comportements suspects via un *Detection Engine* modulaire — **50 détecteurs (engines) actifs**, catalogue complet (7 familles couvrant le cycle d'attaque)
- **Enrichir les alertes** avec de la Cyber Threat Intelligence open-source via une *Threat Intelligence Layer* abstraite (**MISP + OpenCTI connectés**) — OpenCTI agrège 3 sources (MISP · AlienVault · CVE) et intervient **en amont** (matching des IOC connus avant détection) **et en aval** (enrichissement du contexte après détection)
- **Corréler et qualifier** les alertes (severity · confidence · risk score · MITRE ATT&CK) — **intégré au pipeline**, pour se rapprocher d'un vrai workflow SOC
- **Stocker** les alertes dans une base NoSQL **MongoDB** *(déployée · `mongo:7.0` · migration depuis SQLite réalisée et validée)*
- **Visualiser** les résultats dans un dashboard Streamlit **thémé et authentifié à 8 pages**, avec un module de filtres globaux
### Pourquoi ce projet ?
 
Les solutions de détection traditionnelles (antivirus, IDS basés sur signatures) ne détectent pas les menaces avancées qui restent silencieuses pendant des semaines. Le Threat Hunting proactif part du principe que **l'attaquant est déjà là** et cherche des preuves de sa présence avant toute alerte automatique.
 
> **Note de conception** : l'architecture est **figée**. Tous les documents (cahier des charges, rapport, slides, dépôt) racontent la même histoire, et chaque bloc du schéma existe réellement dans le code. **La Corrélation et la Qualification sont intégrées** au pipeline (entre l'enrichissement CTI et le stockage). **MongoDB** est **déployé** (`mongo:7.0`) et la couche de stockage a été **migrée de SQLite vers MongoDB**. **OpenCTI** est **connecté au pipeline** : son connecteur (`cti/opencti.py`, pycti 7.x) est branché au `CTIManager` aux côtés de MISP, et OpenCTI agrège lui-même 3 sources (MISP · AlienVault · CVE). La CTI intervient désormais **dans les deux sens** : un **matching en amont** (`cti/upstream_matcher.py`) identifie les IOC déjà connus **avant** la détection comportementale, et l'**enrichissement en aval** ajoute le contexte de menace **après** la détection. Le seuil de malveillance est **calibré empiriquement** sur les feeds réels (score ≥ 50 ou présence d'un label de menace ; les observables neutres à score 30 sont écartés), avec un filtre d'infrastructure (mDNS/multicast/domaines légitimes). L'**export PDF (ReportLab)** est disponible, aux côtés de l'export CSV/JSON dans la page *Reports*.
 
---
 
## 📌 Statut d'avancement
 
> Mise à jour : Août 2026
 
| Bloc | État | Détail |
|------|------|--------|
| **Lab virtualisé (5 VMs)** | ✅ Opérationnel | vmnet2 · IP fixes · connectivité validée |
| **Durcissement SSH (clés)** | ✅ Appliqué | Authentification par clés RSA / Ed25519 |
| **Zeek** | ✅ Installé | Génération de logs sur PCAP/PCAPng validée |
| **MISP + flux CTI** | ✅ Connecté | Instance Docker + 5 flux CTI configurés |
| **OpenCTI** | ✅ Connecté | Connecteur `opencti.py` (pycti 7.x) branché au CTIManager · hub 3 sources (MISP·AlienVault·CVE) · enrichissement validé |
| **Matching CTI amont** | ✅ Implémenté | `upstream_matcher.py` · IOC connus détectés avant l'analyse comportementale · seuil calibré (score≥50 / labels) · filtre d'infrastructure |
| **MongoDB** | ✅ Déployé | `mongo:7.0` · migration SQLite → MongoDB validée · collections `alerts` · `ioc_cache` · `history` |
| **Feature Extraction** | ✅ Implémenté | entropie · jitter · ports · volume · consommé par les détecteurs |
| **Detection Engine** | ✅ 50 engines | Orchestrateur + 50 détecteurs (7 familles · Reconnaissance 8/8) · `len(app.DETECTORS) == 50` |
| **Alert Correlation / Qualification** | ✅ Intégré | Regroupement (même IP + période) + severity/confidence/risk/ATT&CK — câblé dans `app.py` |
| **Dashboard** | ✅ 8 pages · auth | Thème SOC (Keystone) · login bcrypt · filtres globaux · mode dégradé |
| **Rapports** | ✅ CSV/JSON/PDF | Export CSV + JSON + PDF (ReportLab) depuis la page Reports |
 
**Prochaine étape** : générer les captures dédiées pour documenter chaque engine sur trafic réel, et affiner les seuils heuristiques de la famille DNS/DGA.
 
---
 
## 🏗️ Architecture
 
### Architecture en 4 couches
 
```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                       │
│   Dashboard Streamlit (8 pages · thémé · authentifié)      │
│   Filtres globaux Threat Control · Export CSV/JSON/PDF     │
└─────────────────────────────────────────────────────────────┘
                              ▲
┌─────────────────────────────────────────────────────────────┐
│                     Business Layer                          │
│   Matching CTI amont · Feature Extraction                  │
│   Detection Engine (50 détecteurs)                         │
│   Threat Intelligence Layer (MISP · OpenCTI · connectés)   │
│   Alert Correlation · Alert Qualification (intégrées)      │
└─────────────────────────────────────────────────────────────┘
                              ▲
┌─────────────────────────────────────────────────────────────┐
│                      Data Layer                             │
│      MongoDB · MISP · OpenCTI · Zeek Logs · PCAP/PCAPng    │
└─────────────────────────────────────────────────────────────┘
                              ▲
┌─────────────────────────────────────────────────────────────┐
│                  Infrastructure Layer                       │
│    VMware Fusion · Ubuntu VMs · Kali Linux · vmnet2        │
└─────────────────────────────────────────────────────────────┘
```
 
### Infrastructure du laboratoire
 
```
MacBook Pro M1 — 32 GB RAM — VMware Fusion 13
│
└── Host-Only Network : vmnet2 — 192.168.100.0/24   (auth SSH par clés)
    │
    ├── ThreatHunter Server   192.168.100.10   4 GB (6 GB conseillé)
    │     Ubuntu 22.04 · Zeek · Python · Feature Extraction
    │     Detection Engine · Streamlit · MongoDB (Docker — mongo:7.0)
    │     (+ swapfile 4 Go — marge mémoire pour les gros PCAP)
    │
    ├── MISP Server           192.168.100.20   4 GB
    │     Ubuntu 22.04 · Docker · MISP · MariaDB · valkey
    │
    ├── Victim Server         192.168.100.30   2 GB
    │     Ubuntu 22.04 · Apache · SSH · FTP · DNS
    │
    ├── Attack & Traffic      192.168.100.40   2 GB
    │     Simulator (Kali)
    │     Nmap · Hydra · Scapy · Metasploit
    │
    └── OpenCTI Server        192.168.100.50   8 GB
          Ubuntu 22.04 · Docker · OpenCTI 7.x (platform + worker)
          Elasticsearch · Redis · MinIO · RabbitMQ
          Connecteurs : MISP · AlienVault · CVE
 
macOS (natif — hors VMs)
    Wireshark / tshark · VS Code · Git · Documentation
```
 
> **Précision capture (à clarifier en soutenance)** : Wireshark est installé sur la station d'analyse **macOS** (l'hôte), pas à l'intérieur des VMs. La capture entre VMs se fait avec **tcpdump** au niveau des VMs (production des PCAP/PCAPng) ; les fichiers sont ensuite exploités avec Wireshark sur le Mac pour la visualisation.
 
---
 
## 🔄 Pipeline en 10 étapes (architecture figée)
 
La chaîne suit une logique d'**entonnoir** : le volume de données diminue à chaque étape pendant que la pertinence augmente.
 
| # | Étape | Rôle | Outil / Techno |
|---|-------|------|----------------|
| 1 | **Capture du trafic** | Acquisition du trafic réseau du lab | tcpdump → PCAP/PCAPng, exploité avec Wireshark |
| 2 | **Analyse réseau** | Génération de logs structurés | Zeek (conn · dns · ssl · http · files) |
| 3 | **Feature Extraction** | Calcul des caractéristiques comportementales | Python (pandas) |
| 4 | **Detection Engine** | Exécution des détecteurs | Python (**50 détecteurs**) |
| 5 | **Threat Intelligence** | Matching amont (IOC connus) + enrichissement aval | MISP + OpenCTI (PyMISP · pycti) |
| 6 | **Alert Correlation** | Regroupement des alertes liées | Python *(intégré)* |
| 7 | **Alert Qualification** | Severity · confidence · risk score · ATT&CK | Python *(intégré)* |
| 8 | **Stockage** | Persistance des alertes | MongoDB `mongo:7.0` (Docker Compose) |
| 9 | **Dashboard** | Visualisation des alertes qualifiées | Streamlit + Plotly (8 pages · auth) |
| 10 | **Rapports & export** | Génération de rapports | CSV / JSON / PDF (ReportLab) |
 
### Schéma du pipeline
 
```
Attack & Traffic Simulator (Kali .40)
            │  attaques / trafic simulé
            ▼
    Victim Services (.30) — Apache · SSH · FTP · DNS
            │  trafic réseau généré
            ▼
┌─────────────────────────────────────────────────────────┐
│              ThreatHunter Platform (.10)                 │
│                                                         │
│  ①  Capture     tcpdump → capture.pcap / .pcapng       │
│         ▼                                               │
│  ②  Zeek        conn·dns·http·ssl·files.log            │
│         ▼                                               │
│  ③  Feature Extraction   entropie·jitter·ports·volume │
│         ▼                                               │
│  ④  Detection Engine     50 détecteurs                 │
│         ▼                (Recon · BruteForce · Beaconing│
│                          · Exfil · Tunneling · Latéral  │
│                          · Anomalies DNS/DGA)           │
│  ⑤  Threat Intelligence Layer  (MISP + OpenCTI)        │
│         ├── AMONT : matching des IOC connus            │
│         │           (avant détection) → alerte CTI    │
│         └── AVAL  : enrichissement du contexte        │
│         ▼           (après détection)                 │
│  ⑥  Alert Correlation    même IP + même période        │
│         ▼                → un incident unique          │
│  ⑦  Alert Qualification  severity·confidence·         │
│         ▼                risk score·MITRE ATT&CK       │
│  ⑧  MongoDB (mongo:7.0)  collections alerts ·         │
│         ▼                ioc_cache · history           │
│  ⑨  Dashboard            Streamlit (8 pages · auth ·  │
│         ▼                filtres globaux)              │
│  ⑩  Rapports & export    CSV / JSON / PDF             │
└─────────────────────────────────────────────────────────┘
 
        ┌───────────────────────────────────────────────┐
        │   OpenCTI Server (.50) — hub CTI 3 sources    │
        │   MISP · AlienVault · CVE → API STIX          │
        │   interrogé par ⑤ (amont + aval)              │
        └───────────────────────────────────────────────┘
```
 
> **Architecture CTI en amont + aval (implémentée)** : un **matching CTI en amont** (`cti/upstream_matcher.py`) repère les IOC déjà connus **avant** la détection comportementale, en complément de l'**enrichissement CTI en aval** (`cti/enrichment.py`) qui ajoute le contexte **après** la détection. Les deux sens sont opérationnels et interrogent OpenCTI (hub agrégeant MISP · AlienVault · CVE) via le `CTIManager`. Le matching amont applique un filtre d'infrastructure (mDNS/multicast/domaines légitimes) et un seuil de malveillance calibré sur les feeds réels (score ≥ 50 ou label de menace).
 
### Modes de fonctionnement
 
| Mode | Description | Méthode | Statut |
|------|-------------|---------|--------|
| **V1 — Offline PCAP/PCAPng** | Analyse de captures préenregistrées | `zeek -r capture.pcapng` | ✅ Principal · Garanti |
| **V2 — Live Monitoring** | Analyse du trafic en temps réel | `zeek -i ens160` | 🔬 Bonus · À valider |
 
---
 
## 📦 Prérequis
 
### Machine hôte
 
| Composant | Requis | Recommandé |
|-----------|--------|------------|
| CPU | Apple M1 | Apple M1 Pro/Max |
| RAM | 16 GB | 32 GB |
| Stockage | 200 GB libre | 500 GB SSD |
| OS | macOS Ventura+ | macOS Sonoma+ |
| Virtualisation | VMware Fusion 13 | VMware Fusion 13 Pro |
 
### Fichiers à télécharger
 
```bash
# ISO Ubuntu Server 22.04 ARM64 (utilisé pour 4 VMs)
https://cdimage.ubuntu.com/releases/22.04/release/
→ ubuntu-22.04.x-live-server-arm64.iso
 
# Kali Linux ARM64 VMware (pré-construite)
https://www.kali.org/get-kali/#kali-virtual-machines
→ Choisir : VMware → Apple Silicon (ARM64)
```
 
### Stack logicielle
 
```
Zeek          6.x LTS      Analyse réseau
Python        3.10+        Feature extraction · détection · enrichissement
pandas        latest       Feature Extraction (caractéristiques)
MISP          2.4.x        Threat Intelligence (connecté)
OpenCTI       7.x          Threat Intelligence (connecté · hub 3 sources : MISP·AlienVault·CVE)
MongoDB       7.0          Stockage NoSQL des alertes (déployé · mongo:7.0 — voir note noyau)
Docker        24.x         Déploiement MISP + OpenCTI + MongoDB (Compose)
pymongo       latest       Client Python MongoDB
PyMISP        latest       API MISP Python
pycti         7.260817     Client Python OpenCTI (aligné sur la plateforme 7.x)
Streamlit     1.x          Dashboard
Plotly        latest       Graphiques du dashboard
bcrypt        latest       Authentification du dashboard (hash du mot de passe admin)
ReportLab     4.x          Export PDF
Wireshark     4.x          Visualisation des captures (macOS)
tshark        4.x          Inspection CLI des captures (macOS)
```
 
---
 
## 🚀 Installation
 
> **⚠️ Sécurité — secrets** : toutes les valeurs `<...>` ci-dessous sont des **placeholders**. Remplacez-les par vos propres mots de passe forts et **ne committez jamais** de secret réel dans le dépôt. Les vraies valeurs vivent uniquement dans le fichier `.env` (exclu via `.gitignore`).
 
### Étape 1 — Réseau VMware Fusion
 
```
1. VMware Fusion → Preferences → Network
2. Cliquer 🔒 → entrer mot de passe Mac
3. Cliquer "+" → nouveau réseau
 
Configuration :
  Name    : vmnet2
  Type    : Host-only
  Subnet  : 192.168.100.0
  Mask    : 255.255.255.0
  DHCP    : ❌ Désactivé
 
4. Apply → fermer
```
 
---
 
### Étape 2 — VM ThreatHunter Server (.10)
 
**Création de la VM :**
```
VMware Fusion → File → New → Install from disc or image
  ISO      : ubuntu-22.04-live-server-arm64.iso
  Nom      : TH-Monitoring
  CPU      : 2 cœurs
  RAM      : 4096 Mo   (6144 Mo recommandé avec le conteneur MongoDB)
  Disque   : 40 Go
  Réseau   : vmnet2
  Username : thunter
  Hostname : th-monitoring
  ✅ Cocher : Install OpenSSH server
```
 
**Configuration IP fixe :**
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
 
```yaml
network:
  version: 2
  ethernets:
    ens160:                    # adapter selon votre interface
      addresses:
        - 192.168.100.10/24
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```
 
```bash
sudo netplan apply
ip addr show    # → vérifier 192.168.100.10
```
 
**Installation Zeek :**
```bash
# Dépendances
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git flex bison libpcap-dev \
  libssl-dev python3 python3-pip wireshark tshark net-tools
 
# Dépôt Zeek officiel
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list
 
curl -fsSL \
  https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor \
  | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
 
sudo apt update && sudo apt install -y zeek
 
# PATH permanent
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
 
# Vérification
zeek --version    # → zeek version 6.x.x
```
 
> **Note ARM64** : si aucun paquet Zeek ARM64 n'est disponible pour votre version d'Ubuntu, basculer sur une **image Docker Zeek multi-architecture** (voir docs/Installation_Guide).
 
**Swap (marge mémoire pour les gros PCAP) :**
```bash
# Un swapfile de 4 Go évite que le noyau (OOM killer) tue le pipeline
# ou MongoDB lors de l'analyse de captures volumineuses.
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab   # permanent
free -h    # → Swap: 4.0Gi
```
 
**Déploiement MongoDB via Docker Compose** *(déployé sur le .10 — fichier `deploy/docker-compose.mongodb.yml`)* **:**
```bash
# Docker (si pas déjà installé)
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker && sudo systemctl start docker
sudo usermod -aG docker $USER && newgrp docker
 
# Conteneur MongoDB (image officielle multi-arch, compatible ARM64)
docker run -d --name th-mongo \
  -p 127.0.0.1:27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=thunter \
  -e MONGO_INITDB_ROOT_PASSWORD=<MOT_DE_PASSE_MONGO> \
  -v th-mongo-data:/data/db \
  --restart unless-stopped \
  mongo:7.0
 
docker ps | grep th-mongo    # → conteneur "Up"
```
 
> Renseigner ensuite l'URI dans le fichier `.env` (exclu du dépôt Git) :
> `MONGO_URI=mongodb://thunter:<MOT_DE_PASSE_MONGO_URL_ENCODE>@localhost:27017/?authSource=admin`
> *(les caractères spéciaux du mot de passe doivent être URL-encodés, ex. `@` → `%40`)*
>
> **Note noyau (difficulté rencontrée)** : l'image `mongo:8.0` refuse de démarrer sur les noyaux Linux **6.19 → 7.0.13** (incompatibilité TCMalloc — ticket MongoDB `SERVER-121912`). La VM `.10` tournant sur un noyau `7.0.0`, la plateforme est déployée en **`mongo:7.0`** (antérieure au changement, nativement ARM64, 100 % compatible pymongo et le connecteur `db.py`).
 
**Environnement Python :**
```bash
python3 -m venv ~/threathunt-env
source ~/threathunt-env/bin/activate
echo 'source ~/threathunt-env/bin/activate' >> ~/.bashrc
 
pip install pymisp pymongo pandas streamlit plotly \
  requests reportlab matplotlib bcrypt
# pycti (client OpenCTI) — aligner la version sur la plateforme OpenCTI (7.x)
pip install "pycti==7.260817.0"   # adapter au numéro exact de votre instance OpenCTI
```
 
**Compte admin du dashboard (authentification) :**
```bash
cd ~/ThreatHunter
python -m dashboard.pages.auth --create-admin
# → saisir un identifiant + un mot de passe (min 8 caractères)
# → écrit ADMIN_USERNAME et ADMIN_PASSWORD_HASH (hash bcrypt) dans .env
```
 
---
 
### Étape 3 — VM MISP Server (.20)
 
**Création de la VM :**
```
  Nom      : TH-MISP
  CPU      : 2 cœurs
  RAM      : 4096 Mo
  Disque   : 40 Go
  Réseau   : vmnet2
  Username : mispuser
  Hostname : th-misp
```
 
**IP fixe :**
```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    ens160:
      addresses:
        - 192.168.100.20/24
      nameservers:
        addresses: [8.8.8.8]
```
 
**Déploiement MISP via Docker :**
```bash
sudo apt install -y docker.io docker-compose git
sudo systemctl enable docker && sudo systemctl start docker
sudo usermod -aG docker $USER && newgrp docker
 
git clone https://github.com/MISP/misp-docker.git
cd misp-docker && cp template.env .env
nano .env
```
 
```env
MISP_BASEURL=https://192.168.100.20
MISP_ADMIN_PASSPHRASE=<MOT_DE_PASSE_ADMIN_MISP>
MYSQL_PASSWORD=<MOT_DE_PASSE_MARIADB>
MYSQL_ROOT_PASSWORD=<MOT_DE_PASSE_MARIADB_ROOT>
```
 
```bash
docker-compose up -d
docker-compose ps    # → tous les services "Up" (attendre 3-5 min)
```
 
**Accès MISP :**
```
URL      : https://192.168.100.20
Login    : admin@admin.test
Password : <MOT_DE_PASSE_ADMIN_MISP>
```
 
**Flux CTI à configurer (Sync Actions → Feeds → Add Feed) :**
 
| Flux | URL | Format |
|------|-----|--------|
| CIRCL OSINT | `https://www.circl.lu/doc/misp/feed-osint/` | MISP |
| URLhaus | `https://urlhaus.abuse.ch/downloads/misp/` | MISP |
| FeodoTracker | `https://feodotracker.abuse.ch/downloads/misp.json` | MISP JSON |
| MalwareBazaar | `https://bazaar.abuse.ch/export/misp/full/` | MISP |
| ThreatFox | `https://threatfox.abuse.ch/downloads/misp/` | MISP |
 
> **Note abuse.ch** : les exports abuse.ch peuvent nécessiter un **Auth-Key** gratuit sur `https://auth.abuse.ch/`. Générez le vôtre si un flux ne se synchronise pas.
 
**Générer la clé API :**
```
Administration → List Users → admin
→ Auth keys → Add authentication key → copier et sauvegarder
```
 
---
 
### Étape 4 — VM Victim Server (.30)
 
**Création de la VM :**
```
  Nom      : TH-Victim
  CPU      : 2 cœurs
  RAM      : 2048 Mo
  Disque   : 30 Go
  Réseau   : vmnet2
  Username : victim
  Hostname : th-victim
  IP fixe  : 192.168.100.30/24
```
 
**Installation des services :**
```bash
sudo apt update
sudo apt install -y apache2 openssh-server vsftpd dnsmasq
 
sudo systemctl enable apache2 ssh vsftpd
sudo systemctl start apache2 ssh vsftpd
 
curl http://192.168.100.30    # → page Apache par défaut
ssh victim@192.168.100.30     # → connexion SSH OK
```
 
---
 
### Étape 5 — VM Kali Linux (.40)
 
**Import de la VM :**
```
VMware Fusion → File → Open → sélectionner le .vmx Kali ARM64
  RAM    : 2048 Mo
  Réseau : vmnet2
  Login  : kali / kali
```
 
**Configuration IP fixe :**
```bash
sudo nano /etc/network/interfaces
```
 
```
auto eth0
iface eth0 inet static
    address 192.168.100.40
    netmask 255.255.255.0
```
 
```bash
sudo systemctl restart networking
ip addr show    # → 192.168.100.40
```
 
**Vérification des outils :**
```bash
nmap --version
hydra --version
python3 -c "import scapy; print('Scapy OK')"
msfconsole --version
```
 
---
 
### Étape 6 — VM OpenCTI Server (.50)
 
OpenCTI est déployé sur une **VM dédiée** (stack lourde : Elasticsearch, Redis, MinIO, RabbitMQ, worker). Il agrège plusieurs sources CTI et expose une **API STIX unique** interrogée par le pipeline.
 
**Création de la VM :**
```
  Nom      : TH-OpenCTI
  CPU      : 4 cœurs
  RAM      : 8192 Mo   (OpenCTI + Elasticsearch sont gourmands)
  Disque   : 60 Go
  Réseau   : vmnet2
  Username : opencti
  Hostname : th-opencti
  IP fixe  : 192.168.100.50/24
```
 
**Déploiement OpenCTI via Docker Compose :**
```bash
sudo apt install -y docker.io docker-compose git
sudo systemctl enable docker && sudo systemctl start docker
sudo usermod -aG docker $USER && newgrp docker
 
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker && cp .env.sample .env
nano .env      # définir OPENCTI_ADMIN_EMAIL, OPENCTI_ADMIN_PASSWORD,
               # OPENCTI_ADMIN_TOKEN (UUID), et les mots de passe des services
 
# IMPORTANT : exposer la plateforme sur le réseau du lab (pas seulement localhost)
# afin que la VM .10 puisse joindre l'API :
#   ports: - "0.0.0.0:8080:8080"   (service "opencti" du docker-compose)
 
docker-compose up -d
docker-compose ps    # → services "Up" (démarrage complet : 3-5 min)
```
 
**Accès OpenCTI :**
```
URL      : http://192.168.100.50:8080/dashboard
API      : http://192.168.100.50:8080/graphql
Token    : valeur de OPENCTI_ADMIN_TOKEN (.env)
```
 
**Connecteurs CTI (3 sources alimentant le hub) :** ajouter, dans le `docker-compose` des connecteurs OpenCTI, au minimum :
 
| Connecteur | Rôle |
|------------|------|
| **MISP** | Importe les événements/attributs MISP dans OpenCTI |
| **AlienVault OTX** | Pulses et IOC AlienVault |
| **CVE (MITRE)** | Base de vulnérabilités CVE |
 
> Vérification (dans l'interface) : *Data → Ingestion → Connectors* → les 3 connecteurs doivent être **🟢 Actifs**. Le dashboard OpenCTI doit afficher des indicateurs, malwares, rapports et vulnérabilités réels.
 
**Connexion depuis la plateforme (.10) — variables `.env` :**
```env
# ~/ThreatHunter/.env (VM .10)
OPENCTI_URL=http://192.168.100.50:8080
OPENCTI_TOKEN=<VOTRE_TOKEN_ADMIN_OPENCTI>
OPENCTI_SSL_VERIFY=false
OPENCTI_ENABLED=true
```
 
**Test de bout en bout (depuis la .10) :**
```bash
cd ~/ThreatHunter
# Le connecteur lit l'URL/token depuis .env et interroge le hub
python3 -m cti.opencti
# → [OpenCTI] connecté ... / connected = True / observables réels listés
```
 
> **Threat Intelligence Layer** : MISP et OpenCTI implémentent la même interface abstraite (`cti/base_cti.py`) et sont interrogés en parallèle par le `CTIManager`. OpenCTI agrège MISP · AlienVault · CVE, donc une seule requête OpenCTI donne accès aux trois sources. Le mode dégradé est validé : si MISP (`.20`) est injoignable, le pipeline continue avec OpenCTI seul.
 
---
 
### Étape 7 — Durcissement SSH (clés)
 
L'accès aux VMs se fait par **authentification SSH par clés** (RSA / Ed25519), plus par mot de passe — cohérent avec l'approche défensive du projet.
 
```bash
# Sur le Mac (hôte) — générer une paire de clés
ssh-keygen -t ed25519 -C "threathunter-lab"
 
# Copier la clé publique vers chaque VM
ssh-copy-id thunter@192.168.100.10
ssh-copy-id mispuser@192.168.100.20
ssh-copy-id victim@192.168.100.30
ssh-copy-id opencti@192.168.100.50
 
# Sur chaque VM — désactiver l'authentification par mot de passe
sudo nano /etc/ssh/sshd_config
#   PasswordAuthentication no
#   PubkeyAuthentication yes
sudo systemctl restart ssh
```
 
---
 
### Étape 8 — Validation du lab
 
Depuis **TH-Monitoring (.10)** :
 
```bash
# Connectivité
ping -c 3 192.168.100.20 && ping -c 3 192.168.100.30 \
  && ping -c 3 192.168.100.40 && ping -c 3 192.168.100.50
 
# Services
curl -k https://192.168.100.20                 # → MISP login page
curl http://192.168.100.30                      # → Apache default page
curl -s -X POST http://192.168.100.50:8080/graphql \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ about { version } }"}'        # → version OpenCTI
 
# Zeek (PCAP et PCAPng)
mkdir ~/zeek-test && cd ~/zeek-test
sudo tcpdump -i ens160 -w test.pcapng -G 30 -W 1
zeek -r test.pcapng
ls *.log    # → conn.log dns.log packet_filter.log
 
# MongoDB (le mot de passe est lu depuis $MONGO_URI / .env, jamais en dur)
python3 -c "
import os
from pymongo import MongoClient
c = MongoClient(os.environ['MONGO_URI'])
print('MongoDB OK :', c.server_info()['version'])
"
 
# PyMISP (la clé API est lue depuis .env)
python3 -c "
import os
from pymisp import PyMISP
m = PyMISP('https://192.168.100.20', os.environ['MISP_KEY'], False)
print('MISP OK :', m.misp_instance_version['version'])
"
 
# OpenCTI (via le connecteur du projet)
cd ~/ThreatHunter && python3 -m cti.opencti    # → connected = True
 
# Détecteurs actifs (doit afficher 50)
cd ~/ThreatHunter && python3 -c "import app; print('Détecteurs :', len(app.DETECTORS))"
```
 
**Checklist de validation :**
```
Infrastructure
  ☑ vmnet2 créé (192.168.100.0/24)
  ☑ ping .10 ↔ .20 ↔ .30 ↔ .40 ↔ .50 OK
  ☑ SSH par clés depuis Mac vers .10/.20/.30/.50 (mot de passe désactivé)
 
ThreatHunter Server (.10)
  ☑ zeek --version → 6.x ✓
  ☑ wireshark / tshark --version ✓
  ☑ swapfile 4 Go actif (free -h) ✓
  ☑ conteneur th-mongo "Up" (docker ps) ✓
  ☑ venv actif + PyMISP, pymongo, pycti, bcrypt importables ✓
  ☑ pandas disponible (Feature Extraction) ✓
  ☑ import app → 50 détecteurs ✓
 
MISP Server (.20)
  ☑ https://192.168.100.20 accessible ✓
  ☑ 5 flux CTI configurés et synchronisés ✓
  ☑ Clé API générée et sauvegardée ✓
 
Victim Server (.30)
  ☑ curl http://192.168.100.30 → HTML ✓
  ☑ ssh (clé) victim@192.168.100.30 → OK ✓
 
Kali (.40)
  ☑ nmap, hydra, scapy opérationnels ✓
 
OpenCTI Server (.50)
  ☑ http://192.168.100.50:8080/dashboard accessible ✓
  ☑ API GraphQL répond (version) ✓
  ☑ 3 connecteurs 🟢 Actifs (MISP · AlienVault · CVE) ✓
  ☑ python3 -m cti.opencti → connected = True ✓
 
Zeek
  ☑ zeek -r test.pcapng → conn.log généré (PCAP + PCAPng) ✓
  ☑ zeek-cut fonctionne sur conn.log ✓
 
MongoDB
  ☑ server_info() retourne la version ✓
  ☑ collections alerts / ioc_cache / history accessibles ✓
```
 
---
 
## 📁 Structure du projet
 
Organisation **en couches**, alignée sur le pipeline (arborescence réelle, à plat).
 
```
ThreatHunter/
│
├── config/
│     ├── __init__.py
│     └── settings.py           # Seuils, MONGO_URI, DB_NAME, CTI_FEEDS, ADMIN_*, OPENCTI_*, BASE_DIR
│
├── core/
│     ├── alerts.py             # Modèle Alert (dataclass) — risk_score, confidence, corrélation
│     ├── zeek_parser.py        # Exécution Zeek + parsing des journaux (TSV + JSON)
│     ├── feature_extractor.py  # ★ Feature Extraction (entropie · jitter · ports · volume)
│     └── engine.py             # ★ Detection Engine — orchestration des détecteurs
│
├── detectors/                  # ★ 50 détecteurs (héritent de BaseDetector)
│     ├── base_detector.py            # Classe abstraite BaseDetector
│     ├── port_scan.py … stealth_scan.py  # ENG-000 → 007 (Reconnaissance)
│     ├── brute_force.py              # ENG-008 (SSH)
│     ├── brute_force_services.py     # ENG-009 → 014 (FTP/RDP/SMB/Telnet/VNC/DB)
│     ├── beaconing.py                # ENG-015 (générique)
│     ├── beaconing_channels.py       # ENG-016 → 021 (HTTP/HTTPS/DNS/LongSleep/Jittered/NonStdPort)
│     ├── exfiltration.py             # ENG-022 (générique)
│     ├── exfiltration_channels.py    # ENG-023 → 028 (FTP/HTTP/HTTPS/SMTP/DNS/NonStdPort)
│     ├── dns_tunnel.py               # ENG-029 (générique)
│     ├── tunneling_channels.py       # ENG-030 → 035 (ICMP/SSH/HTTP/HTTPS/iodine/dnscat2)
│     ├── lateral_movement.py         # ENG-036 → 041 (RDP/SMB/DCOM/SSH/VNC/WinRM)
│     └── dns_anomalies.py            # ENG-042 → 049 (NXDOMAIN/entropie/TXT/NULL/fast-flux/fanout/ratio/rebinding)
│
├── cti/                        # ★ Threat Intelligence Layer (abstraite)
│     ├── base_cti.py           # Interface CTI générique (contrat commun)
│     ├── connector.py          # Connecteur MISP (PyMISP)
│     ├── opencti.py            # Connecteur OpenCTI (pycti 7.x · connecté)
│     ├── enrichment.py         # Enrichissement des alertes (CTI en AVAL)
│     ├── upstream_matcher.py   # ★ Matching des IOC connus (CTI en AMONT)
│     └── manager.py            # CTIManager — interroge et consolide les sources
│
├── correlation/
│     └── correlator.py         # ★ Alert Correlation (même IP + même période)
│
├── qualification/
│     └── qualifier.py          # ★ Alert Qualification (severity · confidence · risk · MITRE)
│
├── database/
│     └── db.py                 # MongoDB CRUD (pymongo) — alerts · ioc_cache · history
│
├── dashboard/
│     ├── main.py               # Point d'entrée Streamlit (routeur 8 pages)
│     ├── dashboard_data.py     # Couche données pure (KPIs, filtres, agrégations)
│     └── pages/
│           ├── theme.py        # Thème SOC centralisé (dark · Keystone)
│           ├── auth.py         # Authentification admin (bcrypt · .env)
│           └── keystone-logo-reduced.png
│
├── reports/
│     └── pdf_export.py         # Export PDF (ReportLab) — réutilise dashboard_data
├── deploy/                     # docker-compose.{mongodb,opencti}.yml
├── tests/                      # Tests unitaires (par couche)
├── pcap/                       # Fichiers PCAP / PCAPng par scénario
├── logs/                       # Logs Zeek reçus
├── docs/                       # Documentation technique
│
├── app.py                      # Pipeline principal (orchestrateur — DETECTORS)
├── .env                        # Secrets (MONGO_URI, clé API MISP, OPENCTI_*, ADMIN_*) — hors dépôt
├── .env.example                # Modèle de configuration (placeholders — SANS secret réel)
├── requirements.txt
└── README.md
```
 
★ = couches ajoutées après le retour de l'encadrant.
 
---
 
## 🧩 Couches de traitement
 
| Couche | Responsabilité | Entrée → Sortie |
|--------|----------------|-----------------|
| **Capture** | Acquisition du trafic | trafic réseau → PCAP/PCAPng |
| **Analysis (Zeek)** | Logs structurés | PCAP → conn/dns/http/ssl/files.log |
| **Feature Extraction** | Caractéristiques comportementales | logs → features (entropie · jitter · ports · volume) |
| **CTI Matching (amont)** | Repérage des IOC connus avant détection | logs → alertes CTI (IOC malveillants confirmés) |
| **Detection Engine** | Exécution des 50 détecteurs | features → alertes brutes |
| **Threat Intelligence (aval)** | Enrichissement CTI | alerte → alerte enrichie (MISP · OpenCTI) |
| **Correlation** | Regroupement des alertes liées | N alertes → 1 incident corrélé |
| **Qualification** | Scoring | alerte → severity · confidence · risk score · ATT&CK |
| **Database** | Persistance | alerte qualifiée → MongoDB |
| **Dashboard** | Visualisation | MongoDB → Streamlit + Plotly (8 pages) |
| **Report** | Export | alertes → CSV / JSON / PDF |
 
> **Feature Extraction** est la meilleure amélioration du projet : elle transforme la simple « lecture de logs » en véritable **analyse comportementale**, et c'est ce qui différencie la plateforme d'un simple parser Zeek.
 
---
 
## 🔍 Modules de détection
 
### Architecture orientée objet
 
```python
class BaseDetector(ABC):
    NAME: str = "BaseDetector"
    SEVERITY: str = "LOW"
    MITRE: str = ""
 
    @abstractmethod
    def analyze(self, logs: dict) -> List[Alert]: ...
    def make_alert(self, src_ip, description, dst_ip=None, evidence=None) -> Alert: ...
```
 
Tous les détecteurs héritent de `BaseDetector` et consomment les **features** calculées en amont (et non plus directement les logs Zeek). Ajouter un engine = un fichier dans `detectors/`, sans modifier le moteur.
 
### Détecteurs représentatifs (extrait)
 
> Le catalogue complet des 50 engines implémentés (IDs, familles, features, niveaux de validation) est détaillé dans **`ENGINES_STATUS.md`**.
 
| Détecteur | Feature source | Règle | Seuil | Sévérité | MITRE |
|-----------|----------------|-------|-------|----------|-------|
| `PortScanDetector` | ports distincts / source | count(distinct dst_ports) / min | > 50 ports/min | MEDIUM | T1046 |
| `BruteForceDetector` | échecs SSH | port 22 · conn_state REJ/S0 | > 10 échecs/min | HIGH | T1110 |
| `BeaconingDetector` | jitter | jitter = std(Δt) / mean(Δt) | < 10% jitter (intervalle ≥ 5s) | CRITICAL | T1071 |
| `DNSTunnelDetector` | entropie DNS | entropie Shannon(query) | > 3.5 | HIGH | T1071.004 |
| `ExfiltrationDetector` | volume sortant | orig_bytes sortants / paire src·dst | > 1 MB | HIGH | T1048 |
| `CTIMatchDetector` | IOC des logs (amont) | présence dans la CTI + score≥50 / label | — | selon threat level | — |
 
---
 
## 🛡️ Threat Intelligence Layer
 
La couche CTI est **abstraite** : le moteur interroge une interface générique, ce qui permet de brancher plusieurs sources sans le modifier. Elle intervient dans **les deux sens** du pipeline.
 
```
Threat Intelligence Layer
├── MISP     (implémenté · PyMISP · connecté)
└── OpenCTI  (implémenté · pycti 7.x · connecté · hub agrégeant MISP·AlienVault·CVE)
 
Deux points d'intervention :
├── AMONT (cti/upstream_matcher.py) : matching des IOC connus AVANT la détection
│         → alerte CTIMatchDetector si un indicateur du trafic est déjà fiché
└── AVAL  (cti/enrichment.py)       : enrichissement du contexte APRÈS la détection
          → ajoute le contexte de menace aux alertes comportementales
```
 
### Flux CTI (via MISP et OpenCTI)
 
| Flux | Fournisseur | IoC couverts | Mise à jour |
|------|-------------|--------------|-------------|
| **CIRCL OSINT** | CIRCL Luxembourg | IoC généraux · malware · phishing | Temps réel |
| **URLhaus** | abuse.ch | URLs malveillantes · distribution malware | Plusieurs/jour |
| **FeodoTracker** | abuse.ch | IPs C2 (Emotet · TrickBot · Qakbot) | Quotidienne |
| **MalwareBazaar** | abuse.ch | Hashs malware · famille · tags MITRE | Quotidienne |
| **ThreatFox** | abuse.ch | IoC multi-types · mapping MITRE ATT&CK | Temps réel |
| **AlienVault OTX** | AT&T / LevelBlue | Pulses · IOC communautaires | Temps réel *(via OpenCTI)* |
| **CVE (MITRE)** | MITRE | Vulnérabilités CVE | Quotidienne *(via OpenCTI)* |
 
```python
# Interface CTI générique — implémentée par MISP et OpenCTI
class BaseCTI(ABC):
    SOURCE: str = "BaseCTI"
    connected: bool = False
    @abstractmethod
    def lookup(self, value: str) -> dict | None: ...
 
# Matching CTI EN AMONT — avant la détection comportementale
from cti.upstream_matcher import UpstreamMatcher
 
ioc_alerts = UpstreamMatcher().match(logs)   # logs = dict de DataFrames Zeek
# → extrait les indicateurs externes (IP publiques, domaines, hosts, SNI),
#   filtre le bruit d'infra (mDNS/multicast/domaines légitimes),
#   interroge OpenCTI, et n'alerte que sur les IOC CONFIRMÉS malveillants
#   (score ≥ 50 OU label de menace). Seuil calibré sur les feeds réels.
```
 
```python
# Exemple : alerte enrichie, corrélée et qualifiée, stockée dans MongoDB
from pymongo import MongoClient
import os
 
db = MongoClient(os.environ['MONGO_URI'])['threathunter']
db.alerts.insert_one({
    'detector': 'BeaconingDetector',
    'scenario': 'beaconing',
    'src_ip': '192.168.100.30',
    'dst_ip': '1.2.3.4',
    'mitre': 'T1071',
    'severity': 'CRITICAL',
    'risk_score': 100,           # sortie de la couche Qualification
    'confidence': 1.0,
    'correlated_count': 3,       # sortie de la couche Correlation
    'related_detectors': ['SynScanDetector', 'BruteForceDetector', 'BeaconingDetector'],
    'cti_context': {             # sous-document imbriqué natif
        'sources': ['OpenCTI'], 'matched_value': '1.2.3.4',
        'details': {'OpenCTI': {'score': 50, 'origin': 'AlienVault',
                                'threat_level': 'MEDIUM'}}
    }
})
```
 
---
 
## ⚙️ Utilisation
 
### Usage basique
 
```bash
source ~/threathunt-env/bin/activate
cd ~/ThreatHunter
 
# Analyser une capture (PCAP ou PCAPng) avec Zeek
zeek -r pcap/scenario1_portscan.pcapng -C LogAscii::use_json=T
 
# Lancer le pipeline complet
# (matching CTI amont → détection → enrichissement aval → corrélation → qualification → MongoDB)
python3 app.py --pcap pcap/scenario1_portscan.pcapng
 
# Lancer le dashboard (login admin requis)
streamlit run dashboard/main.py
```
 
### Workflow complet par scénario
 
```bash
# 1. Générer le trafic depuis Kali (.40)
nmap -sS -p 1-1000 192.168.100.30
 
# 2. Capturer le trafic (.30 ou .10)
sudo tcpdump -i ens160 -w /tmp/scenario1.pcapng
 
# 3. Transférer vers ThreatHunter (SSH par clé)
scp victim@192.168.100.30:/tmp/scenario1.pcapng ~/ThreatHunter/pcap/
 
# 4. Analyser avec Zeek
cd ~/ThreatHunter/pcap/ && zeek -r scenario1.pcapng
 
# 5. Lancer le pipeline (matching amont → features → détection → CTI aval → corrélation → qualif)
python3 app.py --pcap scenario1.pcapng
 
# 6. Vérifier les alertes (MongoDB) — le mot de passe est lu depuis l'environnement
docker exec th-mongo mongosh -u thunter -p "$MONGO_PASSWORD" \
  --authenticationDatabase admin \
  threathunter --quiet \
  --eval 'db.alerts.find().sort({timestamp:-1}).limit(10).pretty()'
 
# 7. Ouvrir le dashboard
streamlit run dashboard/main.py --server.port 8501
# → http://192.168.100.10:8501 depuis le Mac (login admin)
```
 
---
 
## 📊 Dashboard Streamlit
 
Dashboard **thémé** (dark SOC · marque Keystone) et **authentifié** (compte admin unique, hash bcrypt dans `.env`). Un module **Threat Control** applique des **filtres globaux à toutes les pages** : période (from/to + présets), sévérité, risk score, détecteur, technique MITRE, IP source/destination, CTI confirmée, incidents corrélés, recherche libre — avec compteur « X / Y » et export CSV de la sélection. Mode dégradé si MongoDB est injoignable.
 
| Page | Fonctionnalités |
|------|----------------|
| **Overview** | KPIs globaux · niveau de menace · radar sévérité · fiabilité de détection · carte de flux · tendances |
| **Alerts** | Table filtrée · sélection de ligne · détail alerte qualifiée (preuves · CTI · corrélation) |
| **IOC Intelligence** | Recherche IP · domaine · hash · tag CTI · classification de l'indicateur |
| **Network Activity** | Top sources/destinations · top talkers · activité par détecteur · MITRE · flux réseau |
| **Threat Timeline** | Chronologie des événements (forme = sévérité) · volume dans le temps |
| **Hunting Queries** | Requêtes libres sur la sélection courante · export CSV |
| **Reports** | Synthèse exécutive · niveau de menace · KPIs · export **CSV** + **JSON** + **PDF** |
| **Settings** | Statut services (test de connexion réel) · configuration Mongo/MISP/OpenCTI · seuils de détection (lecture seule) |
 
```bash
streamlit run dashboard/main.py --server.port 8501
# Accès depuis le Mac : http://192.168.100.10:8501
```
 
---
 
## 🎭 Scénarios de démonstration
 
### Scénario 1 — Port Scan
```bash
# Kali (.40)
nmap -sS -p 1-1000 192.168.100.30
# Feature : count(distinct id.resp_p) / source / minute → > 50
# Wireshark : tcp.flags.syn==1 && tcp.flags.ack==0
```
 
### Scénario 2 — SSH Brute Force
```bash
# Kali (.40)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.30
# Feature : port 22 · conn_state REJ · count > 10 / minute
# Wireshark : tcp.port==22 && tcp.flags.reset==1
```
 
### Scénario 3 — Beaconing C2
```python
# Scapy sur Kali (.40)
import time, requests
while True:
    requests.get('http://192.168.100.30')
    time.sleep(30)    # intervalle fixe → jitter faible
# Feature : jitter < 10% · intervalle moyen ≥ 5s · même paire (src, dst)
# CTI : IP destination croisée avec FeodoTracker / ThreatFox
```
 
### Scénario 4 — DNS Tunneling
```bash
# Kali (.40)
dnscat2 --dns server=192.168.100.30,port=53
# Feature : entropie Shannon(query) > 3.5 (filtre .local / _tcp / _udp / .arpa)
# Wireshark : dns && frame.len > 100
```
 
### Scénario 5 — Data Exfiltration
```bash
# PCAP public — https://malware-traffic-analysis.net
# Feature : orig_bytes > 1 000 000 (1 MB) par paire src/dst
# Wireshark : ssl && ip.dst != [IPs légitimes]
```
 
### Scénario 6 — CTI Matching amont (IOC connu)
```bash
# Rejoue une capture contenant un domaine/IP présent dans OpenCTI
# (ou injecte un IOC réel de tes feeds dans un dns.log de test).
python3 app.py --pcap pcap/<capture_avec_ioc_connu>.pcapng
# → alerte CTIMatchDetector : "IOC connu identifié EN AMONT ..."
#   levée AVANT toute détection comportementale.
# Démonstration : la CTI identifie la menace en amont de l'analyse de comportement.
```
 
---
 
## 📅 Roadmap
 
### Phases de préparation
 
| Phase | Objectif | Statut |
|-------|----------|--------|
| Phase 0 | Étude & Documentation | ✅ Terminé |
| Phase 0.5 | GitHub & Structure | ✅ Terminé |
| Phase 1 | Laboratoire VMware (5 VMs) + durcissement SSH | ✅ Terminé |
| Phase 2 | Installation outils (Zeek ✅ · MISP ✅ · OpenCTI ✅ connecté · MongoDB ✅ déployé) | ✅ Terminé |
| Phase 3 | Structure projet Python en couches | ✅ Terminé |
| Phase 4 | Validation Zeek + engines sur PCAP/PCAPng | ✅ Terminé |
 
### Sprints de développement (par couche)
 
| Sprint | Couche / Objectif | Statut |
|--------|-------------------|--------|
| Sprint 0 | Socle : structure `src/` en couches · parser Zeek · MongoDB | ✅ |
| Sprint 4 | **Feature Extraction** (entropie · jitter · ports · volume) | ✅ |
| Sprint 5 | **Detection Engine** + 50 engines (7 familles · Reconnaissance 8/8) | ✅ |
| Sprint 6 | **Threat Intelligence** (MISP + OpenCTI connectés · matching amont + enrichissement aval) | ✅ |
| Sprint 7 | **Alert Correlation** + **Alert Qualification** | ✅ intégré |
| Sprint 8 | **Dashboard** (8 pages · auth · filtres) · CSV/JSON/PDF | ✅ |
| Sprint 9 | **Affinage des seuils heuristiques** (famille DNS/DGA) sur trafic réel | 🔄 |
 
---
 
## 📖 Glossaire
 
| Terme | Définition |
|-------|------------|
| **Threat Hunting** | Recherche proactive de menaces non détectées par les outils automatisés |
| **IoC** | Indicateur de Compromission — artefact associé à une activité malveillante |
| **CTI** | Cyber Threat Intelligence — renseignement sur les menaces cyber |
| **Feature Extraction** | Couche calculant les caractéristiques comportementales (entropie, jitter, ports, volume) à partir des logs Zeek |
| **Detection Engine** | Moteur orchestrant l'exécution des détecteurs sur les features (50 engines actifs) |
| **Engine** | Un détecteur du catalogue (carte d'identité : ID, famille, MITRE, log, feature) |
| **Threat Intelligence Layer** | Couche CTI abstraite ; connecteurs MISP et OpenCTI (connectés), interrogée en amont (matching) et en aval (enrichissement) |
| **CTI Matching (amont)** | Repérage des IOC déjà connus dans le trafic **avant** la détection comportementale (`upstream_matcher.py`) — **implémenté** |
| **Enrichissement CTI (aval)** | Ajout du contexte de menace aux alertes **après** la détection (`enrichment.py`) — **implémenté** |
| **Alert Correlation** | Regroupement des alertes liées (même IP + même période) en un incident — **intégré** |
| **Alert Qualification** | Scoring d'une alerte : severity, confidence, risk score, MITRE ATT&CK — **intégré** |
| **Risk Score** | Score de risque synthétique (0-100) attribué à une alerte qualifiée |
| **Confidence** | Fiabilité de l'alerte (0-1), relevée par la confirmation CTI et la corrélation |
| **Zeek** | Framework open-source d'analyse réseau passive générant des logs structurés |
| **MISP** | Malware Information Sharing Platform — plateforme CTI open-source (connectée) |
| **OpenCTI** | Plateforme CTI open-source (STIX2) — **connectée** (pycti 7.x) · hub agrégeant MISP · AlienVault · CVE · interrogée en amont (matching) et en aval (enrichissement) |
| **MongoDB** | Base NoSQL orientée documents (JSON/BSON) — collections alerts · ioc_cache · history · **déployé** (`mongo:7.0`) |
| **Collection** | Ensemble de documents MongoDB (équivalent NoSQL d'une table SQL) |
| **bcrypt** | Fonction de hachage utilisée pour le mot de passe admin du dashboard (stocké dans `.env`) |
| **PCAP / PCAPng** | Formats de capture réseau (PCAPng = format moderne, lu nativement par Zeek) |
| **tshark** | Version en ligne de commande de Wireshark |
| **Beaconing** | Machine compromise contactant son C2 à intervalles réguliers |
| **Jitter** | Variation des intervalles — faible jitter = comportement automatisé |
| **DNS Tunneling** | Exfiltration encodée dans des requêtes DNS (entropie élevée) |
| **JA3 / JA3S** | Empreinte de la négociation TLS pour identifier des clients suspects |
| **C2** | Command & Control — infrastructure de contrôle des machines compromises |
| **SOC** | Security Operations Center — centre opérationnel de cybersécurité |
| **STIX** | Structured Threat Information eXpression — format standard d'échange CTI (utilisé par OpenCTI) |
| **PyMISP** | Bibliothèque Python officielle pour l'API REST de MISP |
| **pycti** | Bibliothèque Python officielle pour l'API d'OpenCTI |
| **pymongo** | Bibliothèque Python officielle pour l'API MongoDB |
| **Sprint** | Itération courte livrant une couche/fonctionnalité complète et testée |
 
---
 
## 👤 Auteur
 
**Fatma Amri** — Stage Cybersécurité @ Keystone
Projet : Threat Hunting Réseau — Wireshark / Zeek / MISP / OpenCTI
Durée : 2 mois | Environnement : macOS M1 · VMware Fusion · 32 GB RAM
 
---
 
## 📄 Licence
 
Ce projet utilise exclusivement des outils gratuits, open-source ou source-available :
 
| Outil | Licence |
|-------|---------|
| Zeek | BSD |
| MISP | AGPL v3 |
| OpenCTI | Apache 2.0 |
| Python | PSF |
| Streamlit | Apache 2.0 |
| PyMISP | BSD |
| pycti | Apache 2.0 |
| pymongo | Apache 2.0 |
| bcrypt | Apache 2.0 |
| MongoDB (Community) | SSPL (source-available, gratuit) |
| Wireshark / tshark | GPL v2 |
| Docker | Apache 2.0 |
 
> **Note licence** : MongoDB Community est distribué sous **SSPL**, licence *source-available* gratuite mais non reconnue « open source » par l'OSI. Le pilote `pymongo` reste sous Apache 2.0. Si une conformité stricte « 100 % open-source OSI » est exigée, envisager **FerretDB** (Apache 2.0, compatible API MongoDB) ou **CouchDB** (Apache 2.0).
 
---
 
*ThreatHunter Platform · Stage Cybersécurité · Fatma Amri @ Keystone*
