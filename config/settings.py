"""
Configuration centralisée de la plateforme ThreatHunter.
Toutes les valeurs paramétrables du projet sont ici.
"""
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from pathlib import Path
from dotenv import load_dotenv

# ─── Chemins du projet ────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent   # racine ThreatHunter/
load_dotenv(BASE_DIR / ".env")
PCAP_DIR = BASE_DIR / "pcap"                        # captures réseau
LOGS_DIR = BASE_DIR / "logs"                        # logs générés par Zeek
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")  # voir .env
DB_NAME   = os.getenv("DB_NAME", "threathunter")
# ─── Authentification du dashboard (compte admin unique) ──────
# JAMAIS de mot de passe en clair : seul le hash bcrypt est stocke, dans .env.
# Choix .env (et pas MongoDB) : le dashboard doit rester utilisable en mode
# degrade quand MongoDB est injoignable — les identifiants doivent donc etre
# disponibles sans base.
# Generer / mettre a jour :  python -m dashboard.pages.auth --create-admin
ADMIN_USERNAME      = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")   # $2b$12$....

# ─── Connexion MISP ───────────────────────────────────────────
MISP_URL    = os.getenv("MISP_URL", "https://192.168.100.20")
MISP_KEY    = os.getenv("MISP_KEY", "")   # jamais en dur : voir .env
MISP_VERIFY = False   # certificat auto-signé du lab
# ─── Connexion OpenCTI ────────────────────────────────────────
OPENCTI_URL         = os.getenv("OPENCTI_URL", "http://192.168.100.50:8080")
OPENCTI_TOKEN       = os.getenv("OPENCTI_TOKEN", "")   # jamais en dur : voir .env
OPENCTI_SSL_VERIFY  = False   # pas de TLS sur l'instance du lab
OPENCTI_ENABLED     = os.getenv("OPENCTI_ENABLED", "true")
# ─── Seuils de détection ──────────────────────────────────────
# Chaque détecteur lira son seuil ici (jamais codé en dur dans le détecteur)
THRESHOLDS = {
    "port_scan": {
        "min_ports": 50,        # nb de ports distincts contactés
        "window_sec": 60,       # dans une fenêtre de 60 s
    },
    "brute_force": {
        "min_attempts": 10,     # nb d'échecs de connexion
        "window_sec": 60,
        "port": 22,             # SSH
    },
    "beaconing": {
        "max_jitter": 0.30,     # jitter < 10 % = comportement automatisé
        "min_connections": 4,  # nb minimum de connexions pour conclure
    },
    "dns_tunnel": {
        "min_entropy": 3.5, 
        "min_qlen": 40, 
        "min_queries": 5
    },
    
    "exfiltration": {
        "max_bytes": 1_000_000, # > 1 Mo sortant par session
    },
    "syn_scan": {
        "min_ports": 50
    },
    "tcp_connect_scan": {
        "min_ports": 50
    },
    "udp_scan": {
        "min_ports": 50
    },
    "vertical_scan": {
        "min_ports": 50
    },
    "horizontal_scan": {
        "min_hosts": 20
    },
    "slow_scan": {
        "min_ports": 20,
        "min_interval": 30, 
        "min_duration": 600
    },
    "stealth_scan": {
        "min_ports": 20
    },
    
    "correlation": {
        "window_seconds": 300
    },
    "qualification": {
        "severity_base": {"LOW": 20, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 90},
        "cti_bonus": 15,
        "correlation_bonus": 5,
        "max_correlation_bonus": 20,
    },
}

# ─── Niveaux de sévérité ──────────────────────────────────────
SEVERITY = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]