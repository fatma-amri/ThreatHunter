"""
Configuration centralisée de la plateforme ThreatHunter.
Toutes les valeurs paramétrables du projet sont ici.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# ─── Chemins du projet ────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent   # racine ThreatHunter/
load_dotenv(BASE_DIR / ".env")
PCAP_DIR = BASE_DIR / "pcap"                        # captures réseau
LOGS_DIR = BASE_DIR / "logs"                        # logs générés par Zeek
DB_PATH  = BASE_DIR / "database" / "alerts.db"      # base SQLite

# ─── Connexion MISP ───────────────────────────────────────────
MISP_URL    = os.getenv("MISP_URL", "https://192.168.100.20")
MISP_KEY    = os.getenv("MISP_KEY", "")   # jamais en dur : voir .env
MISP_VERIFY = False   # certificat auto-signé du lab

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
        "min_entropy": 3.5,     # entropie de Shannon élevée = données encodées
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
}

# ─── Niveaux de sévérité ──────────────────────────────────────
SEVERITY = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]