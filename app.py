"""
app.py — Pipeline principal de la plateforme ThreatHunter.

Chaine complete de bout en bout :
    PCAP --(Zeek)--> logs --(FeatureExtractor + detecteurs)--> alertes --> SQLite

Usage :
    python3 app.py --pcap pcap/scenario1_portscan.pcap
    python3 app.py --logs logs/                 # si Zeek a deja tourne
    python3 app.py --pcap capture.pcapng --no-store
"""
from __future__ import annotations
import argparse
import subprocess
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from pathlib import Path

from core.engine import DetectionEngine
from database.db import Database
from config import settings
from cti.enrichment import Enricher


# ─── Detecteurs disponibles ───────────────────────────────
# Au fur et a mesure que tu codes les autres detecteurs,
# il suffit de les importer et de les ajouter a cette liste.
from detectors.port_scan import PortScanDetector
from detectors.brute_force import BruteForceDetector
from detectors.beaconing import BeaconingDetector
from detectors.syn_scan import SynScanDetector
from detectors.tcp_connect_scan import TcpConnectScanDetector
from detectors.udp_scan import UdpScanDetector
from detectors.vertical_scan import VerticalScanDetector
from detectors.horizontal_scan import HorizontalScanDetector
from detectors.slow_scan import SlowScanDetector
# from detectors.dns_tunnel import DNSTunnelDetector
# from detectors.exfiltration import ExfiltrationDetector

DETECTORS = [
    PortScanDetector,
    BruteForceDetector,
    BeaconingDetector,
    SynScanDetector,
    TcpConnectScanDetector,
    UdpScanDetector,
    VerticalScanDetector,
    HorizontalScanDetector,
    SlowScanDetector,
    # DNSTunnelDetector,
    # ExfiltrationDetector,
]


# ─────────────────────────────────────────────────────────
#  Etape 1 — Analyse Zeek d'un PCAP
# ─────────────────────────────────────────────────────────
def run_zeek(pcap_path: Path, logs_dir: Path) -> bool:
    """
    Lance Zeek sur un fichier PCAP (ou PCAPng) et genere les logs
    dans logs_dir. Retourne True si l'analyse a reussi.

    NOTE : Zeek tourne via un wrapper Docker qui monte le DOSSIER COURANT
    dans le conteneur. On doit donc se placer dans le dossier du PCAP et
    passer seulement le NOM du fichier (pas un chemin absolu), puis
    recuperer les logs generes vers logs_dir.
    """
    pcap_path = pcap_path.resolve()
    if not pcap_path.exists():
        print(f"[!] Fichier introuvable : {pcap_path}")
        return False

    logs_dir = logs_dir.resolve()
    logs_dir.mkdir(parents=True, exist_ok=True)
    pcap_dir = pcap_path.parent
    pcap_name = pcap_path.name

    print(f"[Zeek] Analyse de {pcap_name} ...")

    try:
        # cwd = dossier du PCAP -> le wrapper Docker monte ce dossier
        subprocess.run(
            ["zeek", "-C", "-r", pcap_name],
            cwd=str(pcap_dir),
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("[!] Zeek n'est pas installe ou pas dans le PATH.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Zeek a echoue : {e.stderr}")
        return False

    # Deplacer les .log generes (dans pcap_dir) vers logs_dir
    import shutil
    moved = []
    for log_file in pcap_dir.glob("*.log"):
        dest = logs_dir / log_file.name
        shutil.move(str(log_file), str(dest))
        moved.append(log_file.name)

    print(f"[Zeek] Logs generes : {sorted(moved)}")
    return True


# ─────────────────────────────────────────────────────────
#  Etape 2 — Detection (engine + detecteurs)
# ─────────────────────────────────────────────────────────
def run_detection(logs_dir: Path, store: bool) -> list:
    """Configure le moteur, enregistre les detecteurs et lance l'analyse."""
    db = Database()
    engine = DetectionEngine(logs_dir=logs_dir, db=db)

    for detector_cls in DETECTORS:
        engine.register(detector_cls())

    alerts = engine.run(store=False)

    # ─── Enrichissement CTI (MISP) ───────────────────────────
    # L'enrichissement intervient APRES la detection : la CTI ajoute
    # du contexte aux alertes deja detectees par comportement.
    enricher = Enricher()
    alerts = enricher.enrich_all(alerts)

    # Stockage APRES enrichissement (pour sauvegarder le contexte CTI)
    if store and alerts:
        db.insert_many(alerts)
        print(f"[Engine] {len(alerts)} alerte(s) enregistree(s) en base")

    return alerts


# ─────────────────────────────────────────────────────────
#  Affichage recapitulatif
# ─────────────────────────────────────────────────────────
def print_summary(alerts: list) -> None:
    print("\n" + "=" * 60)
    print(f"  RESULTAT : {len(alerts)} alerte(s) detectee(s)")
    print("=" * 60)

    if not alerts:
        print("  Aucun comportement suspect detecte.")
        return

    # Regroupement par severite pour un affichage clair
    by_sev: dict[str, int] = {}
    for a in alerts:
        by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    repartition = " · ".join(
        f"{sev}: {by_sev[sev]}" for sev in order if sev in by_sev
    )
    print(f"  Repartition : {repartition}\n")

    for a in alerts:
        print(f"  {a}")


# ─────────────────────────────────────────────────────────
#  Point d'entree
# ─────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(
        description="ThreatHunter — pipeline d'analyse PCAP/Zeek"
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", type=Path,
                     help="Fichier PCAP/PCAPng a analyser (Zeek sera lance)")
    src.add_argument("--logs", type=Path,
                     help="Dossier de logs Zeek deja generes")
    parser.add_argument("--no-store", action="store_true",
                        help="Ne pas enregistrer les alertes en base")
    args = parser.parse_args()

    store = not args.no_store

    # Determine le dossier de logs a analyser
    if args.pcap:
        logs_dir = Path(settings.LOGS_DIR)
        if not run_zeek(args.pcap, logs_dir):
            return 1
    else:
        logs_dir = args.logs
        if not logs_dir.exists():
            print(f"[!] Dossier de logs introuvable : {logs_dir}")
            return 1

    alerts = run_detection(logs_dir, store=store)
    print_summary(alerts)
    return 0


if __name__ == "__main__":
    sys.exit(main())