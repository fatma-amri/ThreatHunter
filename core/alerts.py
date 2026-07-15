"""
Modèle de données d'une alerte de détection.
Toutes les alertes du projet, quel que soit le détecteur, ont cette structure.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass
class Alert:
    """Représente une alerte produite par un détecteur."""

    # ─── Champs obligatoires ───────────────────────────────
    detector: str          # nom du détecteur (ex: "PortScanDetector")
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    src_ip: str            # IP source (l'attaquant présumé)
    description: str       # explication lisible par un humain

    # ─── Champs optionnels ─────────────────────────────────
    dst_ip: Optional[str] = None      # IP destination (la cible)
    mitre: Optional[str] = None       # technique MITRE ATT&CK (ex: "T1046")
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    evidence: dict = field(default_factory=dict)   # preuves chiffrées
    cti_context: dict = field(default_factory=dict)  # enrichissement MISP

    def to_dict(self) -> dict:
        """Convertit l'alerte en dictionnaire (pour SQLite ou JSON)."""
        return asdict(self)

    def __str__(self) -> str:
        """Affichage lisible en console."""
        cti = " [CTI ✓]" if self.cti_context else ""
        return (f"[{self.severity}] {self.detector} — "
                f"{self.src_ip} → {self.dst_ip or 'N/A'} : {self.description}{cti}")