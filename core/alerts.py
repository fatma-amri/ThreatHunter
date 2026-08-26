"""
Modèle de données d'une alerte de détection.
Toutes les alertes du projet, quel que soit le détecteur, ont cette structure.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List


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

    # ─── Champs ajoutés par la Qualification (couche 7) ────
    confidence: Optional[float] = None   # 0.0 → 1.0 : fiabilité de l'alerte
    risk_score: Optional[int] = None     # 0 → 100 : score de risque synthétique

    # ─── Champs ajoutés par la Corrélation (couche 6) ──────
    correlated_count: int = 1                # nb d'alertes fusionnées (1 = non corrélée)
    related_detectors: List[str] = field(default_factory=list)  # détecteurs impliqués

    def to_dict(self) -> dict:
        """Convertit l'alerte en dictionnaire (pour MongoDB ou JSON)."""
        return asdict(self)

    def __str__(self) -> str:
        """Affichage lisible en console."""
        cti = " [CTI ✓]" if self.cti_context else ""
        rs = f" risk={self.risk_score}" if self.risk_score is not None else ""
        corr = f" (×{self.correlated_count})" if self.correlated_count > 1 else ""
        return (f"[{self.severity}{rs}] {self.detector}{corr} — "
                f"{self.src_ip} → {self.dst_ip or 'N/A'} : {self.description}{cti}")