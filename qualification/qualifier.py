"""
Alert Qualification (couche 7 du pipeline).

Objectif : transformer une alerte brute (ou un incident correle) en alerte
QUALIFIEE, exploitable par un analyste SOC. On calcule :

  - risk_score  (0 -> 100) : score de risque synthetique
  - confidence  (0.0 -> 1.0) : fiabilite de la detection
  - severity    : eventuellement relevee si la CTI confirme la menace

Le score combine trois signaux :
  1. la gravite intrinseque du comportement (severity du detecteur),
  2. la confirmation par la Threat Intelligence (un IOC connu = plus grave),
  3. la correlation (plusieurs detecteurs sur la meme source = plus grave).
"""
from typing import List

from core.alerts import Alert
from config import settings

_SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_ORDER_SEV = {v: k for k, v in _SEV_ORDER.items()}

# Confidence de base par gravite
_BASE_CONFIDENCE = {"LOW": 0.40, "MEDIUM": 0.60, "HIGH": 0.75, "CRITICAL": 0.90}


class Qualifier:
    """Attribue risk_score, confidence et severity finale a chaque alerte."""

    def __init__(self):
        cfg = settings.THRESHOLDS.get("qualification", {})
        self.sev_base = cfg.get("severity_base",
                                {"LOW": 20, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 90})
        self.cti_bonus = cfg.get("cti_bonus", 15)
        self.corr_bonus = cfg.get("correlation_bonus", 5)
        self.max_corr_bonus = cfg.get("max_correlation_bonus", 20)

    # ------------------------------------------------------------------ #
    def qualify_all(self, alerts: List[Alert]) -> List[Alert]:
        return [self.qualify(a) for a in alerts]

    def qualify(self, alert: Alert) -> Alert:
        has_cti = self._has_cti_hit(alert)

        # 1. La CTI peut relever la severite (un IOC connu est plus grave)
        if has_cti and _SEV_ORDER.get(alert.severity, 1) < _SEV_ORDER["HIGH"]:
            alert.severity = "HIGH"

        # 2. Score de risque
        score = self.sev_base.get(alert.severity, 20)
        if has_cti:
            score += self.cti_bonus
        extra = max(0, alert.correlated_count - 1)
        score += min(extra * self.corr_bonus, self.max_corr_bonus)
        alert.risk_score = int(min(score, 100))

        # 3. Confidence
        conf = _BASE_CONFIDENCE.get(alert.severity, 0.4)
        if has_cti:
            conf += 0.15
        conf += min(extra * 0.05, 0.15)
        alert.confidence = round(min(conf, 1.0), 2)

        return alert

    # ------------------------------------------------------------------ #
    @staticmethod
    def _has_cti_hit(alert: Alert) -> bool:
        """
        Determine si l'alerte a ete confirmee par la Threat Intelligence.
        Tolerant a la forme de cti_context : on considere qu'il y a un hit
        si le contexte est non vide et ne signale pas explicitement une
        absence (found=False) ou une erreur seule.
        """
        ctx = alert.cti_context
        if not ctx or not isinstance(ctx, dict):
            return False
        if ctx.get("found") is False:
            return False
        # Un contexte qui ne contient qu'une cle d'erreur n'est pas un hit
        if set(ctx.keys()) <= {"error"}:
            return False
        return True
