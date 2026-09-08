"""
Famille Beaconing / C2 — engines par canal (ENG-016 -> ENG-021).

Meme signal comportemental que le beaconing generique (ENG-015) : une paire
(src -> dst) qui se reconnecte a intervalles TRES reguliers (jitter faible) et
suffisamment espaces (intervalle moyen minimum, pour ecarter les rafales).
Chaque engine se specialise sur un CANAL (port/protocole) ou sur une BANDE de
regularite differente, pour couvrir les variantes d'evasion C2.

MITRE ATT&CK : T1071 - Application Layer Protocol (+ sous-techniques / T1571)
Log utilise  : conn.log
Feature       : jitter + mean_interval (via FeatureExtractor.beaconing_features)

Note : `beaconing_features(conn)` calcule le jitter par paire src/dst sur TOUS
les ports. Pour cibler un canal precis, on FILTRE le conn.log par port AVANT de
passer la feature -> aucune modification de core/ ni de config/settings.py.

Les bandes de detection sont volontairement DISTINCTES d'un engine a l'autre
(ce ne sont pas des doublons) :
  - HTTP / HTTPS / DNS : meme bande stricte, mais canal (port) different.
  - Jittered           : bande de jitter ELARGIE (0.30 < jitter <= 0.50),
                         attrape les beacons a jitter randomise que le strict rate.
  - LongSleep          : intervalle moyen TRES long (>= 300s), low-and-slow.
  - NonStdPort         : beacon regulier sur un port INHABITUEL (exclut les
                         ports de service courants).
"""
from typing import List, Dict, Optional
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor

# Ports de service courants — exclus par le detecteur "port non standard".
COMMON_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465,
                587, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443}


class ChannelBeaconingDetector(BaseDetector):
    """
    Base generique de detection de beaconing par canal.

    A specialiser via les attributs de classe :
      ENGINE_ID, NAME, CHANNEL, MITRE, et un des modes de ciblage de port
      (PORTS = liste a inclure  OU  EXCLUDE_COMMON = True) + bandes optionnelles.
    """

    # --- Identite de famille (commune) ---
    FAMILY = "Beaconing"
    SEVERITY = "CRITICAL"
    MITRE = "T1071"
    LOG = "conn.log"
    FEATURE = "jitter + mean_interval"
    THRESHOLD_KEY = "beaconing"

    # Valeurs par defaut (memes que le beaconing generique ENG-015)
    DEFAULT_MAX_JITTER = 0.30
    DEFAULT_MIN_CONNECTIONS = 4
    DEFAULT_MIN_INTERVAL = 5.0

    # --- A redefinir dans chaque engine concret ---
    ENGINE_ID = "ENG-0XX"
    NAME = "ChannelBeaconingDetector"
    CHANNEL = "generic"
    PORTS: Optional[List[int]] = None      # None = tous les ports ; sinon liste incluse
    EXCLUDE_COMMON = False                  # True = exclut COMMON_PORTS (port non std)
    # Bandes optionnelles (None = valeur de settings / defaut)
    MIN_JITTER: Optional[float] = None      # borne basse (ex : jittered 0.30 < j)
    MAX_JITTER: Optional[float] = None
    MIN_INTERVAL: Optional[float] = None

    def _filter_channel(self, conn: pd.DataFrame) -> pd.DataFrame:
        """Restreint conn.log au canal de l'engine (par port)."""
        col_port = None
        for c in ("id.resp_p", "resp_p", "dst_port"):
            if c in conn.columns:
                col_port = c
                break
        if col_port is None:
            # Pas de colonne port : seul l'engine "tous ports" pourrait tourner.
            return conn if (self.PORTS is None and not self.EXCLUDE_COMMON) else conn.iloc[0:0]
        ports = pd.to_numeric(conn[col_port], errors="coerce")
        if self.PORTS is not None:
            return conn[ports.isin(self.PORTS)]
        if self.EXCLUDE_COMMON:
            return conn[~ports.isin(COMMON_PORTS)]
        return conn

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []

        max_jitter = self.MAX_JITTER if self.MAX_JITTER is not None \
            else self.thresholds.get("max_jitter", self.DEFAULT_MAX_JITTER)
        min_conns = self.thresholds.get("min_connections", self.DEFAULT_MIN_CONNECTIONS)
        min_interval = self.MIN_INTERVAL if self.MIN_INTERVAL is not None \
            else self.thresholds.get("min_interval", self.DEFAULT_MIN_INTERVAL)
        min_jitter = self.MIN_JITTER   # peut rester None

        channel_conn = self._filter_channel(conn)
        if channel_conn is None or channel_conn.empty:
            return []

        features = FeatureExtractor.beaconing_features(channel_conn)
        if features.empty:
            return []

        mask = (
            (features["jitter"] <= max_jitter) &
            (features["n_conns"] >= min_conns) &
            (features["mean_interval"] >= min_interval)
        )
        if min_jitter is not None:
            mask &= (features["jitter"] > min_jitter)
        suspects = features[mask]

        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            band = f"jitter <= {max_jitter:.0%}"
            if min_jitter is not None:
                band = f"{min_jitter:.0%} < jitter <= {max_jitter:.0%}"
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                description=(
                    f"Beaconing {self.CHANNEL} detecte : {int(row['n_conns'])} "
                    f"connexions regulieres (jitter {row['jitter']:.1%}, "
                    f"intervalle moyen {row['mean_interval']:.0f}s ; "
                    f"bande {band}, intervalle >= {min_interval:.0f}s)"
                ),
                evidence={
                    "channel":       self.CHANNEL,
                    "engine_id":     self.ENGINE_ID,
                    "n_conns":       int(row["n_conns"]),
                    "jitter":        float(row["jitter"]),
                    "mean_interval": float(row["mean_interval"]),
                    "max_jitter":    max_jitter,
                    "min_jitter":    min_jitter,
                    "min_interval":  min_interval,
                },
            ))
        return alerts


# ─────────────────────────────────────────────────────────────
#  Engines concrets — un fichier, 6 detecteurs
# ─────────────────────────────────────────────────────────────
class HttpBeaconingDetector(ChannelBeaconingDetector):
    ENGINE_ID = "ENG-016"
    NAME = "HttpBeaconingDetector"
    CHANNEL = "HTTP"
    MITRE = "T1071.001"          # Web Protocols
    PORTS = [80, 8080]


class HttpsBeaconingDetector(ChannelBeaconingDetector):
    ENGINE_ID = "ENG-017"
    NAME = "HttpsBeaconingDetector"
    CHANNEL = "HTTPS/TLS"
    MITRE = "T1071.001"          # Web Protocols
    PORTS = [443, 8443]


class DnsBeaconingDetector(ChannelBeaconingDetector):
    ENGINE_ID = "ENG-018"
    NAME = "DnsBeaconingDetector"
    CHANNEL = "DNS"
    MITRE = "T1071.004"          # DNS
    PORTS = [53]


class LongSleepBeaconingDetector(ChannelBeaconingDetector):
    ENGINE_ID = "ENG-019"
    NAME = "LongSleepBeaconingDetector"
    CHANNEL = "low-and-slow (intervalle long)"
    MITRE = "T1071"
    PORTS = None                 # tous les ports
    MIN_INTERVAL = 300.0         # >= 5 min entre deux battements


class JitteredBeaconingDetector(ChannelBeaconingDetector):
    ENGINE_ID = "ENG-020"
    NAME = "JitteredBeaconingDetector"
    CHANNEL = "jitter randomise"
    MITRE = "T1071"
    PORTS = None
    MIN_JITTER = 0.30            # bande elargie : 30% < jitter <= 50%
    MAX_JITTER = 0.50


class NonStdPortBeaconingDetector(ChannelBeaconingDetector):
    ENGINE_ID = "ENG-021"
    NAME = "NonStdPortBeaconingDetector"
    CHANNEL = "port non standard"
    MITRE = "T1571"              # Non-Standard Port
    EXCLUDE_COMMON = True        # exclut les ports de service courants
