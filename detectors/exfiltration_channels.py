"""
Famille Exfiltration — engines par canal (ENG-023 -> ENG-028).

Meme signal que l'exfiltration generique (ENG-022) : un volume d'octets
SORTANTS anormalement eleve depuis une machine interne vers une destination.
Chaque engine se specialise sur un CANAL (port/protocole) : on FILTRE le
conn.log par port AVANT de passer la feature volume -> aucune modification de
core/ ni de config/settings.py.

MITRE ATT&CK : T1048 - Exfiltration Over Alternative Protocol
  .002 Asymmetric Encrypted Non-C2 (HTTPS/TLS)   .003 Unencrypted Non-C2 (FTP/HTTP/SMTP)
Log utilise  : conn.log
Feature       : total_orig_bytes (via FeatureExtractor.exfil_features)
"""
from typing import List, Dict, Optional
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor

COMMON_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465,
                587, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443}


class ChannelExfiltrationDetector(BaseDetector):
    """
    Base generique de detection d'exfiltration par canal.

    A specialiser via : ENGINE_ID, NAME, CHANNEL, MITRE, et le ciblage de port
    (PORTS = liste a inclure  OU  EXCLUDE_COMMON = True) + MAX_BYTES optionnel.
    """

    FAMILY = "Exfiltration"
    SEVERITY = "HIGH"
    MITRE = "T1048"
    LOG = "conn.log"
    FEATURE = "total_orig_bytes"
    THRESHOLD_KEY = "exfiltration"
    DEFAULT_MAX_BYTES = 1_000_000

    ENGINE_ID = "ENG-0XX"
    NAME = "ChannelExfiltrationDetector"
    CHANNEL = "generic"
    PORTS: Optional[List[int]] = None
    EXCLUDE_COMMON = False
    MAX_BYTES: Optional[int] = None      # override par canal (ex : DNS plus sensible)

    def _filter_channel(self, conn: pd.DataFrame) -> pd.DataFrame:
        col_port = None
        for c in ("id.resp_p", "resp_p", "dst_port"):
            if c in conn.columns:
                col_port = c
                break
        if col_port is None:
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

        max_bytes = self.MAX_BYTES if self.MAX_BYTES is not None \
            else self.thresholds.get("max_bytes", self.DEFAULT_MAX_BYTES)

        channel_conn = self._filter_channel(conn)
        if channel_conn is None or channel_conn.empty:
            return []

        features = FeatureExtractor.exfil_features(channel_conn)
        if features.empty:
            return []

        suspects = features[features["total_orig_bytes"] >= max_bytes]

        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            mb = row["total_orig_bytes"] / 1_000_000
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                description=(
                    f"Exfiltration {self.CHANNEL} suspecte : {mb:.2f} Mo envoyes "
                    f"vers {row['dst_ip']} sur {int(row['n_conns'])} connexion(s) "
                    f"(seuil {max_bytes / 1_000_000:.2f} Mo)"
                ),
                evidence={
                    "channel":          self.CHANNEL,
                    "engine_id":        self.ENGINE_ID,
                    "total_orig_bytes": int(row["total_orig_bytes"]),
                    "total_mb":         round(mb, 2),
                    "n_conns":          int(row["n_conns"]),
                    "threshold_bytes":  max_bytes,
                },
            ))
        return alerts


# ─────────────────────────────────────────────────────────────
#  Engines concrets
# ─────────────────────────────────────────────────────────────
class FtpExfiltrationDetector(ChannelExfiltrationDetector):
    ENGINE_ID = "ENG-023"
    NAME = "FtpExfiltrationDetector"
    CHANNEL = "FTP"
    MITRE = "T1048.003"           # non chiffre
    PORTS = [20, 21]


class HttpExfiltrationDetector(ChannelExfiltrationDetector):
    ENGINE_ID = "ENG-024"
    NAME = "HttpExfiltrationDetector"
    CHANNEL = "HTTP (bulk upload)"
    MITRE = "T1048.003"
    PORTS = [80, 8080]


class HttpsExfiltrationDetector(ChannelExfiltrationDetector):
    ENGINE_ID = "ENG-025"
    NAME = "HttpsExfiltrationDetector"
    CHANNEL = "HTTPS/TLS"
    MITRE = "T1048.002"           # chiffre asymetrique
    PORTS = [443, 8443]


class SmtpExfiltrationDetector(ChannelExfiltrationDetector):
    ENGINE_ID = "ENG-026"
    NAME = "SmtpExfiltrationDetector"
    CHANNEL = "SMTP (email)"
    MITRE = "T1048.003"
    PORTS = [25, 465, 587]


class DnsExfiltrationDetector(ChannelExfiltrationDetector):
    ENGINE_ID = "ENG-027"
    NAME = "DnsExfiltrationDetector"
    CHANNEL = "DNS"
    MITRE = "T1048"
    PORTS = [53]
    MAX_BYTES = 100_000           # DNS = canal etroit : seuil plus sensible (100 Ko)


class NonStdPortExfiltrationDetector(ChannelExfiltrationDetector):
    ENGINE_ID = "ENG-028"
    NAME = "NonStdPortExfiltrationDetector"
    CHANNEL = "port non standard"
    MITRE = "T1048"
    EXCLUDE_COMMON = True
