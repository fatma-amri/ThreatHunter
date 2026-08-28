"""
Famille Mouvement Lateral — 6 engines (ENG-036 -> ENG-041).

Apres une premiere compromission, l'attaquant rebondit de machine INTERNE en
machine INTERNE via des services d'administration (SMB, RDP, SSH, WinRM, DCOM,
VNC). Le signal, tire du conn.log : une source INTERNE qui contacte PLUSIEURS
hotes INTERNES distincts sur un port d'administration.

Difference avec la Reconnaissance (scan) : le scan cartographie des PORTS sur
une cible ; le mouvement lateral touche PEU de ports (le service d'admin) mais
PLUSIEURS hotes, et il est INTERNE -> INTERNE.

Mapping MITRE : chaque engine correspond a une sous-technique reelle de
T1021 - Remote Services.
  .001 RDP · .002 SMB/Admin Shares · .003 DCOM · .004 SSH · .005 VNC · .006 WinRM

Log utilise : conn.log — aucune modification de core/ ni de settings.py.
"""
from typing import List, Dict, Optional
import ipaddress
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert


# Reseaux "internes" = RFC1918 (+ ULA IPv6). Volontairement plus strict que
# ipaddress.is_private, qui inclut aussi loopback, link-local et les plages de
# documentation (192.0.2/24, 198.51.100/24, 203.0.113/24) — a exclure ici.
_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip: str) -> bool:
    """True si l'IP appartient a un reseau interne (RFC1918 / ULA)."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


def _first_col(df: pd.DataFrame, candidates) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None


class LateralMovementDetector(BaseDetector):
    """
    Base generique : une source interne touchant >= MIN_TARGETS hotes internes
    distincts sur le(s) port(s) du service.

    A specialiser via : ENGINE_ID, NAME, SERVICE, PORTS, MITRE.
    """

    FAMILY = "Lateral Movement"
    SEVERITY = "HIGH"
    MITRE = "T1021"
    LOG = "conn.log"
    FEATURE = "distinct_internal_hosts"
    THRESHOLD_KEY = "lateral_movement"    # absent de settings -> defaut
    DEFAULT_MIN_TARGETS = 3

    ENGINE_ID = "ENG-0XX"
    NAME = "LateralMovementDetector"
    SERVICE = "generic"
    PORTS: List[int] = []

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty or not self.PORTS:
            return []

        min_targets = self.thresholds.get("min_targets", self.DEFAULT_MIN_TARGETS)

        col_src = _first_col(conn, ["id.orig_h", "orig_h", "src_ip"])
        col_dst = _first_col(conn, ["id.resp_h", "resp_h", "dst_ip"])
        col_port = _first_col(conn, ["id.resp_p", "resp_p", "dst_port"])
        if not (col_src and col_dst and col_port):
            return []

        df = conn[[col_src, col_dst, col_port]].copy()
        df[col_port] = pd.to_numeric(df[col_port], errors="coerce")
        df = df[df[col_port].isin(self.PORTS)]
        if df.empty:
            return []

        # Interne -> interne uniquement
        df = df[df[col_src].apply(_is_private) & df[col_dst].apply(_is_private)]
        # On ne compte pas une machine se parlant a elle-meme
        df = df[df[col_src] != df[col_dst]]
        if df.empty:
            return []

        alerts: List[Alert] = []
        for src, grp in df.groupby(col_src):
            targets = sorted(grp[col_dst].unique().tolist())
            if len(targets) < min_targets:
                continue
            alerts.append(self.make_alert(
                src_ip=src,
                dst_ip=None,
                description=(
                    f"Mouvement lateral {self.SERVICE} suspecte : la source interne "
                    f"a contacte {len(targets)} hotes internes distincts sur le(s) "
                    f"port(s) {self.PORTS} (seuil : {min_targets})"
                ),
                evidence={
                    "service":        self.SERVICE,
                    "engine_id":      self.ENGINE_ID,
                    "distinct_hosts": len(targets),
                    "targets":        targets[:20],
                    "ports":          self.PORTS,
                    "threshold":      min_targets,
                },
            ))
        return alerts


# ─────────────────────────────────────────────────────────────
#  Engines concrets — 6 sous-techniques reelles de T1021
# ─────────────────────────────────────────────────────────────
class RdpLateralMovementDetector(LateralMovementDetector):
    ENGINE_ID = "ENG-036"
    NAME = "RdpLateralMovementDetector"
    SERVICE = "RDP"
    MITRE = "T1021.001"
    PORTS = [3389]


class SmbLateralMovementDetector(LateralMovementDetector):
    ENGINE_ID = "ENG-037"
    NAME = "SmbLateralMovementDetector"
    SERVICE = "SMB / Admin Shares"
    MITRE = "T1021.002"
    PORTS = [445, 139]


class DcomLateralMovementDetector(LateralMovementDetector):
    ENGINE_ID = "ENG-038"
    NAME = "DcomLateralMovementDetector"
    SERVICE = "DCOM / WMI (RPC)"
    MITRE = "T1021.003"
    PORTS = [135]


class SshLateralMovementDetector(LateralMovementDetector):
    ENGINE_ID = "ENG-039"
    NAME = "SshLateralMovementDetector"
    SERVICE = "SSH"
    MITRE = "T1021.004"
    PORTS = [22]


class VncLateralMovementDetector(LateralMovementDetector):
    ENGINE_ID = "ENG-040"
    NAME = "VncLateralMovementDetector"
    SERVICE = "VNC"
    MITRE = "T1021.005"
    PORTS = [5900, 5901]


class WinRmLateralMovementDetector(LateralMovementDetector):
    ENGINE_ID = "ENG-041"
    NAME = "WinRmLateralMovementDetector"
    SERVICE = "WinRM"
    MITRE = "T1021.006"
    PORTS = [5985, 5986]
