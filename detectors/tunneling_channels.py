"""
Famille Tunneling — 6 engines (ENG-030 -> ENG-035).

Deux sous-approches, toutes deux SANS nouvelle couche core/ :

  A) Tunnels PROTOCOLAIRES (ICMP / SSH / HTTP / HTTPS) — signal VOLUME + DUREE
     derive directement des colonnes reelles du conn.log
     (proto, duration, orig_bytes, resp_bytes). Un tunnel = une (ou peu de)
     session(s) LONGUE(S) transportant BEAUCOUP de donnees, souvent de facon
     BIDIRECTIONNELLE, sur un canal qui ne devrait pas.

  B) Tunnels DNS (iodine / dnscat2) — reutilisent FeatureExtractor.dns_features
     (entropie + longueur de requete), avec des PROFILS de seuils differents du
     detecteur generique ENG-029 (bandes distinctes, pas des doublons).

MITRE ATT&CK :
  ICMP           -> T1095 (Non-Application Layer Protocol)
  SSH/HTTP/HTTPS -> T1572 (Protocol Tunneling)
  iodine/dnscat2 -> T1071.004 (DNS)
"""
from typing import List, Dict, Optional
import pandas as pd

from detectors.base_detector import BaseDetector
from core.alerts import Alert
from core.feature_extractor import FeatureExtractor


# ══════════════════════════════════════════════════════════════
#  Helper commun : agrege le conn.log par paire (volume + duree)
#  Lit uniquement des colonnes reelles du conn.log (cf. zeek_parser).
# ══════════════════════════════════════════════════════════════
def _first_col(df: pd.DataFrame, candidates) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def conn_volume_duration(conn: pd.DataFrame,
                         ports: Optional[List[int]] = None,
                         proto: Optional[str] = None) -> pd.DataFrame:
    """
    Agrege conn.log par paire (src, dst) : volume orig/resp + duree max.
    Filtre optionnel par liste de ports et/ou par protocole (tcp/udp/icmp).
    Colonnes de sortie : src_ip, dst_ip, n_conns, orig_bytes, resp_bytes,
                         total_bytes, max_duration, min_dir_bytes.
    """
    cols = ["src_ip", "dst_ip", "n_conns", "orig_bytes", "resp_bytes",
            "total_bytes", "max_duration", "min_dir_bytes"]
    if conn is None or conn.empty:
        return pd.DataFrame(columns=cols)
    df = conn.copy()
    col_src = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
    col_dst = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
    col_ob = _first_col(df, ["orig_bytes", "orig_ip_bytes"])
    col_rb = _first_col(df, ["resp_bytes", "resp_ip_bytes"])
    col_dur = _first_col(df, ["duration"])
    col_port = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])
    col_proto = _first_col(df, ["proto", "protocol"])
    if not (col_src and col_dst and col_ob):
        return pd.DataFrame(columns=cols)

    if proto and col_proto:
        df = df[df[col_proto].astype(str).str.lower() == proto.lower()]
    if ports is not None and col_port:
        df = df[pd.to_numeric(df[col_port], errors="coerce").isin(ports)]
    if df.empty:
        return pd.DataFrame(columns=cols)

    df[col_ob] = pd.to_numeric(df[col_ob], errors="coerce").fillna(0)
    if col_rb:
        df[col_rb] = pd.to_numeric(df[col_rb], errors="coerce").fillna(0)
    else:
        df["_rb"] = 0.0
        col_rb = "_rb"
    if col_dur:
        df[col_dur] = pd.to_numeric(df[col_dur], errors="coerce").fillna(0)
    else:
        df["_dur"] = 0.0
        col_dur = "_dur"

    g = (df.groupby([col_src, col_dst])
           .agg(n_conns=(col_ob, "size"),
                orig_bytes=(col_ob, "sum"),
                resp_bytes=(col_rb, "sum"),
                max_duration=(col_dur, "max"))
           .reset_index()
           .rename(columns={col_src: "src_ip", col_dst: "dst_ip"}))
    g["total_bytes"] = g["orig_bytes"] + g["resp_bytes"]
    g["min_dir_bytes"] = g[["orig_bytes", "resp_bytes"]].min(axis=1)  # bidirectionnel
    return g.sort_values("total_bytes", ascending=False)


# ══════════════════════════════════════════════════════════════
#  A) Tunnels protocolaires (volume + duree, conn.log)
# ══════════════════════════════════════════════════════════════
class _ProtocolTunnelDetector(BaseDetector):
    FAMILY = "Tunneling"
    SEVERITY = "HIGH"
    LOG = "conn.log"
    FEATURE = "volume + duree"
    THRESHOLD_KEY = "tunnel"          # absent de settings -> valeurs par defaut

    ENGINE_ID = "ENG-0XX"
    NAME = "_ProtocolTunnelDetector"
    CHANNEL = "generic"
    PORTS: Optional[List[int]] = None
    PROTO: Optional[str] = None
    MIN_TOTAL_BYTES = 1_000_000       # volume total sur le canal
    MIN_DURATION = 0.0                # duree max d'une session (s)
    MIN_DIR_BYTES = 0                 # volume min de la direction la plus faible (bidirectionnel)

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        conn = logs.get("conn")
        if conn is None or conn.empty:
            return []
        feats = conn_volume_duration(conn, ports=self.PORTS, proto=self.PROTO)
        if feats.empty:
            return []
        mask = (
            (feats["total_bytes"] >= self.MIN_TOTAL_BYTES) &
            (feats["max_duration"] >= self.MIN_DURATION) &
            (feats["min_dir_bytes"] >= self.MIN_DIR_BYTES)
        )
        suspects = feats[mask]
        alerts: List[Alert] = []
        for _, row in suspects.iterrows():
            alerts.append(self.make_alert(
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                description=(
                    f"Tunnel {self.CHANNEL} suspecte : "
                    f"{row['total_bytes']/1_000_000:.2f} Mo "
                    f"(sortant {row['orig_bytes']/1_000_000:.2f} / entrant "
                    f"{row['resp_bytes']/1_000_000:.2f} Mo), duree max "
                    f"{row['max_duration']:.0f}s sur {int(row['n_conns'])} session(s)"
                ),
                evidence={
                    "channel":      self.CHANNEL,
                    "engine_id":    self.ENGINE_ID,
                    "total_bytes":  int(row["total_bytes"]),
                    "orig_bytes":   int(row["orig_bytes"]),
                    "resp_bytes":   int(row["resp_bytes"]),
                    "max_duration": float(row["max_duration"]),
                    "n_conns":      int(row["n_conns"]),
                },
            ))
        return alerts


class IcmpTunnelDetector(_ProtocolTunnelDetector):
    ENGINE_ID = "ENG-030"
    NAME = "IcmpTunnelDetector"
    CHANNEL = "ICMP"
    MITRE = "T1095"
    PROTO = "icmp"
    MIN_TOTAL_BYTES = 50_000          # ICMP transporte normalement ~rien
    MIN_DURATION = 0.0
    MIN_DIR_BYTES = 0


class SshTunnelDetector(_ProtocolTunnelDetector):
    ENGINE_ID = "ENG-031"
    NAME = "SshTunnelDetector"
    CHANNEL = "SSH"
    MITRE = "T1572"
    PORTS = [22]
    MIN_TOTAL_BYTES = 1_000_000       # session SSH grasse
    MIN_DURATION = 300.0              # ... et longue (>= 5 min)


class HttpTunnelDetector(_ProtocolTunnelDetector):
    ENGINE_ID = "ENG-032"
    NAME = "HttpTunnelDetector"
    CHANNEL = "HTTP"
    MITRE = "T1572"
    PORTS = [80, 8080]
    MIN_TOTAL_BYTES = 1_000_000
    MIN_DURATION = 300.0
    MIN_DIR_BYTES = 500_000           # bidirectionnel soutenu (≠ navigation normale)


class HttpsTunnelDetector(_ProtocolTunnelDetector):
    ENGINE_ID = "ENG-032b"            # variante TLS (DoH inclus) — a numeroter au catalogue
    NAME = "HttpsTunnelDetector"
    CHANNEL = "HTTPS/TLS"
    MITRE = "T1572"
    PORTS = [443, 8443]
    MIN_TOTAL_BYTES = 1_000_000
    MIN_DURATION = 300.0
    MIN_DIR_BYTES = 500_000


# ══════════════════════════════════════════════════════════════
#  B) Tunnels DNS (profils sur dns_features) — bandes distinctes d'ENG-029
# ══════════════════════════════════════════════════════════════
class _DnsProfileTunnelDetector(BaseDetector):
    FAMILY = "Tunneling"
    SEVERITY = "HIGH"
    MITRE = "T1071.004"
    LOG = "dns.log"
    FEATURE = "dns_entropy + qlen"
    THRESHOLD_KEY = "dns_tunnel"

    INFRA_PATTERN = r"(?:\.in-addr\.arpa|\.ip6\.arpa|\.local|_tcp|_udp|_dns-sd)\.?$"

    ENGINE_ID = "ENG-0XX"
    NAME = "_DnsProfileTunnelDetector"
    PROFILE = "generic"
    MIN_ENTROPY = 3.5
    MIN_QLEN = 40
    MIN_QUERIES = 5

    def analyze(self, logs: Dict[str, pd.DataFrame]) -> List[Alert]:
        dns = logs.get("dns")
        if dns is None or dns.empty:
            return []
        feats = FeatureExtractor.dns_features(dns)
        if feats.empty:
            return []
        feats = feats[~feats["query"].str.contains(
            self.INFRA_PATTERN, case=False, regex=True, na=False)]
        if feats.empty:
            return []
        suspects = feats[(feats["entropy"] >= self.MIN_ENTROPY) &
                         (feats["qlen"] >= self.MIN_QLEN)]
        if suspects.empty:
            return []
        alerts: List[Alert] = []
        for src, grp in suspects.groupby("src_ip"):
            if len(grp) < self.MIN_QUERIES:
                continue
            alerts.append(self.make_alert(
                src_ip=src,
                description=(
                    f"Tunnel DNS ({self.PROFILE}) suspecte : {len(grp)} requetes "
                    f"(entropie max {grp['entropy'].max():.2f}, longueur max "
                    f"{int(grp['qlen'].max())} ; profil entropie>={self.MIN_ENTROPY}, "
                    f"longueur>={self.MIN_QLEN})"
                ),
                evidence={
                    "profile":            self.PROFILE,
                    "engine_id":          self.ENGINE_ID,
                    "suspicious_queries": int(len(grp)),
                    "max_entropy":        float(grp["entropy"].max()),
                    "max_qlen":           int(grp["qlen"].max()),
                    "sample_query":       str(grp.sort_values("entropy", ascending=False).iloc[0]["query"])[:120],
                },
            ))
        return alerts


class IodineDnsTunnelDetector(_DnsProfileTunnelDetector):
    ENGINE_ID = "ENG-033"
    NAME = "IodineDnsTunnelDetector"
    PROFILE = "iodine"
    MIN_QLEN = 100                    # iodine bourre des labels tres longs
    MIN_ENTROPY = 3.5
    MIN_QUERIES = 5


class Dnscat2TunnelDetector(_DnsProfileTunnelDetector):
    ENGINE_ID = "ENG-034"
    NAME = "Dnscat2TunnelDetector"
    PROFILE = "dnscat2"
    MIN_ENTROPY = 4.0                 # entropie tres elevee, volume de requetes eleve
    MIN_QLEN = 40
    MIN_QUERIES = 10
