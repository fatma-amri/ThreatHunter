"""
Extraction des caracteristiques comportementales a partir des logs Zeek.

Les detecteurs ne travaillent PAS directement sur les logs bruts : ils
travaillent sur des caracteristiques calculees (features). C'est cette
etape qui transforme de la "lecture de logs" en "analyse comportementale".

Chaque methode prend un DataFrame Zeek et renvoie un DataFrame agrege,
pret a etre teste contre un seuil par un detecteur.
"""
from __future__ import annotations
import math
from collections import Counter
from typing import Optional

import pandas as pd


class FeatureExtractor:
    """Calcule les features comportementales sur les DataFrames Zeek."""

    # ─────────────────────────────────────────────────────────
    #  Outils generiques
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def shannon_entropy(s: str) -> float:
        """
        Entropie de Shannon d'une chaine (en bits par caractere).
        Une valeur elevee = chaine "aleatoire" -> typique d'un encodage
        de donnees (DNS tunneling, domaines DGA...).
        """
        if not s:
            return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    # ─────────────────────────────────────────────────────────
    #  Features PORT SCAN  (source: conn.log)
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def port_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
        """
        Pour chaque IP source, compte le nombre de ports destination
        DISTINCTS contactes et le nombre d'hotes cibles.

        Un scan de ports se traduit par un tres grand nombre de ports
        distincts vises par une meme source.

        Retourne un DataFrame :
            src_ip | distinct_ports | distinct_hosts | total_conns
        """
        if conn is None or conn.empty:
            return pd.DataFrame(
                columns=["src_ip", "distinct_ports", "distinct_hosts", "total_conns"]
            )

        df = conn.copy()

        # Zeek nomme les colonnes id.orig_h / id.resp_h / id.resp_p.
        # On les remappe vers des noms simples, en restant tolerant.
        col_src  = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst  = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_port = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])

        if not (col_src and col_dst and col_port):
            return pd.DataFrame(
                columns=["src_ip", "distinct_ports", "distinct_hosts", "total_conns"]
            )

        grouped = (
            df.groupby(col_src)
              .agg(
                  distinct_ports=(col_port, "nunique"),
                  distinct_hosts=(col_dst,  "nunique"),
                  total_conns=(col_port,    "size"),
              )
              .reset_index()
              .rename(columns={col_src: "src_ip"})
        )
        return grouped.sort_values("distinct_ports", ascending=False)

    # ─────────────────────────────────────────────────────────
    #  Features BEACONING  (source: conn.log)
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def beaconing_features(conn: pd.DataFrame) -> pd.DataFrame:
        """
        Pour chaque paire (src, dst), calcule la regularite temporelle des
        connexions via le JITTER = ecart-type des intervalles / moyenne.

        Un beaconing C2 contacte son serveur a intervalles tres reguliers,
        donc un jitter FAIBLE (proche de 0) sur un nombre eleve de connexions.

        Retourne :
            src_ip | dst_ip | n_conns | mean_interval | jitter
        """
        cols = ["src_ip", "dst_ip", "n_conns", "mean_interval", "jitter"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)

        df = conn.copy()
        col_src = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_ts  = _first_col(df, ["ts", "timestamp"])

        if not (col_src and col_dst and col_ts):
            return pd.DataFrame(columns=cols)

        df[col_ts] = pd.to_numeric(df[col_ts], errors="coerce")
        df = df.dropna(subset=[col_ts])

        rows = []
        for (src, dst), g in df.groupby([col_src, col_dst]):
            if len(g) < 3:                      # trop peu de points -> non significatif
                continue
            times = g[col_ts].sort_values().to_numpy()
            deltas = times[1:] - times[:-1]     # intervalles entre connexions
            mean = float(deltas.mean())
            if mean <= 0:
                continue
            std = float(deltas.std())
            jitter = std / mean                 # jitter relatif
            rows.append({
                "src_ip": src, "dst_ip": dst,
                "n_conns": int(len(g)),
                "mean_interval": round(mean, 2),
                "jitter": round(jitter, 4),
            })

        return pd.DataFrame(rows, columns=cols).sort_values("jitter")

    # ─────────────────────────────────────────────────────────
    #  Features DNS TUNNELING  (source: dns.log)
    # ─────────────────────────────────────────────────────────
    @classmethod
    def dns_features(cls, dns: pd.DataFrame) -> pd.DataFrame:
        """
        Pour chaque requete DNS, calcule l'entropie et la longueur du nom.
        Puis agrege par domaine parent.

        Un tunnel DNS encode des donnees dans les sous-domaines : longueur
        anormale + entropie elevee.

        Retourne :
            src_ip | query | qlen | entropy
        """
        cols = ["src_ip", "query", "qlen", "entropy"]
        if dns is None or dns.empty:
            return pd.DataFrame(columns=cols)

        df = dns.copy()
        col_src   = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_query = _first_col(df, ["query", "qname"])

        if not col_query:
            return pd.DataFrame(columns=cols)

        df = df.dropna(subset=[col_query])
        out = pd.DataFrame({
            "src_ip":  df[col_src] if col_src else "N/A",
            "query":   df[col_query].astype(str),
        })
        out["qlen"]    = out["query"].str.len()
        out["entropy"] = out["query"].apply(cls.shannon_entropy).round(3)
        return out.sort_values("entropy", ascending=False)

    # ─────────────────────────────────────────────────────────
    #  Features EXFILTRATION  (source: conn.log)
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def exfil_features(conn: pd.DataFrame) -> pd.DataFrame:
        """
        Pour chaque paire (src, dst), somme le volume d'octets SORTANTS
        (orig_bytes). Une exfiltration se traduit par un volume sortant
        anormalement eleve vers une destination externe.

        Retourne :
            src_ip | dst_ip | total_orig_bytes | n_conns
        """
        cols = ["src_ip", "dst_ip", "total_orig_bytes", "n_conns"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)

        df = conn.copy()
        col_src   = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst   = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_bytes = _first_col(df, ["orig_bytes", "orig_ip_bytes"])

        if not (col_src and col_dst and col_bytes):
            return pd.DataFrame(columns=cols)

        df[col_bytes] = pd.to_numeric(df[col_bytes], errors="coerce").fillna(0)
        grouped = (
            df.groupby([col_src, col_dst])
              .agg(total_orig_bytes=(col_bytes, "sum"),
                   n_conns=(col_bytes, "size"))
              .reset_index()
              .rename(columns={col_src: "src_ip", col_dst: "dst_ip"})
        )
        return grouped.sort_values("total_orig_bytes", ascending=False)


# ─────────────────────────────────────────────────────────────
#  Helper : trouve la premiere colonne existante parmi une liste
# ─────────────────────────────────────────────────────────────
def _first_col(df: pd.DataFrame, candidates: list[str]) -> Optional[str]:
    """Retourne le premier nom de colonne present dans df, sinon None."""
    for c in candidates:
        if c in df.columns:
            return c
    return None
