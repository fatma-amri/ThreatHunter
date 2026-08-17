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
    def port_scan_features(conn: pd.DataFrame, states: Optional[set] = None) -> pd.DataFrame:
        """
        Pour chaque IP source, compte le nombre de ports destination
        DISTINCTS contactes et le nombre d'hotes cibles.

        Un scan de ports se traduit par un tres grand nombre de ports
        distincts vises par une meme source.

        states : ensemble optionnel d'etats conn_state a conserver avant
                 agregation. Permet de specialiser le detecteur selon la
                 *technique* de scan :
                   - {"S0"}  -> SYN scan (half-open, SYN sans handshake)
                   - {"SF"}  -> TCP Connect scan (connexion complete)
                 Si None (defaut), tous les etats sont pris en compte :
                 c'est le comportement d'origine du PortScanDetector.

        Retourne un DataFrame :
            src_ip | distinct_ports | distinct_hosts | total_conns
        """
        cols = ["src_ip", "distinct_ports", "distinct_hosts", "total_conns"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)

        df = conn.copy()

        # Zeek nomme les colonnes id.orig_h / id.resp_h / id.resp_p.
        # On les remappe vers des noms simples, en restant tolerant.
        col_src  = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst  = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_port = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])

        if not (col_src and col_dst and col_port):
            return pd.DataFrame(columns=cols)

        # Filtre optionnel par etat de connexion (specialise le detecteur).
        if states:
            col_state = _first_col(df, ["conn_state", "state"])
            if col_state:
                df = df[df[col_state].isin(states)]
            if df.empty:
                return pd.DataFrame(columns=cols)

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
    #  Features UDP SCAN  (source: conn.log)
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def udp_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
        """
        Pour chaque IP source, compte le nombre de ports destination UDP
        DISTINCTS contactes. Un UDP scan (nmap -sU) sonde de nombreux ports
        UDP : on filtre donc sur le protocole (proto == udp) avant d'agreger.

        Retourne un DataFrame :
            src_ip | distinct_ports | distinct_hosts | total_conns
        """
        cols = ["src_ip", "distinct_ports", "distinct_hosts", "total_conns"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)

        df = conn.copy()
        col_src   = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst   = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_port  = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])
        col_proto = _first_col(df, ["proto", "protocol"])

        if not (col_src and col_dst and col_port and col_proto):
            return pd.DataFrame(columns=cols)

        # Ne garder que le trafic UDP (insensible a la casse)
        df = df[df[col_proto].astype(str).str.lower() == "udp"]
        if df.empty:
            return pd.DataFrame(columns=cols)

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
    #  Features VERTICAL SCAN  (source: conn.log)
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def vertical_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
        """
        Pour chaque PAIRE (src, dst), compte le nombre de ports destination
        DISTINCTS. Un vertical scan = une source qui sonde de tres nombreux
        ports sur UNE MEME cible (contrairement au port scan global, agrege
        toutes destinations confondues).

        Retourne :
            src_ip | dst_ip | distinct_ports | total_conns
        """
        cols = ["src_ip", "dst_ip", "distinct_ports", "total_conns"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)

        df = conn.copy()
        col_src  = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst  = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_port = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])

        if not (col_src and col_dst and col_port):
            return pd.DataFrame(columns=cols)

        grouped = (
            df.groupby([col_src, col_dst])
              .agg(distinct_ports=(col_port, "nunique"),
                   total_conns=(col_port, "size"))
              .reset_index()
              .rename(columns={col_src: "src_ip", col_dst: "dst_ip"})
        )
        return grouped.sort_values("distinct_ports", ascending=False)
    # ─────────────────────────────────────────────────────────
    #  Features HORIZONTAL SCAN  (source: conn.log)
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def horizontal_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
        """
        Pour chaque PAIRE (src, port), compte le nombre d'HOTES destination
        DISTINCTS. Un horizontal scan = une source qui teste UN MEME port
        sur de tres nombreux hotes (ex: qui a le 445 ouvert ?).

        Retourne :
            src_ip | dst_port | distinct_hosts | total_conns
        """
        cols = ["src_ip", "dst_port", "distinct_hosts", "total_conns"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)

        df = conn.copy()
        col_src  = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst  = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_port = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])

        if not (col_src and col_dst and col_port):
            return pd.DataFrame(columns=cols)

        grouped = (
            df.groupby([col_src, col_port])
              .agg(distinct_hosts=(col_dst, "nunique"),
                   total_conns=(col_dst, "size"))
              .reset_index()
              .rename(columns={col_src: "src_ip", col_port: "dst_port"})
        )
        return grouped.sort_values("distinct_hosts", ascending=False)
    # ─────────────────────────────────────────────────────────
    #  Features SLOW SCAN  (source: conn.log)
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def slow_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
        """
        Pour chaque PAIRE (src, dst), calcule le nombre de ports distincts,
        la DUREE totale du balayage et l'INTERVALLE MOYEN entre connexions.

        Un slow scan etale ses sondes dans le temps pour rester sous les
        seuils classiques : nombre de ports significatif MAIS intervalle
        moyen eleve et duree totale longue (contrairement a un scan rapide
        qui envoie tout en quelques secondes).

        Retourne :
            src_ip | dst_ip | distinct_ports | duration | mean_interval
        """
        cols = ["src_ip", "dst_ip", "distinct_ports", "duration", "mean_interval"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)

        df = conn.copy()
        col_src  = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst  = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_port = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])
        col_ts   = _first_col(df, ["ts", "timestamp"])

        if not (col_src and col_dst and col_port and col_ts):
            return pd.DataFrame(columns=cols)

        df[col_ts] = pd.to_numeric(df[col_ts], errors="coerce")
        df = df.dropna(subset=[col_ts])
        if df.empty:
            return pd.DataFrame(columns=cols)

        rows = []
        for (src, dst), g in df.groupby([col_src, col_dst]):
            n_ports = int(g[col_port].nunique())
            if n_ports < 2:
                continue                       # pas un balayage
            times = g[col_ts].sort_values().to_numpy()
            duration = float(times[-1] - times[0])
            # intervalle moyen entre 2 connexions successives
            mean_interval = duration / (len(times) - 1) if len(times) > 1 else 0.0
            rows.append({
                "src_ip": src, "dst_ip": dst,
                "distinct_ports": n_ports,
                "duration": round(duration, 2),
                "mean_interval": round(mean_interval, 2),
            })

        return pd.DataFrame(rows, columns=cols).sort_values("mean_interval", ascending=False)
    # ─────────────────────────────────────────────────────────
    #  Features SSH BRUTE FORCE  (source: conn.log)
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def brute_force_features(conn: pd.DataFrame, port: int = 22) -> pd.DataFrame:
        """
        Pour chaque IP source, compte le nombre de tentatives de connexion
        ECHOUEES vers un service (par defaut SSH, port 22).

        Une attaque brute force enchaine de nombreuses connexions qui
        echouent (mauvais mot de passe -> connexion rejetee ou avortee).
        Dans Zeek, ces echecs correspondent a des conn_state comme
        REJ (rejetee), S0 (pas de reponse) ou RSTO/RSTR.

        Retourne :
            src_ip | failed_attempts | dst_ip
        """
        cols = ["src_ip", "failed_attempts", "dst_ip"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)

        df = conn.copy()
        col_src   = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst   = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_port  = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])
        col_state = _first_col(df, ["conn_state", "state"])

        if not (col_src and col_port):
            return pd.DataFrame(columns=cols)

        # 1. Ne garder que le trafic vers le port cible (22 par defaut)
        df[col_port] = pd.to_numeric(df[col_port], errors="coerce")
        df = df[df[col_port] == port]
        if df.empty:
            return pd.DataFrame(columns=cols)

        # 2. Ne garder que les connexions en ECHEC
        failed_states = {"REJ", "S0", "RSTO", "RSTR", "RSTOS0", "SH"}
        if col_state:
            df = df[df[col_state].isin(failed_states)]
        if df.empty:
            return pd.DataFrame(columns=cols)

        # 3. Compter les echecs par source
        grouped = (
            df.groupby(col_src)
              .agg(failed_attempts=(col_port, "size"),
                   dst_ip=(col_dst, "first") if col_dst else (col_port, "size"))
              .reset_index()
              .rename(columns={col_src: "src_ip"})
        )
        return grouped.sort_values("failed_attempts", ascending=False)

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

        # Exclure les destinations qui ne peuvent PAS etre un C2 :
        #  - broadcast (.255), multicast (224-239.x), diffusion locale
        # Un serveur C2 est toujours une IP externe routable. Ce filtre
        # elimine les faux positifs dus au trafic reseau Windows (NetBIOS,
        # SMB, mDNS...) qui est lui aussi regulier.
        def _is_c2_candidate(ip: str) -> bool:
            ip = str(ip)
            if ip.endswith(".255"):                       # broadcast
                return False
            first = ip.split(".")[0]
            if first.isdigit() and 224 <= int(first) <= 239:  # multicast
                return False
            if ip in ("255.255.255.255",):                # broadcast global
                return False
            return True

        df = df[df[col_dst].apply(_is_c2_candidate)]
        if df.empty:
            return pd.DataFrame(columns=cols)

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