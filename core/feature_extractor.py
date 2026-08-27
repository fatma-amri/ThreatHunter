"""
Extraction des caracteristiques comportementales a partir des logs Zeek.
"""
from __future__ import annotations
import math
from collections import Counter
from typing import Optional

import pandas as pd


class FeatureExtractor:
    """Calcule les features comportementales sur les DataFrames Zeek."""

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    @staticmethod
    def port_scan_features(conn: pd.DataFrame, states: Optional[set] = None) -> pd.DataFrame:
        cols = ["src_ip", "distinct_ports", "distinct_hosts", "total_conns"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)
        df = conn.copy()
        col_src  = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst  = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_port = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])
        if not (col_src and col_dst and col_port):
            return pd.DataFrame(columns=cols)
        if states:
            col_state = _first_col(df, ["conn_state", "state"])
            if col_state:
                df = df[df[col_state].isin(states)]
            if df.empty:
                return pd.DataFrame(columns=cols)
        grouped = (
            df.groupby(col_src)
              .agg(distinct_ports=(col_port, "nunique"),
                   distinct_hosts=(col_dst, "nunique"),
                   total_conns=(col_port, "size"))
              .reset_index().rename(columns={col_src: "src_ip"})
        )
        return grouped.sort_values("distinct_ports", ascending=False)

    @staticmethod
    def udp_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
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
        df = df[df[col_proto].astype(str).str.lower() == "udp"]
        if df.empty:
            return pd.DataFrame(columns=cols)
        grouped = (
            df.groupby(col_src)
              .agg(distinct_ports=(col_port, "nunique"),
                   distinct_hosts=(col_dst, "nunique"),
                   total_conns=(col_port, "size"))
              .reset_index().rename(columns={col_src: "src_ip"})
        )
        return grouped.sort_values("distinct_ports", ascending=False)

    @staticmethod
    def vertical_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
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
              .reset_index().rename(columns={col_src: "src_ip", col_dst: "dst_ip"})
        )
        return grouped.sort_values("distinct_ports", ascending=False)

    @staticmethod
    def horizontal_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
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
              .reset_index().rename(columns={col_src: "src_ip", col_port: "dst_port"})
        )
        return grouped.sort_values("distinct_hosts", ascending=False)

    @staticmethod
    def slow_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
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
                continue
            times = g[col_ts].sort_values().to_numpy()
            duration = float(times[-1] - times[0])
            mean_interval = duration / (len(times) - 1) if len(times) > 1 else 0.0
            rows.append({"src_ip": src, "dst_ip": dst, "distinct_ports": n_ports,
                         "duration": round(duration, 2), "mean_interval": round(mean_interval, 2)})
        return pd.DataFrame(rows, columns=cols).sort_values("mean_interval", ascending=False)

    @staticmethod
    def stealth_scan_features(conn: pd.DataFrame) -> pd.DataFrame:
        cols = ["src_ip", "dst_ip", "scan_type", "stealth_conns", "distinct_ports"]
        if conn is None or conn.empty:
            return pd.DataFrame(columns=cols)
        df = conn.copy()
        col_src   = _first_col(df, ["id.orig_h", "orig_h", "src_ip"])
        col_dst   = _first_col(df, ["id.resp_h", "resp_h", "dst_ip"])
        col_port  = _first_col(df, ["id.resp_p", "resp_p", "dst_port"])
        col_proto = _first_col(df, ["proto", "protocol"])
        col_hist  = _first_col(df, ["history"])
        if not (col_src and col_dst and col_port and col_hist):
            return pd.DataFrame(columns=cols)
        if col_proto:
            df = df[df[col_proto].astype(str).str.lower() == "tcp"]
        if df.empty:
            return pd.DataFrame(columns=cols)
        def _orig_flags(hist):
            hist = "" if hist is None else str(hist)
            return {c for c in hist if c in "SFRAPU"}
        def _classify(flags):
            if "S" in flags:
                return None
            if "F" in flags and "P" in flags:
                return "Xmas"
            if "F" in flags:
                return "FIN"
            if len(flags) == 0:
                return "NULL"
            return None
        df["_flags"] = df[col_hist].apply(_orig_flags)
        df["_stype"] = df["_flags"].apply(_classify)
        df = df[df["_stype"].notna()]
        if df.empty:
            return pd.DataFrame(columns=cols)
        rows = []
        for (src, dst), g in df.groupby([col_src, col_dst]):
            scan_type = g["_stype"].mode().iloc[0]
            rows.append({"src_ip": src, "dst_ip": dst, "scan_type": scan_type,
                         "stealth_conns": int(len(g)), "distinct_ports": int(g[col_port].nunique())})
        return pd.DataFrame(rows, columns=cols).sort_values("distinct_ports", ascending=False)

    @staticmethod
    def brute_force_features(conn: pd.DataFrame, port: int = 22) -> pd.DataFrame:
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
        df[col_port] = pd.to_numeric(df[col_port], errors="coerce")
        df = df[df[col_port] == port]
        if df.empty:
            return pd.DataFrame(columns=cols)
        failed_states = {"REJ", "S0", "RSTO", "RSTR", "RSTOS0", "SH"}
        if col_state:
            df = df[df[col_state].isin(failed_states)]
        if df.empty:
            return pd.DataFrame(columns=cols)
        grouped = (
            df.groupby(col_src)
              .agg(failed_attempts=(col_port, "size"),
                   dst_ip=(col_dst, "first") if col_dst else (col_port, "size"))
              .reset_index().rename(columns={col_src: "src_ip"})
        )
        return grouped.sort_values("failed_attempts", ascending=False)

    @staticmethod
    def beaconing_features(conn: pd.DataFrame) -> pd.DataFrame:
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
        def _is_c2_candidate(ip):
            ip = str(ip)
            if ip.endswith(".255"):
                return False
            first = ip.split(".")[0]
            if first.isdigit() and 224 <= int(first) <= 239:
                return False
            if ip in ("255.255.255.255",):
                return False
            return True
        df = df[df[col_dst].apply(_is_c2_candidate)]
        if df.empty:
            return pd.DataFrame(columns=cols)
        rows = []
        for (src, dst), g in df.groupby([col_src, col_dst]):
            if len(g) < 3:
                continue
            times = g[col_ts].sort_values().to_numpy()
            deltas = times[1:] - times[:-1]
            mean = float(deltas.mean())
            if mean <= 0:
                continue
            std = float(deltas.std())
            rows.append({"src_ip": src, "dst_ip": dst, "n_conns": int(len(g)),
                         "mean_interval": round(mean, 2), "jitter": round(std / mean, 4)})
        return pd.DataFrame(rows, columns=cols).sort_values("jitter")

    @classmethod
    def dns_features(cls, dns: pd.DataFrame) -> pd.DataFrame:
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
            "src_ip": df[col_src] if col_src else "N/A",
            "query":  df[col_query].astype(str),
        })
        out["qlen"]    = out["query"].str.len()
        out["entropy"] = out["query"].apply(cls.shannon_entropy).round(3)
        return out.sort_values("entropy", ascending=False)

    @staticmethod
    def exfil_features(conn: pd.DataFrame) -> pd.DataFrame:
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
              .agg(total_orig_bytes=(col_bytes, "sum"), n_conns=(col_bytes, "size"))
              .reset_index().rename(columns={col_src: "src_ip", col_dst: "dst_ip"})
        )
        return grouped.sort_values("total_orig_bytes", ascending=False)


def _first_col(df: pd.DataFrame, candidates: list[str]) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None
