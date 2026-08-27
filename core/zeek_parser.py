import pandas as pd
from pathlib import Path
from typing import Optional


class ZeekParser:
    """Lit les logs Zeek d'un dossier et les convertit en DataFrames."""

    # Colonnes qui doivent être numériques (Zeek les écrit en texte)
    NUMERIC_FIELDS = {
        "id.orig_p", "id.resp_p", "duration", "orig_bytes", "resp_bytes",
        "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
        "missed_bytes", "ts",
    }

    def __init__(self, logs_dir: Path):
        self.logs_dir = Path(logs_dir)

    def _read_header(self, path: Path) -> Optional[list]:
        """Extrait la liste des colonnes depuis la ligne '#fields' du log."""
        with open(path, "r") as f:
            for line in f:
                if line.startswith("#fields"):
                    # "#fields\tts\tuid\t..." → ['ts', 'uid', ...]
                    return line.strip().split("\t")[1:]
                if not line.startswith("#"):
                    break   # on a dépassé l'en-tête sans trouver #fields
        return None

    def parse(self, log_name: str) -> pd.DataFrame:
        """
        Lit un log Zeek (ex: 'conn.log') et renvoie un DataFrame.
        Renvoie un DataFrame vide si le fichier n'existe pas.
        """
        path = self.logs_dir / log_name

        if not path.exists():
            print(f"[ZeekParser] Fichier absent : {path}")
            return pd.DataFrame()

        fields = self._read_header(path)
        if not fields:
            print(f"[ZeekParser] En-tête #fields introuvable dans {log_name}")
            return pd.DataFrame()

        # Lecture du TSV en ignorant les lignes de commentaire (#)
        df = pd.read_csv(
            path,
            sep="\t",
            comment="#",
            names=fields,
            na_values=["-", "(empty)"],   # Zeek note les valeurs vides ainsi
            low_memory=False,
        )

        # Conversion des colonnes numériques
        for col in df.columns:
            if col in self.NUMERIC_FIELDS:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        # 'ts' est un timestamp Unix → on ajoute une colonne datetime lisible
        if "ts" in df.columns:
            df["datetime"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")

        print(f"[ZeekParser] {log_name} : {len(df)} lignes, {len(df.columns)} colonnes")
        return df

    # ─── Raccourcis pour les logs les plus utilisés ───────────
    def conn(self) -> pd.DataFrame:
        return self.parse("conn.log")

    def dns(self) -> pd.DataFrame:
        return self.parse("dns.log")

    def http(self) -> pd.DataFrame:
        return self.parse("http.log")

    def ssl(self) -> pd.DataFrame:
        return self.parse("ssl.log")

    def files(self) -> pd.DataFrame:
        return self.parse("files.log")