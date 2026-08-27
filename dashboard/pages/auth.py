"""
Authentification du dashboard ThreatHunter — compte admin unique.

Principe
--------
  * Un seul compte (ADMIN_USERNAME). Seul le HASH bcrypt du mot de passe est
    stocke, dans le fichier .env (ADMIN_PASSWORD_HASH). Jamais de mot de passe
    en clair, ni dans le code, ni dans MongoDB.
  * Stockage dans .env (et PAS dans MongoDB) : le dashboard doit rester
    utilisable en "mode degrade" quand MongoDB est injoignable. Les
    identifiants doivent donc etre disponibles sans base de donnees.
  * Etat de session via st.session_state. Pas de cookie persistant : un
    rafraichissement de l'onglet redemande la connexion (acceptable pour un
    poste operateur SOC).

Creer / mettre a jour le compte admin
-------------------------------------
    python -m dashboard.pages.auth --create-admin

Le script demande un identifiant + un mot de passe (saisie masquee), calcule
le hash bcrypt et affiche (ou ecrit) les deux lignes a placer dans .env :

    ADMIN_USERNAME=admin
    ADMIN_PASSWORD_HASH=$2b$12$....
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Permet `python -m dashboard.pages.auth` ET l'import depuis le dashboard.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

try:
    import bcrypt
    _BCRYPT_OK = True
except ImportError:  # pragma: no cover - dependance declaree dans requirements.txt
    bcrypt = None
    _BCRYPT_OK = False

from config import settings

# Cles de session (prefixe th_ pour ne pas collisionner avec les filtres).
_SESSION_KEY = "th_auth_ok"
_USER_KEY = "th_auth_user"
_ATTEMPTS_KEY = "th_auth_attempts"
_SOFT_LIMIT = 5          # au-dela : temporisation croissante a la connexion
_MIN_PASSWORD_LEN = 8


# ─────────────────────────────────────────────────────────────
#  Verification des identifiants
# ─────────────────────────────────────────────────────────────
def _password_matches(password: str, stored_hash: str) -> bool:
    """Compare un mot de passe au hash bcrypt stocke. Retourne False (jamais
    d'exception) si le hash est absent ou malforme."""
    if not password or not stored_hash or not _BCRYPT_OK:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def verify_credentials(username: str, password: str) -> bool:
    """Verifie l'identifiant + le mot de passe contre la config (.env)."""
    expected_user = (getattr(settings, "ADMIN_USERNAME", "") or "").strip()
    stored_hash = (getattr(settings, "ADMIN_PASSWORD_HASH", "") or "").strip()
    if not expected_user or not stored_hash:
        return False
    if (username or "").strip() != expected_user:
        return False
    return _password_matches(password, stored_hash)


def admin_configured() -> bool:
    """True si un identifiant ET un hash sont presents dans la config."""
    return bool((getattr(settings, "ADMIN_USERNAME", "") or "").strip()
                and (getattr(settings, "ADMIN_PASSWORD_HASH", "") or "").strip())


# ─────────────────────────────────────────────────────────────
#  Etat de session
# ─────────────────────────────────────────────────────────────
def is_authenticated() -> bool:
    import streamlit as st
    return bool(st.session_state.get(_SESSION_KEY))


def current_user() -> str:
    import streamlit as st
    return st.session_state.get(_USER_KEY, "")


def logout() -> None:
    import streamlit as st
    for k in (_SESSION_KEY, _USER_KEY, _ATTEMPTS_KEY):
        st.session_state.pop(k, None)


# ─────────────────────────────────────────────────────────────
#  UI — ecran de connexion
# ─────────────────────────────────────────────────────────────
def _login_screen(logo_uri: str | None = None) -> None:
    """Ecran de connexion centre. Rien d'autre n'est rendu tant que
    l'utilisateur n'est pas authentifie."""
    import streamlit as st

    # La sidebar n'a pas de sens avant connexion : on la masque.
    st.markdown(
        '<style>section[data-testid="stSidebar"]{display:none;}</style>',
        unsafe_allow_html=True)

    mark = (f'<img src="{logo_uri}" alt="Keystone Group">' if logo_uri
            else '<span style="color:#e01e2b;font-size:1.3rem;">&#9670;</span>')

    _, mid, _ = st.columns([1, 1.15, 1])
    with mid:
        with st.container(key="th_login_box"):
            st.markdown(f"""
            <div class="th-login-head">
              <div class="th-login-mark">{mark}</div>
              <div>
                <div class="th-login-title">ThreatHunter</div>
                <div class="th-login-sub">SOC · Keystone Group</div>
              </div>
            </div>
            <div class="th-login-hint">Sign in to access the console</div>
            """, unsafe_allow_html=True)

            if not admin_configured():
                st.error(
                    "No admin account configured. Run "
                    "`python -m dashboard.pages.auth --create-admin`, then set "
                    "`ADMIN_USERNAME` and `ADMIN_PASSWORD_HASH` in the project `.env`.")
                st.stop()
            if not _BCRYPT_OK:
                st.error("`bcrypt` is not installed. Run `pip install -r requirements.txt`.")
                st.stop()

            with st.form("th_login_form", clear_on_submit=False, border=False):
                username = st.text_input("Username", key="th_login_user")
                password = st.text_input("Password", type="password", key="th_login_pwd")
                submitted = st.form_submit_button(
                    "Sign in", type="primary", use_container_width=True)

            if submitted:
                attempts = int(st.session_state.get(_ATTEMPTS_KEY, 0))
                # Temporisation anti-force-brute, croissante et bornee.
                if attempts >= _SOFT_LIMIT:
                    time.sleep(min(1.5 + (attempts - _SOFT_LIMIT) * 1.0, 8.0))
                if verify_credentials(username, password):
                    st.session_state[_SESSION_KEY] = True
                    st.session_state[_USER_KEY] = (username or "").strip()
                    st.session_state.pop(_ATTEMPTS_KEY, None)
                    st.rerun()
                else:
                    st.session_state[_ATTEMPTS_KEY] = attempts + 1
                    st.error("Invalid username or password.")


def require_auth(logo_uri: str | None = None) -> None:
    """Barriere d'authentification. A appeler dans main() juste apres
    inject_theme(). Si l'utilisateur n'est pas connecte : affiche le login et
    stoppe le rendu de la page (aucune page ni donnee n'est chargee)."""
    import streamlit as st
    if is_authenticated():
        return
    _login_screen(logo_uri)
    st.stop()


def logout_button() -> None:
    """Identite de session (avatar + nom + role) + bouton 'Sign out'.

    Sensible au conteneur : rend via `st.*` (et non `st.sidebar.*`) pour se
    placer la ou l'appelant l'invoque — ici la Zone 1 de la barre laterale."""
    import html as _html
    import streamlit as st
    user = (current_user() or "admin").strip() or "admin"
    initial = _html.escape(user[:1].upper())
    # Avatar + (nom / role) alignes verticalement : le wrapper texte est une
    # colonne flex, pas un <span> a enfants block (evite tout chevauchement).
    st.markdown(
        f'<div class="th-session">'
        f'<span class="th-session-avatar">{initial}</span>'
        f'<span class="th-session-id">'
        f'<span class="th-session-name">{_html.escape(user)}</span>'
        f'<span class="th-session-role">Administrator</span>'
        f'</span></div>',
        unsafe_allow_html=True)
    if st.button("Sign out", icon=":material/logout:",
                 use_container_width=True, key="th_logout_btn"):
        logout()
        st.rerun()


# ─────────────────────────────────────────────────────────────
#  CLI — creation / mise a jour du compte admin
# ─────────────────────────────────────────────────────────────
def _upsert_env(path: Path, values: dict[str, str]) -> None:
    """Ecrit/remplace des cles KEY=VALUE dans un fichier .env, en preservant le
    reste du fichier."""
    lines = path.read_text().splitlines() if path.exists() else []
    keys = set(values)
    out: list[str] = []
    seen: set[str] = set()
    for ln in lines:
        key = ln.split("=", 1)[0].strip() if "=" in ln and not ln.lstrip().startswith("#") else None
        if key in keys:
            out.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            out.append(ln)
    for k, v in values.items():
        if k not in seen:
            out.append(f"{k}={v}")
    path.write_text("\n".join(out).rstrip("\n") + "\n")


def _cli_create_admin() -> int:
    import getpass

    if not _BCRYPT_OK:
        print("!! 'bcrypt' n'est pas installe.  ->  pip install -r requirements.txt")
        return 1

    print("ThreatHunter — creation / mise a jour du compte admin")
    print("-" * 52)
    default_user = (getattr(settings, "ADMIN_USERNAME", "") or "admin").strip() or "admin"
    username = input(f"Username [{default_user}]: ").strip() or default_user

    pwd1 = getpass.getpass("Password (min 8 chars): ")
    if len(pwd1) < _MIN_PASSWORD_LEN:
        print(f"!! Mot de passe trop court (min {_MIN_PASSWORD_LEN} caracteres).")
        return 1
    if pwd1 != getpass.getpass("Confirm password: "):
        print("!! Les mots de passe ne correspondent pas.")
        return 1

    hashed = bcrypt.hashpw(pwd1.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    env_path = Path(settings.BASE_DIR) / ".env"

    print("\nLignes a placer dans", env_path, ":\n")
    print(f"ADMIN_USERNAME={username}")
    print(f"ADMIN_PASSWORD_HASH={hashed}\n")

    answer = input(f"Ecrire directement dans {env_path} ? [y/N]: ").strip().lower()
    if answer == "y":
        _upsert_env(env_path, {"ADMIN_USERNAME": username, "ADMIN_PASSWORD_HASH": hashed})
        print(f"OK — {env_path} mis a jour. Redemarre le dashboard.")
    else:
        print("Rien ecrit. Copie les deux lignes ci-dessus dans ton .env.")
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="ThreatHunter — gestion du compte admin du dashboard")
    parser.add_argument("--create-admin", action="store_true",
                        help="Cree/met a jour le compte admin (hash bcrypt -> .env)")
    args = parser.parse_args()

    if args.create_admin:
        sys.exit(_cli_create_admin())
    parser.print_help()
    sys.exit(0)
