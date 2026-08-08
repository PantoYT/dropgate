#!/usr/bin/env python3
"""
dropgate — samodzielny, bezpieczny drop plików przez tokenowany link.

Jeden plik, tylko biblioteka standardowa. Postaw gdziekolwiek (python3 >= 3.8),
wpnij w Cloudflare i wyślij komuś plik przez 128-bitowy klucz hex.

  python3 dropgate.py go            # panel w przeglądarce + tunel — wszystko naraz
  python3 dropgate.py share plik.7z # jedna komenda: link gotowy w schowku
  python3 dropgate.py add plik.7z --expires 24h --pass sezam

Dwa serwery, celowo rozdzielone:
  * PUBLICZNY  (tunelowany)  — tylko /d/<token>, nic więcej
  * PANEL      (127.0.0.1)   — dodawanie/kasowanie, NIGDY nie idzie w tunel

Model bezpieczeństwa:
  * token = secrets.token_hex(16) (128 bit) — URL jest capability (nie do zgadnięcia)
  * porównania stałoczasowe (hmac.compare_digest) — brak timing-oracle
  * anti-traversal: serwuje wyłącznie z allowlisty nazw danego share'a
  * opcjonalne hasło (drugi czynnik) — trzymane jako salt+sha256, cookie podpisane HMAC
  * wygasanie czasowe, limit pobrań, linki jednorazowe (burn-after-download)
  * streaming w kawałkach + Range (wznawianie), bez wczytywania pliku do RAM
  * panel: bind na 127.0.0.1, token sesji, sprawdzanie adresu klienta, nagłówek anty-CSRF
"""

import argparse, hashlib, hmac, html, json, mimetypes, os, re, secrets, shutil
import signal, socket, subprocess, sys, tarfile, tempfile, threading, time, webbrowser
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote, unquote

try:
    import fcntl  # POSIX advisory locking — spójny odczyt-modyfikacja-zapis DB
except ImportError:
    fcntl = None

# ── lokalizacja stanu ────────────────────────────────────────────────────────
# Kolejność: $DROPGATE_HOME → <katalog skryptu>/state (gdy leży plik PORTABLE)
# → ~/.dropgate. Dzięki temu ta sama kopia działa i z pendrive'a, i z systemu.

def _resolve_base() -> Path:
    env = os.environ.get("DROPGATE_HOME")
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent
    if (here / "PORTABLE").exists():
        return here / "state"
    return Path.home() / ".dropgate"

BASE = _resolve_base()
DB_PATH = BASE / "shares.json"
SECRET_PATH = BASE / "secret.key"
CONF_PATH = BASE / "config.json"
FILES_DIR = BASE / "files"          # tu lądują pliki wrzucone przez panel / --copy
CHUNK = 256 * 1024                  # 256 KB — rozmiar kawałka streamingu

# ══════════════════════════════════════════════════════════════════════════════
# Warstwa stanu (DB) — atomowy zapis + blokada plikowa między procesami
# ══════════════════════════════════════════════════════════════════════════════

def ensure_base():
    BASE.mkdir(parents=True, exist_ok=True)
    try: os.chmod(BASE, 0o700)
    except OSError: pass
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(secrets.token_bytes(32))
        try: os.chmod(SECRET_PATH, 0o600)
        except OSError: pass
    if not DB_PATH.exists():
        _write_raw({"shares": {}})

def server_secret() -> bytes:
    return SECRET_PATH.read_bytes()

@contextmanager
def _locked(path: Path, exclusive: bool):
    """Blokada advisory na osobnym pliku-latch; brak fcntl → no-op (best effort)."""
    latch = path.with_suffix(path.suffix + ".lock")
    f = open(latch, "a+")
    try:
        if fcntl:
            fcntl.flock(f, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        if fcntl:
            fcntl.flock(f, fcntl.LOCK_UN)
        f.close()

def _write_raw(obj: dict):
    tmp = DB_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), "utf-8")
    try: os.chmod(tmp, 0o600)
    except OSError: pass
    os.replace(tmp, DB_PATH)  # atomowa podmiana

def db_load() -> dict:
    with _locked(DB_PATH, exclusive=False):
        try:
            return json.loads(DB_PATH.read_text("utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {"shares": {}}

def db_update(mutator):
    """Read-modify-write pod wyłączną blokadą. mutator(data) -> opcjonalny wynik."""
    with _locked(DB_PATH, exclusive=True):
        try:
            data = json.loads(DB_PATH.read_text("utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            data = {"shares": {}}
        result = mutator(data)
        _write_raw(data)
        return result

# ── konfiguracja (tryb tunelu, stała domena) ─────────────────────────────────

DEFAULT_BACKUP = {
    "host": "",             # np. 192.168.33.10 — pusty = backup wyłączony
    "user": "",
    "key": "backup_key",            # klucz prywatny, ścieżka względem katalogu stanu
    "known_hosts": "known_hosts",   # przypięty klucz hosta — działa na obcym PC
    "auto": True,           # backup po każdej zmianie bazy (w trybie `go`)
    "keep": 10,             # ile kopii trzymać na serwerze
    "timeout": 8,           # sekundy na nawiązanie połączenia
    "retry_after": 300,     # karencja po nieudanej próbie — żeby nie dobijać serwera
}

DEFAULT_CONF = {
    "mode": "quick",        # quick | named | off
    "hostname": "",         # dla mode=named, np. drop.panto-dev.com
    "tunnel_id": "",        # UUID nazwanego tunelu
    "credentials": "tunnel.json",   # ścieżka względem katalogu stanu
    "port": 8787,
    "admin_port": 8788,
    "default_expires": "24h",
    "backup": dict(DEFAULT_BACKUP),
}

def conf_load() -> dict:
    c = dict(DEFAULT_CONF)
    try:
        c.update(json.loads(CONF_PATH.read_text("utf-8")))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    c["backup"] = {**DEFAULT_BACKUP, **(c.get("backup") or {})}
    return c

def conf_save(c: dict):
    CONF_PATH.write_text(json.dumps(c, ensure_ascii=False, indent=2), "utf-8")
    try: os.chmod(CONF_PATH, 0o600)
    except OSError: pass

def conf_path_abs(rel: str) -> Path:
    p = Path(rel)
    return p if p.is_absolute() else (BASE / p)

# ══════════════════════════════════════════════════════════════════════════════
# Logika share'ów
# ══════════════════════════════════════════════════════════════════════════════

def parse_duration(s: str):
    if s is None: return None
    s = s.strip().lower()
    if s in ("never", "none", "0", "inf", "nigdy"): return None
    m = re.fullmatch(r"(\d+)\s*([smhdw])", s)
    if not m:
        raise ValueError(f"zły format czasu: {s!r} (użyj np. 30m, 12h, 7d, never)")
    unit = {"s":1, "m":60, "h":3600, "d":86400, "w":604800}[m.group(2)]
    return int(m.group(1)) * unit

def hash_pass(passphrase: str):
    if not passphrase: return None
    salt = secrets.token_hex(8)
    dig = hashlib.sha256((salt + ":" + passphrase).encode()).hexdigest()
    return {"salt": salt, "hash": dig}

def check_pass(rec: dict, attempt: str) -> bool:
    if not rec: return True
    dig = hashlib.sha256((rec["salt"] + ":" + (attempt or "")).encode()).hexdigest()
    return hmac.compare_digest(dig, rec["hash"])

def file_entry(p: Path) -> dict:
    """Wpis pliku. Dodatkowo ścieżka względem korzenia wolumenu — dzięki temu
    share na pendrivie przeżywa zmianę litery dysku na innym komputerze."""
    p = Path(p).expanduser().resolve()
    e = {"name": p.name, "path": str(p), "size": p.stat().st_size}
    anchor = BASE.resolve().anchor
    if anchor:
        try:
            e["rel"] = p.relative_to(anchor).as_posix()
        except ValueError:
            pass  # inny wolumen niż stan — zostaje ścieżka absolutna
    return e

def entry_path(e: dict) -> Path:
    rel = e.get("rel")
    if rel:
        anchor = BASE.resolve().anchor
        if anchor:
            cand = Path(anchor) / rel
            if cand.is_file():
                return cand
    return Path(e.get("path", ""))

def import_file(src: Path, token: str) -> Path:
    """Kopiuje plik do magazynu (BASE/files/<token>/) — share przestaje zależeć
    od oryginału i jedzie razem z pendrivem."""
    dst_dir = FILES_DIR / token[:12]
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / Path(src).name
    shutil.copy2(src, dst)
    return dst

def make_share(paths, expires=None, maxdl=None, once=False, passphrase=None,
               label=None, copy=False):
    token = secrets.token_hex(16)
    files = []
    for p in paths:
        p = Path(p).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"nie plik: {p}")
        if copy:
            p = import_file(p, token)
        files.append(file_entry(p))
    if not files:
        raise ValueError("brak plików do udostępnienia")
    now = time.time()
    rec = {
        "token": token,
        "created": now,
        "expires": (now + expires) if expires else None,
        "max": maxdl,
        "once": bool(once),
        "downloads": 0,
        "label": label or files[0]["name"],
        "pass": hash_pass(passphrase),
        "files": files,
    }
    db_update(lambda d: d["shares"].__setitem__(token, rec))
    return rec

def drop_share(token: str) -> bool:
    """Kasuje share i sprząta pliki, które dropgate sam skopiował."""
    rec = db_update(lambda d: d["shares"].pop(token, None))
    if not rec:
        return False
    store = FILES_DIR / token[:12]
    if store.is_dir():
        shutil.rmtree(store, ignore_errors=True)
    return True

def share_alive(rec: dict):
    """Zwraca (ok, powód). Nie modyfikuje stanu."""
    if rec is None: return False, "brak"
    if rec.get("expires") and time.time() > rec["expires"]:
        return False, "wygasł"
    if rec.get("max") is not None and rec.get("downloads", 0) >= rec["max"]:
        return False, "limit pobrań"
    return True, "ok"

def share_size(rec: dict) -> int:
    return sum(f.get("size", 0) for f in rec.get("files", []))

# ══════════════════════════════════════════════════════════════════════════════
# Backup na własny serwer po SSH — pendrive przestaje być pojedynczym punktem awarii
#
# Po drugiej stronie siedzi ~/dropgate-recv.sh przypięty do klucza przez
# `restrict,command="…"` w authorized_keys: ten klucz nie daje shella, umie
# wyłącznie list / put / get / prune / stat. Zgubiony pendrive nie daje więc
# dostępu do serwera — tylko do własnych kopii.
# ══════════════════════════════════════════════════════════════════════════════

BACKUP_STATE = BASE / "backup-state.json"
BACKUP_NAME_RE = re.compile(r"^dropgate-\d{8}-\d{6}\.tar\.gz$")
BACKUP_SKIP = (".lock", ".tmp", ".part")

class BackupError(Exception):
    pass

def backup_conf(conf=None) -> dict:
    conf = conf or conf_load()
    return {**DEFAULT_BACKUP, **(conf.get("backup") or {})}

def backup_ready(conf=None):
    """Zwraca (gotowy, powód-jeśli-nie)."""
    b = backup_conf(conf)
    if not (b.get("host") and b.get("user")):
        return False, "nieskonfigurowany"
    if not conf_path_abs(b["key"]).is_file():
        return False, f"brak klucza {b['key']}"
    if not shutil.which("ssh"):
        return False, "brak klienta ssh"
    return True, ""

def _ssh_args(b: dict, remote: str, key: Path):
    args = [shutil.which("ssh"), "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={int(b.get('timeout', 8))}",
            "-o", "IdentitiesOnly=yes",
            "-i", str(key)]
    kh = conf_path_abs(b.get("known_hosts") or "known_hosts")
    if kh.is_file():                      # przypięty klucz hosta = działa wszędzie
        args += ["-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={kh}"]
    return args + [f"{b['user']}@{b['host']}", remote]

# OpenSSH na Windowsie odmawia użycia klucza, do którego ma dostęp "Everyone" —
# a dokładnie takie ACL ma plik na pendrivie. Wtedy robimy prywatną kopię klucza
# w katalogu tymczasowym, używamy jej i kasujemy.
_KEY_REJECTED_RE = re.compile(
    r"bad permissions|bad owner|UNPROTECTED PRIVATE KEY|are too open|Permission denied",
    re.I)

@contextmanager
def _private_key_copy(src: Path):
    tmp = Path(tempfile.gettempdir()) / f"dropgate-key-{secrets.token_hex(6)}"
    tmp.write_bytes(src.read_bytes())
    try:
        if os.name == "nt":
            who = os.environ.get("USERNAME", "")
            dom = os.environ.get("USERDOMAIN", "")
            acct = f"{dom}\\{who}" if dom and who else who
            if acct:
                subprocess.run(["icacls", str(tmp), "/inheritance:r", "/grant:r", f"{acct}:F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            os.chmod(tmp, 0o600)
        yield tmp
    finally:
        try:
            with open(tmp, "r+b") as fh:          # nadpisz przed skasowaniem
                n = fh.seek(0, os.SEEK_END); fh.seek(0); fh.write(secrets.token_bytes(n))
        except OSError:
            pass
        try: tmp.unlink()
        except OSError: pass

def _ssh_stderr(raw: bytes) -> str:
    lines = [l.strip() for l in (raw or b"").decode("utf-8", "replace").splitlines()]
    lines = [l for l in lines if l and not l.startswith("@") and "WARNING:" not in l]
    return " / ".join(lines[-2:]) if lines else ""

def _ssh_once(b, remote, key, stdin, timeout):
    if stdin is not None and hasattr(stdin, "seek"):
        stdin.seek(0)
    try:
        return subprocess.run(_ssh_args(b, remote, key), stdin=stdin, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError) as e:
        raise BackupError(str(e))

def _ssh(b: dict, remote: str, stdin=None, capture_bytes=False, timeout=None):
    if not shutil.which("ssh"):
        raise BackupError("brak klienta ssh w PATH")
    key = conf_path_abs(b["key"])
    r = _ssh_once(b, remote, key, stdin, timeout)
    if r.returncode != 0 and _KEY_REJECTED_RE.search((r.stderr or b"").decode("utf-8", "replace")):
        with _private_key_copy(key) as tmpkey:    # pendrive → prywatna kopia klucza
            r = _ssh_once(b, remote, tmpkey, stdin, timeout)
    if r.returncode != 0:
        raise BackupError(_ssh_stderr(r.stderr) or f"ssh zakończył się kodem {r.returncode}")
    return r.stdout if capture_bytes else r.stdout.decode("utf-8", "replace").strip()

def backup_state() -> dict:
    try:
        st = json.loads(BACKUP_STATE.read_text("utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    if "ok_at" not in st and st.get("name") and st.get("ok") is not False:
        st["ok_at"] = st.get("at")            # stan sprzed rozdzielenia próba/sukces
    return st

def _set_backup_state(**kw):
    st = backup_state(); st.update(kw); st["at"] = time.time()
    if kw.get("ok"):
        st["ok_at"] = st["at"]                 # osobno: kiedy ostatnio SIĘ UDAŁO
    try:
        BACKUP_STATE.write_text(json.dumps(st, ensure_ascii=False, indent=2), "utf-8")
    except OSError:
        pass

def _tar_state(dst: Path) -> int:
    """Pakuje katalog stanu (bez blokad i śmieci) do archiwum."""
    def keep(p: Path) -> bool:
        return not (p.suffix in BACKUP_SKIP or p.name == dst.name
                    or p.name == BACKUP_STATE.name or p.name == "cloudflared.yml")
    with tarfile.open(dst, "w:gz", compresslevel=1) as tar:
        for item in sorted(BASE.iterdir()):
            if item.is_file() and keep(item):
                tar.add(item, arcname=item.name)
        if FILES_DIR.is_dir():
            for f in sorted(FILES_DIR.rglob("*")):
                if f.is_file() and keep(f):
                    tar.add(f, arcname=f.relative_to(BASE).as_posix())
    return dst.stat().st_size

_BACKUP_LOCK = threading.Lock()

def backup_run(conf=None, reason="ręcznie") -> dict:
    conf = conf or conf_load()
    ok, why = backup_ready(conf)
    if not ok:
        raise BackupError(why)
    if not _BACKUP_LOCK.acquire(blocking=False):
        raise BackupError("backup już trwa")
    RT.backup_busy = True
    b = backup_conf(conf)
    name = "dropgate-" + time.strftime("%Y%m%d-%H%M%S") + ".tar.gz"
    tmp = BASE / (name + ".tmp")
    try:
        try:
            size = _tar_state(tmp)
            with open(tmp, "rb") as fh:
                _ssh(b, f"put {name}", stdin=fh)
        except (BackupError, OSError) as e:
            _set_backup_state(ok=False, msg=str(e), reason=reason)
            raise BackupError(str(e))
        finally:
            try: tmp.unlink()
            except OSError: pass
        try:
            _ssh(b, f"prune {int(b.get('keep', 10))}")
        except BackupError:
            pass                              # prune to sprzątanie, nie powód do alarmu
        _set_backup_state(ok=True, msg="", name=name, size=size, reason=reason)
        return {"name": name, "size": size}
    finally:
        RT.backup_busy = False
        _BACKUP_LOCK.release()

def backup_list(conf=None):
    conf = conf or conf_load()
    ok, why = backup_ready(conf)
    if not ok:
        raise BackupError(why)
    out = _ssh(backup_conf(conf), "list")
    return [l.strip() for l in out.splitlines() if BACKUP_NAME_RE.match(l.strip())]

def backup_remote_stat(conf=None) -> dict:
    conf = conf or conf_load()
    ok, why = backup_ready(conf)
    if not ok:
        raise BackupError(why)
    d = {}
    for line in _ssh(backup_conf(conf), "stat").splitlines():
        k, _, v = line.partition(" ")
        d[k] = v
    return d

def _safe_members(tar: tarfile.TarFile):
    """Tylko zwykłe pliki, względne ścieżki, bez '..' i bez linków."""
    for m in tar.getmembers():
        name = m.name.replace("\\", "/")
        if m.issym() or m.islnk() or name.startswith("/") or ".." in name.split("/"):
            continue
        if not (m.isfile() or m.isdir()):
            continue
        m.name = name
        yield m

def backup_restore(name=None, conf=None) -> dict:
    conf = conf or conf_load()
    ok, why = backup_ready(conf)
    if not ok:
        raise BackupError(why)
    b = backup_conf(conf)
    if not name:
        avail = backup_list(conf)
        if not avail:
            raise BackupError("na serwerze nie ma żadnego backupu")
        name = avail[0]
    if not BACKUP_NAME_RE.match(name):
        raise BackupError(f"zła nazwa backupu: {name}")
    blob = _ssh(b, f"get {name}", capture_bytes=True)
    tmp = BASE / (name + ".dl")
    tmp.write_bytes(blob)
    try:
        with tarfile.open(tmp, "r:gz") as tar:
            members = list(_safe_members(tar))
            tar.extractall(BASE, members=members)
    finally:
        try: tmp.unlink()
        except OSError: pass
    return {"name": name, "size": len(blob), "files": len(members)}

def _db_signature():
    try:
        st = DB_PATH.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None

def start_autobackup(conf: dict):
    """Pilnuje bazy i po zmianie (z chwilą wyciszenia) wysyła kopię."""
    b = backup_conf(conf)
    ok, why = backup_ready(conf)
    if not b.get("auto"):
        return
    if not ok:
        if b.get("host"):
            print(f"! auto-backup wyłączony: {why}", file=sys.stderr)
        return

    def loop():
        last = _db_signature()
        cooldown = int(b.get("retry_after", 300))
        failed_at = 0.0
        while True:
            time.sleep(10)
            sig = _db_signature()
            if sig == last:
                continue
            # po nieudanej próbie odczekaj — nie dobijaj serwera, który nie odpowiada
            # (seria nieudanych logowań to prosta droga do bana od fail2ban)
            if failed_at and time.time() - failed_at < cooldown:
                continue
            time.sleep(5)                     # wyciszenie — poczekaj na koniec uploadu
            sig = _db_signature()
            try:
                r = backup_run(conf, reason="auto")
                print(f"• backup: {r['name']} ({fmt_size(r['size'])})", file=sys.stderr)
                failed_at = 0.0
                last = sig
            except BackupError as e:
                failed_at = time.time()
                print(f"! backup nieudany: {e} — kolejna próba za {cooldown // 60} min",
                      file=sys.stderr)

    threading.Thread(target=loop, daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
# Stan procesu (adres publiczny, tunel) — współdzielony między wątkami
# ══════════════════════════════════════════════════════════════════════════════

class Runtime:
    def __init__(self):
        self.base_url = ""        # publiczny adres bez końcowego /
        self.lan_url = ""
        self.local_url = ""       # http://127.0.0.1:<port> — awaryjnie, zanim wstanie tunel
        self.tunnel = "off"       # off | starting | up | error
        self.tunnel_msg = ""
        self.admin_token = ""
        self.pub_port = 0
        self.backup_busy = False

RT = Runtime()

def link_base() -> str:
    return RT.base_url or RT.lan_url or RT.local_url

def public_link(token: str) -> str:
    base = link_base()
    return f"{base}/d/{token}" if base else f"/d/{token}"

# ══════════════════════════════════════════════════════════════════════════════
# HTTP — część wspólna
# ══════════════════════════════════════════════════════════════════════════════

def sign_unlock(token: str, passrec: dict) -> str:
    msg = f"{token}:{passrec['hash']}".encode()
    return hmac.new(server_secret(), msg, hashlib.sha256).hexdigest()

def fmt_size(n: int) -> str:
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

MONO = ('ui-monospace,SFMono-Regular,"SF Mono","Cascadia Mono",'
        'Menlo,Consolas,"Liberation Mono",monospace')

PAGE_CSS = """
:root{--bg:#0a0a0c;--fg:#ededef;--dim:#75757e;--line:#1d1d23;--acc:#ffb43f;--err:#ff6b6b}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--fg);
font:14px/1.65 %MONO%;display:flex;align-items:center;justify-content:center;padding:28px}
.card{width:100%;max-width:440px}
h1{font-size:15px;font-weight:600;margin:0;letter-spacing:-.01em}
.muted{color:var(--dim);font-size:12px;margin:2px 0 24px}
ul{list-style:none;padding:0;margin:0;border-top:1px solid var(--line)}
li{display:flex;justify-content:space-between;align-items:baseline;gap:16px;
padding:13px 4px;border-bottom:1px solid var(--line)}
li:hover{background:#101013}
a.f{color:var(--fg);text-decoration:none;word-break:break-all}
a.f:hover{color:var(--acc)}
.sz{color:var(--dim);font-size:12px;white-space:nowrap;font-variant-numeric:tabular-nums}
.badge{color:var(--dim);font-size:11px;letter-spacing:.06em;text-transform:uppercase;
margin-top:16px}
input[type=password]{width:100%;background:transparent;border:1px solid var(--line);
color:var(--fg);border-radius:2px;padding:11px 12px;font:14px %MONO%;margin:6px 0 10px;
outline:none}
input[type=password]:focus{border-color:var(--acc)}
button{width:100%;font:600 13px %MONO%;color:#0a0a0c;background:var(--acc);
border:0;border-radius:2px;padding:11px;cursor:pointer;letter-spacing:.02em}
button:hover{background:#ffc46a}
.err{color:var(--err);font-size:12px;margin:0 0 8px}
.foot{color:#4a4a52;font-size:11px;margin:26px 0 0;letter-spacing:.06em;
text-transform:uppercase}
.brand{color:var(--dim)}
""".replace("%MONO%", MONO)

def page(title: str, body: str) -> bytes:
    return (f"<!doctype html><html lang=pl><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{PAGE_CSS}</style></head>"
            f"<body><div class=card>{body}"
            f"<p class=foot><span class=brand>dropgate</span></p>"
            f"</div></body></html>").encode("utf-8")

class BaseHandler(BaseHTTPRequestHandler):
    server_version = "dropgate"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def _send(self, body: bytes, code=200, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj, ensure_ascii=False).encode("utf-8"), code=code,
                   ctype="application/json; charset=utf-8")

    def _notfound(self):
        self._send(page("nie znaleziono",
                        "<h1>Nie znaleziono</h1><p class=muted>Link nieaktywny, wygasł "
                        "lub błędny.</p>"), code=404)

    def log_message(self, fmt, *args):
        if os.environ.get("DROPGATE_QUIET"):
            return
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

# ══════════════════════════════════════════════════════════════════════════════
# Serwer PUBLICZNY — wyłącznie /d/<token>[/<plik>]
# ══════════════════════════════════════════════════════════════════════════════

class Handler(BaseHandler):

    def do_HEAD(self): self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        parts = [unquote(p) for p in u.path.split("/") if p != ""]
        if not parts:
            return self._send(page("dropgate", "<h1>dropgate</h1>"
                                   "<p class=muted>Serwer działa. Potrzebujesz linku z tokenem.</p>"))
        if parts[0] == "d" and len(parts) == 2:
            return self._share_index(parts[1])
        if parts[0] == "d" and len(parts) == 3:
            return self._share_file(parts[1], parts[2])
        return self._notfound()

    def do_POST(self):
        u = urlparse(self.path)
        parts = [unquote(p) for p in u.path.split("/") if p != ""]
        if parts[:1] == ["d"] and len(parts) == 2:
            return self._unlock(parts[1])
        return self._notfound()

    # ── uwierzytelnienie hasłem (opcjonalne) ──
    def _unlocked(self, token: str, rec: dict) -> bool:
        passrec = rec.get("pass")
        if not passrec:
            return True
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        key = f"dg_{token}"
        if key not in cookie:
            return False
        return hmac.compare_digest(cookie[key].value, sign_unlock(token, passrec))

    def _unlock(self, token: str):
        rec = db_load()["shares"].get(token)
        ok, _ = share_alive(rec)
        if not rec or not ok:
            return self._notfound()
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        attempt = parse_qs(body.decode("utf-8", "replace")).get("k", [""])[0]
        if rec.get("pass") and check_pass(rec["pass"], attempt):
            cval = sign_unlock(token, rec["pass"])
            cookie = f"dg_{token}={cval}; Path=/d/{token}; HttpOnly; SameSite=Strict; Max-Age=86400"
            return self._send(b"", code=303, extra=[("Location", f"/d/{token}"),
                                                    ("Set-Cookie", cookie)])
        return self._unlock_form(token, error=True)

    def _unlock_form(self, token: str, error=False):
        err = "<p class=err>Błędne hasło.</p>" if error else ""
        body = (f"<h1>Chronione</h1><p class=muted>Ten drop wymaga hasła.</p>{err}"
                f"<form method=post action='/d/{html.escape(token)}'>"
                f"<input type=password name=k placeholder='hasło' autofocus>"
                f"<button type=submit>Odblokuj</button></form>")
        self._send(page("odblokuj", body), code=401)

    # ── strona-indeks share'a ──
    def _share_index(self, token: str):
        rec = db_load()["shares"].get(token)
        ok, reason = share_alive(rec)
        if not rec or not ok:
            return self._notfound()
        if not self._unlocked(token, rec):
            return self._unlock_form(token)
        rows = ""
        for f in rec["files"]:
            href = f"/d/{quote(token)}/{quote(f['name'])}"
            rows += (f"<li><a class=f href='{href}'>{html.escape(f['name'])}</a>"
                     f"<span class=sz>{fmt_size(f['size'])}</span></li>")
        meta = []
        if rec.get("expires"):
            meta.append("wygasa " + time.strftime("%Y-%m-%d %H:%M", time.localtime(rec["expires"])))
        if rec.get("max") is not None:
            meta.append(f"pobrań {rec.get('downloads',0)}/{rec['max']}")
        if rec.get("once"):
            meta.append("jednorazowy")
        badge = f"<div class=badge>{' · '.join(meta)}</div>" if meta else ""
        body = (f"<h1>{html.escape(rec.get('label') or 'Pliki')}</h1>"
                f"<p class=muted>Kliknij, aby pobrać.</p><ul>{rows}</ul>{badge}")
        self._send(page(rec.get("label") or "pliki", body))

    # ── serwowanie pliku (Range + zliczanie + burn) ──
    def _share_file(self, token: str, name: str):
        rec = db_load()["shares"].get(token)
        ok, reason = share_alive(rec)
        if not rec or not ok:
            return self._notfound()
        if not self._unlocked(token, rec):
            return self._unlock_form(token)
        entry = next((f for f in rec["files"] if f["name"] == os.path.basename(name)), None)
        if not entry:
            return self._notfound()
        path = entry_path(entry)
        if not path.is_file():
            return self._send(page("brak", "<h1>Plik zniknął</h1>"
                                   "<p class=muted>Źródło zostało przeniesione lub usunięte.</p>"),
                              code=410)
        size = path.stat().st_size

        # Range (wznawianie)
        start, end = 0, size - 1
        status = 200
        rng = self.headers.get("Range")
        if rng:
            m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng.strip())
            if m:
                if m.group(1): start = int(m.group(1))
                if m.group(2): end = min(int(m.group(2)), size - 1)
                if start > end or start >= size:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.send_header("Content-Length", "0")
                    self.end_headers(); return
                status = 206

        length = end - start + 1
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Disposition",
                         f'attachment; filename="{entry["name"]}"')
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()

        if self.command == "HEAD":
            return

        # licz jako pobranie tylko przy pełnym starcie (start==0) — Range-resume nie dubluje
        counted = (start == 0)
        try:
            with open(path, "rb") as fh:
                fh.seek(start)
                remaining = length
                while remaining > 0:
                    buf = fh.read(min(CHUNK, remaining))
                    if not buf: break
                    self.wfile.write(buf)
                    remaining -= len(buf)
        except (BrokenPipeError, ConnectionResetError):
            return  # klient przerwał — nie licz

        if counted:
            self._register_download(token)

    def _register_download(self, token: str):
        def mut(data):
            r = data["shares"].get(token)
            if not r: return
            r["downloads"] = r.get("downloads", 0) + 1
            if r.get("once"):
                data["shares"].pop(token, None)  # burn-after-download
        db_update(mut)
        rec = db_load()["shares"].get(token)
        if rec is None:
            store = FILES_DIR / token[:12]
            if store.is_dir():
                shutil.rmtree(store, ignore_errors=True)

# ══════════════════════════════════════════════════════════════════════════════
# Multipart — strumieniowo na dysk (bez wciągania pliku do RAM)
# ══════════════════════════════════════════════════════════════════════════════

class MultipartError(Exception):
    pass

class MultipartStream:
    """Minimalny parser multipart/form-data. Pliki lecą kawałkami do dest_dir."""

    def __init__(self, rfile, length: int, boundary: bytes, dest_dir: Path):
        self.rfile, self.remaining, self.dest = rfile, length, dest_dir
        self.delim = b"--" + boundary
        self.buf = b""
        self.files, self.fields = [], {}

    def _fill(self, want: int):
        while len(self.buf) < want and self.remaining > 0:
            chunk = self.rfile.read(min(CHUNK, self.remaining))
            if not chunk:
                self.remaining = 0
                break
            self.remaining -= len(chunk)
            self.buf += chunk

    def _read_line(self) -> bytes:
        while b"\r\n" not in self.buf:
            before = len(self.buf)
            self._fill(len(self.buf) + 1024)
            if len(self.buf) == before:
                raise MultipartError("urwany strumień")
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def parse(self):
        line = self._read_line()
        if not line.startswith(self.delim):
            raise MultipartError("brak pierwszego separatora")
        while True:
            headers = {}
            while True:
                line = self._read_line()
                if line == b"":
                    break
                k, _, v = line.decode("utf-8", "replace").partition(":")
                headers[k.strip().lower()] = v.strip()
            disp = headers.get("content-disposition", "")
            name = _disp_param(disp, "name")
            filename = _disp_param(disp, "filename")
            if filename:
                more = self._consume_part(self._open_dest(filename))
            else:
                sink = _MemSink()
                more = self._consume_part(sink)
                self.fields[name or ""] = sink.value().decode("utf-8", "replace")
            if not more:
                break
        return self.files, self.fields

    def _open_dest(self, filename: str):
        safe = os.path.basename(filename.replace("\\", "/")).strip()
        safe = re.sub(r'[\x00-\x1f<>:"|?*]', "_", safe) or "plik"
        self.dest.mkdir(parents=True, exist_ok=True)
        path = self.dest / safe
        n = 1
        while path.exists():
            stem, ext = os.path.splitext(safe)
            path = self.dest / f"{stem}({n}){ext}"
            n += 1
        self.files.append(path)
        return open(path, "wb")

    def _consume_part(self, sink) -> bool:
        """Zapisuje ciało part-a do sink; zwraca True gdy są kolejne part-y."""
        sep = b"\r\n" + self.delim
        try:
            while True:
                idx = self.buf.find(sep)
                if idx >= 0:
                    sink.write(self.buf[:idx])
                    self.buf = self.buf[idx + len(sep):]
                    break
                keep = len(sep)
                if len(self.buf) > keep:
                    sink.write(self.buf[:-keep])
                    self.buf = self.buf[-keep:]
                before = len(self.buf)
                self._fill(len(self.buf) + CHUNK)
                if len(self.buf) == before:
                    sink.write(self.buf)
                    self.buf = b""
                    raise MultipartError("urwany upload")
        finally:
            sink.close()
        self._fill(2)
        tail, self.buf = self.buf[:2], self.buf[2:]
        return tail != b"--"

class _MemSink:
    def __init__(self): self.parts = []
    def write(self, b): self.parts.append(b)
    def close(self): pass
    def value(self): return b"".join(self.parts)

def _disp_param(disp: str, key: str):
    m = re.search(rf'{key}="([^"]*)"', disp)
    return m.group(1) if m else None

# ══════════════════════════════════════════════════════════════════════════════
# PANEL — tylko 127.0.0.1, nigdy nie trafia do tunelu
# ══════════════════════════════════════════════════════════════════════════════

PANEL_HTML = r"""<!doctype html><html lang=pl><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>dropgate</title><style>
:root{--bg:#0a0a0c;--fg:#ededef;--dim:#75757e;--dim2:#4e4e57;--line:#1d1d23;
--acc:#ffb43f;--ok:#7ee08a;--err:#ff6b6b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:13px/1.6 %MONO%;-webkit-font-smoothing:antialiased}
.wrap{max-width:760px;margin:0 auto;padding:38px 24px 80px}

/* — nagłówek — */
.top{display:flex;align-items:baseline;justify-content:space-between;gap:16px;
padding-bottom:14px;border-bottom:1px solid var(--line)}
.logo{font-size:14px;font-weight:600;letter-spacing:-.01em}
.logo b{color:var(--acc);font-weight:600}
.state{display:flex;align-items:center;gap:8px;color:var(--dim);font-size:12px;
min-width:0}
.state .host{color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dot{width:6px;height:6px;border-radius:50%;background:var(--dim2);flex:none}
.dot.up{background:var(--ok)}
.dot.starting{background:var(--acc);animation:blink 1.2s infinite}
.dot.error{background:var(--err)}
@keyframes blink{50%{opacity:.25}}

/* — strefa zrzutu — */
#drop{margin:26px 0 0;border:1px dashed #2a2a32;padding:30px 20px;text-align:center;
cursor:pointer;transition:border-color .12s,background .12s;position:relative}
#drop:hover,#drop.over{border-color:var(--acc);background:#0f0f12}
#drop .big{font-size:13px}
#drop .sub{font-size:11.5px;color:var(--dim);margin-top:5px}
#drop .kbd{color:var(--acc)}
.bar{position:absolute;left:0;bottom:0;height:2px;width:0;background:var(--acc);
transition:width .15s}

/* — opcje — */
.opts{display:flex;flex-wrap:wrap;align-items:center;gap:18px;margin:16px 0 0;
color:var(--dim);font-size:12px}
.opt{display:flex;align-items:center;gap:7px}
label.chk{display:flex;align-items:center;gap:7px;cursor:pointer;user-select:none}
label.chk:hover{color:var(--fg)}
select,input[type=text],input[type=password],input[type=number]{
background:transparent;border:0;border-bottom:1px solid var(--line);color:var(--fg);
padding:3px 2px;font:12px %MONO%;outline:none;border-radius:0}
select{cursor:pointer}
select option{background:#141418}
input:focus,select:focus{border-bottom-color:var(--acc)}
input[type=checkbox]{appearance:none;-webkit-appearance:none;width:12px;height:12px;
border:1px solid #2f2f38;background:transparent;cursor:pointer;position:relative;top:2px;
margin:0;border-radius:0;transition:.1s}
input[type=checkbox]:hover{border-color:var(--acc)}
input[type=checkbox]:checked{background:var(--acc);border-color:var(--acc)}
input[type=checkbox]:checked::after{content:"";position:absolute;left:3px;top:0;
width:3px;height:6px;border:solid var(--bg);border-width:0 1.5px 1.5px 0;
transform:rotate(45deg)}
.pathrow{display:flex;align-items:center;gap:10px;margin-top:16px;
padding-top:16px;border-top:1px solid var(--line)}
.pathrow span{color:var(--dim2);font-size:11.5px;white-space:nowrap}
.pathrow input{flex:1}

/* — lista — */
.lhead{display:flex;align-items:baseline;justify-content:space-between;gap:16px;
margin:46px 0 0;padding-bottom:10px;border-bottom:1px solid var(--line);
font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim2)}
.lhead .bk{cursor:pointer;letter-spacing:.06em}
.lhead .bk:hover{color:var(--fg)}
.row{padding:15px 2px;border-bottom:1px solid var(--line)}
.row:hover{background:#0e0e11}
.row.dead{opacity:.42}
.r1{display:flex;align-items:baseline;gap:12px}
.name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sz{color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums;white-space:nowrap}
.r2{display:flex;align-items:center;gap:12px;margin-top:7px}
.url{color:var(--dim);font-size:12px;cursor:pointer;overflow:hidden;
text-overflow:ellipsis;white-space:nowrap}
.url:hover{color:var(--acc)}
.meta{color:var(--dim2);font-size:11px;margin-top:6px;letter-spacing:.02em}
.acts{margin-left:auto;display:flex;gap:14px;opacity:0;transition:opacity .12s}
.row:hover .acts,.row:focus-within .acts{opacity:1}
.act{color:var(--dim);font-size:11.5px;cursor:pointer;background:0;border:0;
padding:0;font-family:inherit;letter-spacing:.04em}
.act:hover{color:var(--acc)}
.act.rm:hover{color:var(--err)}
.tag{color:var(--dim2);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase}
.empty{color:var(--dim2);padding:22px 2px;font-size:12px}

.toast{position:fixed;left:50%;transform:translateX(-50%) translateY(8px);bottom:28px;
background:#17171c;border:1px solid var(--line);padding:9px 16px;font-size:12px;
opacity:0;transition:.16s;pointer-events:none;color:var(--fg)}
.toast.on{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.bad{border-color:var(--err);color:var(--err)}
</style></head><body><div class=wrap>

<div class=top>
  <div class=logo><b>drop</b>gate</div>
  <div class=state><span class="dot" id=dot></span><span class=host id=st>…</span></div>
</div>

<div id=drop>
  <div class=big>Przeciągnij pliki tutaj</div>
  <div class=sub>albo <span class=kbd>kliknij</span> — kopiuję je do magazynu, link działa po odpięciu źródła</div>
  <input type=file id=file multiple hidden>
  <i class=bar id=bar></i>
</div>

<div class=opts>
  <span class=opt>wygasa
    <select id=exp>
      <option value=1h>za godzinę</option>
      <option value=24h selected>za dobę</option>
      <option value=7d>za tydzień</option>
      <option value=30d>za miesiąc</option>
      <option value=never>nigdy</option>
    </select></span>
  <span class=opt>hasło <input type=password id=pass placeholder="—" style="width:120px"></span>
  <label class=chk><input type=checkbox id=once> jednorazowy</label>
  <label class=chk><input type=checkbox id=maxon> limit
    <input type=number id=max value=1 min=1 style="width:42px"></label>
</div>

<div class=pathrow>
  <span>duży plik bez kopiowania</span>
  <input type=text id=path placeholder="wklej ścieżkę i naciśnij Enter">
</div>

<div class=lhead><span id=cnt>aktywne</span><span class=bk id=bk></span></div>
<div id=list><div class=empty>…</div></div>
</div>
<div class=toast id=toast></div>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let toastT;
function toast(m,bad){const t=$('#toast');t.textContent=m;t.className='toast on'+(bad?' bad':'');
  clearTimeout(toastT);toastT=setTimeout(()=>t.className='toast',2000)}
function copy(txt){navigator.clipboard.writeText(txt).then(()=>toast('link w schowku'),
  ()=>toast('nie udało się skopiować',1))}
function opts(){const p=new URLSearchParams();
  p.set('expires',$('#exp').value);
  if($('#pass').value)p.set('pass',$('#pass').value);
  if($('#once').checked)p.set('once','1');
  if($('#maxon').checked)p.set('max',$('#max').value);
  return p}
async function api(url,body){
  const r=await fetch(url,{method:'POST',headers:{'X-Dropgate':'1','Content-Type':'application/json'},
    body:JSON.stringify(body||{})});
  const j=await r.json().catch(()=>({error:'nieczytelna odpowiedź'}));
  if(!r.ok)throw new Error(j.error||r.status);
  return j}
function shortUrl(u){
  return u.replace(/^https?:\/\//,'').replace(/\/d\/([0-9a-f]{8})[0-9a-f]+([0-9a-f]{4})$/,'/d/$1…$2')}

function render(s){
  $('#dot').className='dot '+s.tunnel;
  $('#st').textContent = s.public ? s.base.replace(/^https?:\/\//,'')
    : s.tunnel==='starting' ? 'stawiam tunel…'
    : s.tunnel==='error' ? 'tunel padł — '+s.msg
    : 'tylko lokalnie';
  $('#st').title = s.public ? s.base : (s.base+' — nie do wysłania na zewnątrz');
  const b=s.backup;
  $('#bk').textContent = !b.on ? '' : (b.busy ? 'backup trwa…'
    : b.ok===false ? 'backup: '+b.msg : (b.ago ? 'backup '+b.ago+' ↻' : 'backup ↻'));
  $('#bk').style.color = (b.on && b.ok===false) ? 'var(--err)' : '';
  $('#cnt').textContent = s.shares.length ? 'aktywne · '+s.shares.length : 'aktywne';
  const L=$('#list');
  if(!s.shares.length){L.innerHTML='<div class=empty>Pusto — przeciągnij plik powyżej.</div>';return}
  L.innerHTML=s.shares.map(x=>`
    <div class="row${x.alive?'':' dead'}">
      <div class=r1>
        <span class=name title="${esc(x.files.map(f=>f.name).join(', '))}">${esc(x.label)}</span>
        <span class=sz>${esc(x.size)}</span>
      </div>
      <div class=r2>
        <span class=url data-copy="${esc(x.url)}" title="${esc(x.url)}">${esc(shortUrl(x.url))}</span>
        <span class=acts>
          <button class=act data-copy="${esc(x.url)}">kopiuj</button>
          <button class="act rm" data-rm="${esc(x.token)}">usuń</button>
        </span>
      </div>
      <div class=meta>${x.files.length>1?x.files.length+' pliki · ':''}${
        x.expires?'wygasa '+esc(x.expires)+' · ':''}pobrań ${x.downloads}${x.max!==null?'/'+x.max:''}${
        x.pass?' · <span class=tag>hasło</span>':''}${x.once?' · <span class=tag>jednorazowy</span>':''}${
        x.alive?'':' · '+esc(x.reason)}</div>
    </div>`).join('');
}

$('#list').addEventListener('click',async e=>{
  const c=e.target.closest('[data-copy]'), r=e.target.closest('[data-rm]');
  if(c)copy(c.dataset.copy);
  if(r){try{await api('/api/rm',{token:r.dataset.rm});toast('usunięte');refresh()}
        catch(err){toast(err.message,1)}}
});
$('#bk').onclick=async()=>{
  if(!$('#bk').textContent)return;
  toast('wysyłam kopię…');
  try{const r=await api('/api/backup');toast('backup: '+r.name)}
  catch(err){toast('backup: '+err.message,1)}
  refresh();
};

const drop=$('#drop');
drop.onclick=()=>$('#file').click();
$('#file').onchange=e=>upload(e.target.files);
;['dragenter','dragover'].forEach(t=>drop.addEventListener(t,e=>{e.preventDefault();drop.classList.add('over')}));
;['dragleave','drop'].forEach(t=>drop.addEventListener(t,e=>{e.preventDefault();drop.classList.remove('over')}));
drop.addEventListener('drop',e=>upload(e.dataTransfer.files));
window.addEventListener('dragover',e=>e.preventDefault());
window.addEventListener('drop',e=>e.preventDefault());

function upload(files){
  if(!files||!files.length)return;
  const fd=new FormData();
  for(const f of files)fd.append('f',f,f.name);
  const xhr=new XMLHttpRequest();
  xhr.open('POST','/api/upload?'+opts().toString());
  xhr.setRequestHeader('X-Dropgate','1');
  xhr.upload.onprogress=e=>{if(e.lengthComputable)$('#bar').style.width=(e.loaded/e.total*100)+'%'};
  xhr.onload=()=>{
    $('#bar').style.width='0';
    if(xhr.status>=200&&xhr.status<300){copy(JSON.parse(xhr.responseText).url);refresh()}
    else{let m=xhr.responseText;try{m=JSON.parse(m).error}catch(e){}toast(m,1)}
  };
  xhr.onerror=()=>{$('#bar').style.width='0';toast('błąd wysyłki',1)};
  xhr.send(fd);
}
$('#path').addEventListener('keydown',async e=>{
  if(e.key!=='Enter')return;
  const p=$('#path').value.trim(); if(!p)return;
  try{
    const o={path:p};for(const [k,v] of opts())o[k]=v;
    const r=await api('/api/path',o);
    $('#path').value='';copy(r.url);refresh();
  }catch(err){toast(err.message,1)}
});
async function refresh(){
  try{const r=await fetch('/api/state');render(await r.json())}catch(e){}
}
refresh();setInterval(refresh,2500);
</script></body></html>""".replace("%MONO%", MONO)

class AdminHandler(BaseHandler):

    # ── dostęp ──
    def _local(self) -> bool:
        ip = self.client_address[0]
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _authed(self) -> bool:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        c = cookie.get("dg_admin")
        return bool(c) and hmac.compare_digest(c.value, RT.admin_token)

    def _deny(self):
        self._send(page("brak dostępu", "<h1>Brak dostępu</h1><p class=muted>Panel dropgate "
                        "jest tylko lokalny. Otwórz link wypisany w konsoli.</p>"), code=403)

    def do_GET(self):
        if not self._local():
            return self._deny()
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/" and q.get("t"):
            if hmac.compare_digest(q["t"][0], RT.admin_token):
                return self._send(b"", code=303, extra=[
                    ("Location", "/"),
                    ("Set-Cookie", f"dg_admin={RT.admin_token}; Path=/; HttpOnly; SameSite=Strict")])
            return self._deny()
        if not self._authed():
            return self._deny()
        if u.path == "/":
            return self._send(PANEL_HTML.encode("utf-8"))
        if u.path == "/api/state":
            return self._json(self._state())
        return self._notfound()

    def do_POST(self):
        if not self._local() or not self._authed():
            return self._deny()
        if self.headers.get("X-Dropgate") != "1":     # anty-CSRF (nie da się z <form>)
            return self._json({"error": "brak nagłówka"}, code=400)
        u = urlparse(self.path)
        try:
            if u.path == "/api/upload":
                return self._upload(parse_qs(u.query))
            if u.path == "/api/path":
                return self._add_path()
            if u.path == "/api/rm":
                return self._rm()
            if u.path == "/api/backup":
                return self._backup()
        except (ValueError, FileNotFoundError, MultipartError, BackupError, OSError) as e:
            return self._json({"error": str(e)}, code=400)
        return self._notfound()

    # ── dane dla panelu ──
    def _state(self):
        out = []
        for tok, r in sorted(db_load()["shares"].items(),
                             key=lambda kv: kv[1].get("created", 0), reverse=True):
            ok, reason = share_alive(r)
            out.append({
                "token": tok,
                "label": r.get("label", "?"),
                "files": [{"name": f["name"], "size": fmt_size(f.get("size", 0))} for f in r["files"]],
                "size": fmt_size(share_size(r)),
                "expires": time.strftime("%d.%m %H:%M", time.localtime(r["expires"])) if r.get("expires") else "",
                "downloads": r.get("downloads", 0),
                "max": r.get("max"),
                "once": bool(r.get("once")),
                "pass": bool(r.get("pass")),
                "alive": ok, "reason": reason,
                "url": public_link(tok),
            })
        bok, bwhy = backup_ready()
        bst = backup_state()
        return {"base": link_base(), "public": bool(RT.base_url or RT.lan_url),
                "tunnel": RT.tunnel, "msg": RT.tunnel_msg, "shares": out,
                "backup": {"on": bok, "why": bwhy, "busy": RT.backup_busy,
                           "ok": bst.get("ok"), "msg": bst.get("msg", ""),
                           "name": bst.get("name", ""),
                           "ago": _ago(bst["ok_at"]) if bst.get("ok_at") else ""}}

    def _opts(self, q: dict):
        def one(k, default=None):
            v = q.get(k, [default])
            return v[0] if v else default
        expires = parse_duration(one("expires", "24h"))
        maxdl = one("max")
        return {
            "expires": expires,
            "maxdl": int(maxdl) if maxdl else None,
            "once": one("once") in ("1", "true", "on"),
            "passphrase": one("pass") or None,
        }

    def _upload(self, q: dict):
        ctype = self.headers.get("Content-Type", "")
        m = re.search(r'boundary=("?)([^";]+)\1', ctype)
        if not m or not ctype.lower().startswith("multipart/form-data"):
            raise ValueError("oczekiwano multipart/form-data")
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            raise ValueError("puste żądanie")
        staging = FILES_DIR / ("_up_" + secrets.token_hex(4))
        try:
            files, _ = MultipartStream(self.rfile, length, m.group(2).encode(), staging).parse()
            if not files:
                raise ValueError("brak plików")
            opt = self._opts(q)
            rec = make_share([str(f) for f in files], copy=False, **opt)
            final = FILES_DIR / rec["token"][:12]
            final.parent.mkdir(parents=True, exist_ok=True)
            staging.rename(final)
            def fix(d):
                for e in d["shares"][rec["token"]]["files"]:
                    e.update(file_entry(final / e["name"]))
            db_update(fix)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        self._json({"token": rec["token"], "url": public_link(rec["token"])})

    def _add_path(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or b"{}")
        p = Path(str(body.get("path", "")).strip().strip('"'))
        if not p.expanduser().is_file():
            raise FileNotFoundError(f"nie ma takiego pliku: {p}")
        opt = self._opts({k: [v] for k, v in body.items() if k != "path"})
        rec = make_share([p], copy=False, **opt)
        self._json({"token": rec["token"], "url": public_link(rec["token"])})

    def _backup(self):
        r = backup_run(reason="panel")
        self._json({"name": r["name"], "size": fmt_size(r["size"])})

    def _rm(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or b"{}")
        token = str(body.get("token", ""))
        matches = [t for t in db_load()["shares"] if t.startswith(token)] if token else []
        for t in matches:
            drop_share(t)
        self._json({"removed": len(matches)})

# ══════════════════════════════════════════════════════════════════════════════
# Serwer + tunel
# ══════════════════════════════════════════════════════════════════════════════

def serve(host, port, handler=Handler, quiet=False):
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    if not quiet:
        print(f"dropgate serwuje na http://{host}:{port}  (Ctrl+C aby zakończyć)", file=sys.stderr)
    return httpd

def find_cloudflared():
    here = Path(__file__).resolve().parent
    names = ("cloudflared.exe", "cloudflared")
    for d in (here, here / "bin", BASE, BASE.parent):
        for n in names:
            c = d / n
            if c.exists():
                return str(c)
    for cand in (shutil.which("cloudflared"),
                 str(Path.home() / "bin" / "cloudflared"),
                 r"C:\Program Files (x86)\cloudflared\cloudflared.exe",
                 r"C:\Program Files\cloudflared\cloudflared.exe",
                 "/usr/local/bin/cloudflared", "/usr/bin/cloudflared"):
        if cand and Path(cand).exists():
            return cand
    return None

def free_port(preferred):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", preferred)); s.close(); return preferred
    except OSError:
        s.close()
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.bind(("127.0.0.1", 0)); p = s2.getsockname()[1]; s2.close(); return p

def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))   # adres TEST-NET, nic nie wysyła
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()

QUICK_RE = re.compile(r"https://[a-z0-9][a-z0-9-]*\.trycloudflare\.com")

def start_tunnel(port: int, conf: dict, on_url=None, verbose=False):
    """Odpala cloudflared (quick albo nazwany) w tle. Zwraca proces albo None."""
    cf = find_cloudflared()
    if not cf:
        RT.tunnel, RT.tunnel_msg = "error", "brak cloudflared"
        print("! nie znalazłem cloudflared — linki będą tylko lokalne", file=sys.stderr)
        return None

    mode = conf.get("mode", "quick")
    if mode == "named":
        cred = conf_path_abs(conf.get("credentials", "tunnel.json"))
        host = conf.get("hostname", "")
        if not (cred.is_file() and host and conf.get("tunnel_id")):
            RT.tunnel, RT.tunnel_msg = "error", "niekompletna konfiguracja nazwanego tunelu"
            print("! nazwany tunel nieskonfigurowany — wracam do quick-tunnela", file=sys.stderr)
            mode = "quick"

    if mode == "named":
        cfg = BASE / "cloudflared.yml"
        cfg.write_text(
            f"tunnel: {conf['tunnel_id']}\n"
            f"credentials-file: {conf_path_abs(conf['credentials'])}\n"
            f"no-autoupdate: true\n"
            f"ingress:\n"
            f"  - hostname: {conf['hostname']}\n"
            f"    service: http://127.0.0.1:{port}\n"
            f"  - service: http_status:404\n", "utf-8")
        cmd = [cf, "tunnel", "--no-autoupdate", "--config", str(cfg), "run"]
        fixed_url = "https://" + conf["hostname"]
    else:
        cmd = [cf, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"]
        fixed_url = None

    RT.tunnel, RT.tunnel_msg = "starting", ""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", bufsize=1)

    def pump():
        for line in proc.stdout:
            if verbose:
                sys.stderr.write("  cf| " + line)
            if RT.tunnel != "up":
                if fixed_url:
                    if "Registered tunnel connection" in line:
                        RT.base_url, RT.tunnel = fixed_url, "up"
                        if on_url: on_url(fixed_url)
                else:
                    m = QUICK_RE.search(line)
                    if m:
                        RT.base_url, RT.tunnel = m.group(0), "up"
                        if on_url: on_url(m.group(0))
        code = proc.wait()
        if RT.tunnel != "up" or code not in (0, None):
            RT.tunnel = "error"
            RT.tunnel_msg = RT.tunnel_msg or f"cloudflared zakończył się kodem {code}"

    threading.Thread(target=pump, daemon=True).start()
    return proc

def clip_copy(text: str) -> bool:
    try:
        if os.name == "nt":
            subprocess.run(["clip"], input=text, text=True, check=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return True
        for cmd in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "-ib"]):
            if shutil.which(cmd[0]):
                subprocess.run(cmd, input=text, text=True, check=True)
                return True
    except (OSError, subprocess.SubprocessError):
        pass
    return False

def banner(lines):
    w = max(len(l) for l in lines) + 4
    print("\n" + "═" * w)
    for l in lines:
        print("  " + l)
    print("═" * w + "\n", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
# Komendy
# ══════════════════════════════════════════════════════════════════════════════

def _wait_forever(proc=None):
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nzatrzymano.", file=sys.stderr)
    finally:
        if proc is not None:
            try: proc.terminate()
            except OSError: pass

def _quiet_backup(conf):
    try:
        r = backup_run(conf, reason="share")
        print(f"• backup: {r['name']} ({fmt_size(r['size'])})", file=sys.stderr)
    except BackupError as e:
        print(f"! backup nieudany: {e}", file=sys.stderr)

def cmd_go(args):
    """Wszystko naraz: serwer publiczny + tunel + panel w przeglądarce."""
    conf = conf_load()
    if args.quick: conf["mode"] = "quick"
    if args.named: conf["mode"] = "named"
    if args.no_tunnel: conf["mode"] = "off"

    RT.pub_port = free_port(args.port or conf.get("port", 8787))
    adm_port = free_port(args.admin_port or conf.get("admin_port", 8788))
    RT.admin_token = secrets.token_urlsafe(24)

    pub_host = "0.0.0.0" if args.lan else "127.0.0.1"
    pub = serve(pub_host, RT.pub_port, Handler, quiet=True)
    threading.Thread(target=pub.serve_forever, daemon=True).start()
    RT.local_url = f"http://127.0.0.1:{RT.pub_port}"
    if args.lan:
        RT.lan_url = f"http://{lan_ip()}:{RT.pub_port}"

    adm = serve("127.0.0.1", adm_port, AdminHandler, quiet=True)
    threading.Thread(target=adm.serve_forever, daemon=True).start()

    start_autobackup(conf)

    panel = f"http://127.0.0.1:{adm_port}/?t={RT.admin_token}"
    proc = None
    if conf.get("mode") != "off":
        proc = start_tunnel(RT.pub_port, conf,
                            on_url=lambda u: banner([f"PUBLICZNY ADRES:  {u}"]),
                            verbose=args.verbose)
    else:
        RT.tunnel = "off"

    lines = [f"PANEL:  {panel}", f"LOKALNIE: {RT.local_url}",
             "", "Przeciągnij plik do panelu → link ląduje w schowku."]
    if RT.lan_url:
        lines.insert(2, f"LAN:    {RT.lan_url}")
    banner(lines)
    if not args.no_browser:
        try: webbrowser.open(panel)
        except Exception: pass
    _wait_forever(proc)

def cmd_share(args):
    """Jedna komenda: dodaj plik(i), postaw tunel, wypisz i skopiuj gotowy link."""
    conf = conf_load()
    if args.quick: conf["mode"] = "quick"
    if args.named: conf["mode"] = "named"
    if args.lan or args.no_tunnel: conf["mode"] = "off"

    rec = make_share(args.files,
                     expires=parse_duration(args.expires or conf.get("default_expires")),
                     maxdl=args.max, once=args.once, passphrase=args.passphrase,
                     label=args.label, copy=args.copy)

    if backup_conf(conf).get("auto") and backup_ready(conf)[0]:
        threading.Thread(target=lambda: _quiet_backup(conf), daemon=True).start()

    RT.pub_port = free_port(args.port or conf.get("port", 8787))
    host = "0.0.0.0" if args.lan else "127.0.0.1"
    pub = serve(host, RT.pub_port, Handler, quiet=True)
    threading.Thread(target=pub.serve_forever, daemon=True).start()
    RT.local_url = f"http://127.0.0.1:{RT.pub_port}"

    def announce(_=None):
        url = public_link(rec["token"])
        copied = clip_copy(url)
        lines = [f"LINK:  {url}"]
        if copied: lines.append("(skopiowany do schowka)")
        if rec.get("pass"): lines.append("hasło: ustawione")
        if rec.get("expires"):
            lines.append("wygasa: " + time.strftime("%Y-%m-%d %H:%M", time.localtime(rec["expires"])))
        lines.append("Ctrl+C kończy serwowanie.")
        banner(lines)

    proc = None
    if args.lan:
        RT.lan_url = f"http://{lan_ip()}:{RT.pub_port}"
        announce()
    elif conf.get("mode") == "off":
        announce()
    else:
        print("• stawiam tunel…", file=sys.stderr)
        proc = start_tunnel(RT.pub_port, conf, on_url=announce, verbose=args.verbose)
        if proc is None:
            announce()
    _wait_forever(proc)

def cmd_add(args):
    rec = make_share(args.files, expires=parse_duration(args.expires) if args.expires else None,
                     maxdl=args.max, once=args.once, passphrase=args.passphrase,
                     label=args.label, copy=args.copy)
    print(f"token: {rec['token']}")
    if rec.get("expires"):
        print("wygasa:", time.strftime("%Y-%m-%d %H:%M", time.localtime(rec["expires"])))
    if rec.get("max") is not None: print("limit pobrań:", rec["max"])
    if rec.get("once"): print("jednorazowy: tak")
    if rec.get("pass"): print("hasło: ustawione")
    print("pliki:", ", ".join(f["name"] for f in rec["files"]))
    base = args.base or _conf_base()
    if base:
        link = f"{base.rstrip('/')}/d/{rec['token']}"
        print("\nlink:", link)
        if clip_copy(link): print("(skopiowany do schowka)")
    else:
        print("\nścieżka linku:", f"/d/{rec['token']}")
        print("(uruchom `go` albo `tunnel`, żeby dostać pełny URL)")

def _conf_base() -> str:
    c = conf_load()
    if c.get("mode") == "named" and c.get("hostname"):
        return "https://" + c["hostname"]
    return ""

def cmd_ls(args):
    shares = db_load()["shares"]
    if not shares:
        print("brak share'ów."); return
    base = args.base or _conf_base()
    for tok, r in shares.items():
        ok, reason = share_alive(r)
        exp = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["expires"])) if r.get("expires") else "nigdy"
        dl = f"{r.get('downloads',0)}/{r['max']}" if r.get("max") is not None else str(r.get("downloads",0))
        tags = []
        if r.get("once"): tags.append("once")
        if r.get("pass"): tags.append("pass")
        if not ok: tags.append(reason)
        print(f"{tok[:12]}…  {r.get('label','?')[:28]:28}  wygasa:{exp:16}  "
              f"pobrań:{dl:8}  {' '.join(tags)}")
        if base:
            print(f"              {base.rstrip('/')}/d/{tok}")

def cmd_rm(args):
    if args.token == "all":
        for t in list(db_load()["shares"]):
            drop_share(t)
        print("usunięto wszystkie share'y."); return
    matches = [t for t in db_load()["shares"] if t.startswith(args.token)]
    for t in matches:
        drop_share(t)
    print(f"usunięto: {len(matches)}" if matches else "nie znaleziono tokenu.")

def cmd_url(args):
    shares = db_load()["shares"]
    matches = {t: r for t, r in shares.items() if t.startswith(args.token)} if args.token else shares
    if not matches: print("nie znaleziono."); return
    base = (args.base or _conf_base()).rstrip("/")
    links = [f"{base}/d/{t}" for t in matches]
    for (t, r), link in zip(matches.items(), links):
        print(f"{link}   ({r.get('label','?')})")
    if len(links) == 1 and base and clip_copy(links[0]):
        print("(skopiowany do schowka)")

def cmd_serve(args):
    httpd = serve(args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nzatrzymano.", file=sys.stderr)

def cmd_tunnel(args):
    conf = conf_load()
    if args.quick: conf["mode"] = "quick"
    if args.named: conf["mode"] = "named"
    RT.pub_port = free_port(args.port or conf.get("port", 8787))
    httpd = serve("127.0.0.1", RT.pub_port, Handler, quiet=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"• serwer lokalny: http://127.0.0.1:{RT.pub_port}", file=sys.stderr)
    proc = start_tunnel(RT.pub_port, conf, on_url=_print_links, verbose=True)
    if proc is None:
        sys.exit("Brak cloudflared. Zainstaluj albo użyj `serve --host 0.0.0.0`.")
    _wait_forever(proc)

def _print_links(base):
    shares = db_load()["shares"]
    lines = [f"PUBLICZNY ADRES:  {base}"]
    if not shares:
        lines.append("(brak share'ów — dodaj: dropgate add <plik>)")
    for tok, r in shares.items():
        ok, reason = share_alive(r)
        flag = "" if ok else f"  [{reason}]"
        lock = " [hasło]" if r.get("pass") else ""
        lines.append(f"• {r.get('label','?')}{lock}{flag}")
        lines.append(f"  {base}/d/{tok}")
    banner(lines)

def _ago(ts) -> str:
    if not ts: return "nigdy"
    d = max(0, int(time.time() - ts))
    if d < 60: return f"{d} s temu"
    if d < 3600: return f"{d // 60} min temu"
    if d < 86400: return f"{d // 3600} godz. temu"
    return f"{d // 86400} dni temu"

def cmd_backup(args):
    conf = conf_load()
    ok, why = backup_ready(conf)
    b = backup_conf(conf)
    if args.status or args.list:
        st = backup_state()
        print(f"cel:      {b['user']}@{b['host']}" if b.get("host") else "cel:      (nieskonfigurowany)")
        print(f"gotowy:   {'tak' if ok else 'NIE — ' + why}")
        okat = st.get("ok_at")
        print(f"ostatni:  {st.get('name','—')}  "
              f"{_ago(okat) if okat else ('(data nieznana)' if st.get('name') else 'nigdy')}")
        if st.get("ok") is False:
            print(f"BŁĄD:     {st.get('msg','')}  (próba {_ago(st.get('at'))})")
        if ok:
            try:
                rs = backup_remote_stat(conf)
                print(f"serwer:   {rs.get('count','?')} kopii, {fmt_size(int(rs.get('bytes') or 0))}, "
                      f"wolne {fmt_size(int(rs.get('free') or 0))}")
                if args.list:
                    for n in backup_list(conf):
                        print("  " + n)
            except BackupError as e:
                print(f"serwer:   nieosiągalny ({e})")
        return
    if not ok:
        sys.exit(f"backup niemożliwy: {why}")
    print(f"pakuję {BASE} → {b['user']}@{b['host']}…", file=sys.stderr)
    r = backup_run(conf)
    print(f"wysłane: {r['name']}  ({fmt_size(r['size'])})")

def cmd_restore(args):
    conf = conf_load()
    ok, why = backup_ready(conf)
    if not ok:
        sys.exit(f"restore niemożliwy: {why}")
    if not args.yes:
        avail = backup_list(conf)
        target = args.name or (avail[0] if avail else "—")
        print(f"To NADPISZE stan w {BASE} zawartością {target}.")
        print("Dostępne kopie:")
        for n in avail[:10]:
            print("  " + n)
        print("\nDodaj --yes, żeby wykonać.")
        return
    r = backup_restore(args.name, conf)
    print(f"odtworzone z {r['name']}: {r['files']} plików ({fmt_size(r['size'])})")
    print(f"stan: {BASE}")

def cmd_config(args):
    conf = conf_load()
    if args.show or not any([args.mode, args.hostname, args.tunnel_id, args.credentials,
                             args.port, args.admin_port, args.default_expires]):
        print(json.dumps(conf, ensure_ascii=False, indent=2))
        print(f"\nstan: {BASE}")
        cf = find_cloudflared()
        print(f"cloudflared: {cf or 'NIE ZNALEZIONO'}")
        return
    for k in ("mode", "hostname", "tunnel_id", "credentials", "default_expires"):
        v = getattr(args, k)
        if v: conf[k] = v
    for k in ("port", "admin_port"):
        v = getattr(args, k)
        if v: conf[k] = int(v)
    conf_save(conf)
    print(json.dumps(conf, ensure_ascii=False, indent=2))

def build_parser():
    p = argparse.ArgumentParser(prog="dropgate", description="Bezpieczny drop plików przez token hex.")
    sub = p.add_subparsers(dest="cmd")

    def tunnel_flags(sp):
        sp.add_argument("--quick", action="store_true", help="wymuś quick-tunnel (losowa domena)")
        sp.add_argument("--named", action="store_true", help="wymuś nazwany tunel (stała domena z configu)")
        sp.add_argument("--verbose", "-v", action="store_true", help="pokaż logi cloudflared")

    g = sub.add_parser("go", help="panel w przeglądarce + serwer + tunel (domyślne)")
    g.add_argument("--port", type=int, help="port publiczny")
    g.add_argument("--admin-port", type=int, dest="admin_port", help="port panelu")
    g.add_argument("--lan", action="store_true", help="wystaw też na LAN (bind 0.0.0.0)")
    g.add_argument("--no-tunnel", action="store_true", dest="no_tunnel", help="bez tunelu")
    g.add_argument("--no-browser", action="store_true", dest="no_browser", help="nie otwieraj przeglądarki")
    tunnel_flags(g)
    g.set_defaults(fn=cmd_go)

    s = sub.add_parser("share", help="dodaj plik(i) i od razu wystaw link (jedna komenda)")
    s.add_argument("files", nargs="+")
    s.add_argument("--expires", "-e", help="np. 30m, 12h, 7d, never")
    s.add_argument("--max", type=int, help="maks. liczba pobrań")
    s.add_argument("--once", action="store_true", help="link jednorazowy")
    s.add_argument("--pass", dest="passphrase", help="dodatkowe hasło")
    s.add_argument("--label", help="etykieta")
    s.add_argument("--copy", action="store_true", help="skopiuj plik do magazynu dropgate")
    s.add_argument("--lan", action="store_true", help="bez tunelu, link w sieci lokalnej")
    s.add_argument("--no-tunnel", action="store_true", dest="no_tunnel")
    s.add_argument("--port", type=int)
    tunnel_flags(s)
    s.set_defaults(fn=cmd_share)

    a = sub.add_parser("add", help="dodaj plik(i) i wygeneruj token (bez serwera)")
    a.add_argument("files", nargs="+")
    a.add_argument("--expires", "-e", help="np. 30m, 12h, 7d, never (domyślnie never)")
    a.add_argument("--max", type=int, help="maks. liczba pobrań")
    a.add_argument("--once", action="store_true", help="link jednorazowy (burn-after-download)")
    a.add_argument("--pass", dest="passphrase", help="dodatkowe hasło (drugi czynnik)")
    a.add_argument("--label", help="etykieta share'a")
    a.add_argument("--copy", action="store_true", help="skopiuj plik do magazynu dropgate")
    a.add_argument("--base", help="bazowy URL do złożenia pełnego linku")
    a.set_defaults(fn=cmd_add)

    l = sub.add_parser("ls", help="lista share'ów")
    l.add_argument("--base", help="bazowy URL")
    l.set_defaults(fn=cmd_ls)

    r = sub.add_parser("rm", help="usuń share (prefiks tokenu lub 'all')")
    r.add_argument("token"); r.set_defaults(fn=cmd_rm)

    u = sub.add_parser("url", help="wypisz linki")
    u.add_argument("token", nargs="?", default="")
    u.add_argument("--base", help="bazowy URL")
    u.set_defaults(fn=cmd_url)

    sv = sub.add_parser("serve", help="sam serwer publiczny (bez panelu i tunelu)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8787)
    sv.set_defaults(fn=cmd_serve)

    t = sub.add_parser("tunnel", help="serwer + tunel, linki na stdout")
    t.add_argument("--port", type=int)
    tunnel_flags(t)
    t.set_defaults(fn=cmd_tunnel)

    bk = sub.add_parser("backup", help="wyślij kopię stanu na serwer po SSH")
    bk.add_argument("--status", action="store_true", help="tylko pokaż stan backupu")
    bk.add_argument("--list", action="store_true", help="wypisz kopie na serwerze")
    bk.set_defaults(fn=cmd_backup)

    rs = sub.add_parser("restore", help="odtwórz stan z kopii na serwerze")
    rs.add_argument("name", nargs="?", help="nazwa kopii (domyślnie najnowsza)")
    rs.add_argument("--yes", action="store_true", help="tak, nadpisz obecny stan")
    rs.set_defaults(fn=cmd_restore)

    c = sub.add_parser("config", help="pokaż/ustaw konfigurację")
    c.add_argument("--show", action="store_true")
    c.add_argument("--mode", choices=["quick", "named", "off"])
    c.add_argument("--hostname")
    c.add_argument("--tunnel-id", dest="tunnel_id")
    c.add_argument("--credentials")
    c.add_argument("--port")
    c.add_argument("--admin-port", dest="admin_port")
    c.add_argument("--default-expires", dest="default_expires")
    c.set_defaults(fn=cmd_config)
    return p

def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    ensure_base()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["go"]                     # dwuklik / gołe uruchomienie → panel
    elif argv[0] not in ("-h", "--help") and not argv[0].startswith("-"):
        known = {"go", "share", "add", "ls", "rm", "url", "serve", "tunnel", "config",
                 "backup", "restore"}
        if argv[0] not in known and Path(argv[0]).exists():
            argv = ["share"] + argv       # przeciągnięcie plików na skrypt/.bat
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except (ValueError, FileNotFoundError, BackupError) as e:
        sys.exit(f"błąd: {e}")

if __name__ == "__main__":
    main()
