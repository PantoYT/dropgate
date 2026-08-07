#!/usr/bin/env python3
"""
dropgate — samodzielny, bezpieczny drop plików przez tokenowany link.

Jeden plik, tylko biblioteka standardowa. Postaw gdziekolwiek (python3 >= 3.8),
wpnij w Cloudflare quick-tunnel i wyślij sobie plik przez 128-bitowy klucz hex.

  python3 dropgate.py add ~/backup.zip --expires 24h --pass sezam
  python3 dropgate.py tunnel
      → https://losowa-nazwa.trycloudflare.com/d/<token>

Model bezpieczeństwa:
  * token = secrets.token_hex(16) (128 bit) — URL jest capability (nie do zgadnięcia)
  * porównania stałoczasowe (hmac.compare_digest) — brak timing-oracle
  * anti-traversal: serwuje wyłącznie z allowlisty nazw danego share'a
  * opcjonalne hasło (drugi czynnik) — trzymane jako salt+sha256, cookie podpisane HMAC
  * wygasanie czasowe, limit pobrań, linki jednorazowe (burn-after-download)
  * streaming w kawałkach + Range (wznawianie), bez wczytywania pliku do RAM
"""

import argparse, hashlib, hmac, html, json, mimetypes, os, re, secrets, shutil
import signal, socket, subprocess, sys, threading, time
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
BASE = Path(os.environ.get("DROPGATE_HOME", Path.home() / ".dropgate"))
DB_PATH = BASE / "shares.json"
SECRET_PATH = BASE / "secret.key"
CHUNK = 256 * 1024  # 256 KB — rozmiar kawałka streamingu

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

# ══════════════════════════════════════════════════════════════════════════════
# Logika share'ów
# ══════════════════════════════════════════════════════════════════════════════

def parse_duration(s: str):
    if s is None: return None
    s = s.strip().lower()
    if s in ("never", "none", "0", "inf"): return None
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

def make_share(paths, expires, maxdl, once, passphrase, label):
    files = []
    for p in paths:
        p = Path(p).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"nie plik: {p}")
        files.append({"name": p.name, "path": str(p), "size": p.stat().st_size})
    if not files:
        raise ValueError("brak plików do udostępnienia")
    token = secrets.token_hex(16)
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

def share_alive(rec: dict):
    """Zwraca (ok, powód). Nie modyfikuje stanu."""
    if rec is None: return False, "brak"
    if rec.get("expires") and time.time() > rec["expires"]:
        return False, "wygasł"
    if rec.get("max") is not None and rec.get("downloads", 0) >= rec["max"]:
        return False, "limit pobrań"
    return True, "ok"

# ══════════════════════════════════════════════════════════════════════════════
# HTTP
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

PAGE_CSS = """
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#0b0d13;color:#e7eaf3;
font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#12141c;border:1px solid #232838;border-radius:16px;padding:26px 28px;
max-width:460px;width:100%;box-shadow:0 24px 60px rgba(0,0,0,.55)}
h1{font-size:16px;margin:0 0 2px;letter-spacing:.02em}
.muted{color:#8a92a8;font-size:12.5px;margin:0 0 18px}
ul{list-style:none;padding:0;margin:0}
li{display:flex;justify-content:space-between;align-items:center;gap:12px;
padding:13px 15px;border:1px solid #232838;border-radius:11px;margin-bottom:10px;
transition:.15s;background:#0e1017}
li:hover{border-color:#3a4667;background:#141826}
a.f{color:#8ab4ff;text-decoration:none;font:13px/1.4 ui-monospace,monospace;
word-break:break-all}a.f:hover{text-decoration:underline}
.sz{color:#8a92a8;font-size:12px;white-space:nowrap;font-variant-numeric:tabular-nums}
.badge{display:inline-block;font-size:11px;color:#8a92a8;border:1px solid #232838;
border-radius:20px;padding:2px 10px;margin-top:4px}
input[type=password]{width:100%;background:#0e1017;border:1px solid #232838;color:#e7eaf3;
border-radius:10px;padding:11px 13px;font:14px system-ui;margin:8px 0 12px;outline:none}
input:focus{border-color:#5666e6}
button{width:100%;font:600 14px system-ui;color:#fff;background:linear-gradient(180deg,#6f7fff,#5666e6);
border:0;border-radius:10px;padding:11px;cursor:pointer}
button:hover{filter:brightness(1.08)}
.err{color:#ff7b7b;font-size:12.5px;margin:0 0 10px}
.foot{color:#5c6478;font-size:11px;margin:18px 0 0;text-align:center}
.brand{color:#7c8cff;font-weight:700}
"""

def page(title: str, body: str) -> bytes:
    return (f"<!doctype html><html lang=pl><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{PAGE_CSS}</style></head>"
            f"<body><div class=card>{body}"
            f"<p class=foot><span class=brand>dropgate</span> · bezpieczny drop</p>"
            f"</div></body></html>").encode("utf-8")

class Handler(BaseHTTPRequestHandler):
    server_version = "dropgate"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ── util ──
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

    def _notfound(self):
        self._send(page("nie znaleziono",
                        "<h1>Nie znaleziono</h1><p class=muted>Link nieaktywny, wygasł "
                        "lub błędny.</p>"), code=404)

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    # ── routing ──
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
        path = Path(entry["path"])
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
                if m.group(2): end = int(m.group(2))
                if start > end or start >= size:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.end_headers(); return
                status = 206

        ctype = mimetypes.guess_type(entry["name"])[0] or "application/octet-stream"
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
            counted = False  # klient przerwał — nie licz
            return

        if counted:
            self._register_download(token)

    def _register_download(self, token: str):
        def mut(data):
            r = data["shares"].get(token)
            if not r: return
            r["downloads"] = r.get("downloads", 0) + 1
            if r.get("once"):
                data["shares"].pop(token, None)  # burn-after-download
            elif r.get("max") is not None and r["downloads"] >= r["max"]:
                pass  # zostaje, ale share_alive odetnie kolejne
        db_update(mut)

# ══════════════════════════════════════════════════════════════════════════════
# Serwer + tunel
# ══════════════════════════════════════════════════════════════════════════════

def serve(host, port, quiet=False):
    httpd = ThreadingHTTPServer((host, port), Handler)
    if not quiet:
        print(f"dropgate serwuje na http://{host}:{port}  (Ctrl+C aby zakończyć)", file=sys.stderr)
    return httpd

def find_cloudflared():
    for cand in (shutil.which("cloudflared"),
                 str(Path.home() / "bin" / "cloudflared"),
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

def cmd_tunnel(args):
    cf = find_cloudflared()
    if not cf:
        sys.exit("Brak cloudflared w PATH ani ~/bin. Zainstaluj lub podaj serwer ręcznie "
                 "(python3 dropgate.py serve --host 0.0.0.0).")
    port = free_port(args.port)
    httpd = serve("127.0.0.1", port, quiet=True)
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()

    print(f"• serwer lokalny: http://127.0.0.1:{port}", file=sys.stderr)
    print("• uruchamiam Cloudflare quick-tunnel…\n", file=sys.stderr)
    proc = subprocess.Popen(
        [cf, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    base = None
    url_re = re.compile(r"https://[a-z0-9][a-z0-9-]*\.trycloudflare\.com")
    def stop(*_):
        proc.terminate(); httpd.shutdown(); sys.exit(0)
    signal.signal(signal.SIGINT, stop); signal.signal(signal.SIGTERM, stop)

    for line in proc.stdout:
        if base is None:
            m = url_re.search(line)
            if m:
                base = m.group(0)
                _print_links(base)
        # cichy pass-through logów cloudflared (na stderr)
        sys.stderr.write("  cf| " + line)
    proc.wait()

def _print_links(base):
    shares = db_load()["shares"]
    print("\n" + "═" * 58)
    print(f"  PUBLICZNY ADRES:  {base}")
    print("═" * 58)
    if not shares:
        print("  (brak share'ów — dodaj: python3 dropgate.py add <plik>)")
    for tok, r in shares.items():
        ok, reason = share_alive(r)
        flag = "" if ok else f"  [{reason}]"
        lock = " 🔒" if r.get("pass") else ""
        print(f"  • {r.get('label','?')}{lock}{flag}")
        print(f"    {base}/d/{tok}")
    print("═" * 58 + "\n", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def cmd_add(args):
    expires = parse_duration(args.expires) if args.expires else None
    rec = make_share(args.files, expires, args.max, args.once, args.passphrase, args.label)
    print(f"token: {rec['token']}")
    if rec.get("expires"):
        print("wygasa:", time.strftime("%Y-%m-%d %H:%M", time.localtime(rec["expires"])))
    if rec.get("max") is not None: print("limit pobrań:", rec["max"])
    if rec.get("once"): print("jednorazowy: tak")
    if rec.get("pass"): print("hasło: ustawione")
    print("pliki:", ", ".join(f["name"] for f in rec["files"]))
    if args.base:
        print("\nlink:", f"{args.base.rstrip('/')}/d/{rec['token']}")
    else:
        print("\nścieżka linku:", f"/d/{rec['token']}")
        print("(uruchom `tunnel` albo dodaj --base https://twoja-domena, by dostać pełny URL)")

def cmd_ls(args):
    shares = db_load()["shares"]
    if not shares:
        print("brak share'ów."); return
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

def cmd_rm(args):
    if args.token == "all":
        db_update(lambda d: d["shares"].clear())
        print("usunięto wszystkie share'y."); return
    def mut(d):
        matches = [t for t in d["shares"] if t.startswith(args.token)]
        for t in matches: d["shares"].pop(t)
        return matches
    matches = db_update(mut)
    print(f"usunięto: {len(matches)}" if matches else "nie znaleziono tokenu.")

def cmd_url(args):
    shares = db_load()["shares"]
    matches = {t: r for t, r in shares.items() if t.startswith(args.token)} if args.token else shares
    if not matches: print("nie znaleziono."); return
    base = args.base.rstrip("/") if args.base else ""
    for t, r in matches.items():
        print(f"{base}/d/{t}   ({r.get('label','?')})")

def cmd_serve(args):
    ensure_base()
    httpd = serve(args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nzatrzymano.", file=sys.stderr)

def build_parser():
    p = argparse.ArgumentParser(prog="dropgate", description="Bezpieczny drop plików przez token hex.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="dodaj plik(i) i wygeneruj token")
    a.add_argument("files", nargs="+")
    a.add_argument("--expires", "-e", help="np. 30m, 12h, 7d, never (domyślnie never)")
    a.add_argument("--max", type=int, help="maks. liczba pobrań")
    a.add_argument("--once", action="store_true", help="link jednorazowy (burn-after-download)")
    a.add_argument("--pass", dest="passphrase", help="dodatkowe hasło (drugi czynnik)")
    a.add_argument("--label", help="etykieta share'a")
    a.add_argument("--base", help="bazowy URL do złożenia pełnego linku")
    a.set_defaults(fn=cmd_add)

    l = sub.add_parser("ls", help="lista share'ów"); l.set_defaults(fn=cmd_ls)

    r = sub.add_parser("rm", help="usuń share (prefiks tokenu lub 'all')")
    r.add_argument("token"); r.set_defaults(fn=cmd_rm)

    u = sub.add_parser("url", help="wypisz linki")
    u.add_argument("token", nargs="?", default="")
    u.add_argument("--base", help="bazowy URL")
    u.set_defaults(fn=cmd_url)

    s = sub.add_parser("serve", help="uruchom serwer HTTP")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(fn=cmd_serve)

    t = sub.add_parser("tunnel", help="serwer + Cloudflare quick-tunnel (tymczasowa domena)")
    t.add_argument("--port", type=int, default=8787)
    t.set_defaults(fn=cmd_tunnel)
    return p

def main(argv=None):
    ensure_base()
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except (ValueError, FileNotFoundError) as e:
        sys.exit(f"błąd: {e}")

if __name__ == "__main__":
    main()
