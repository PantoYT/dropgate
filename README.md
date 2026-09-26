# dropgate

A standalone, secure file drop via a tokenized link. One Python file, **standard library
only**, zero dependencies (except `cloudflared`, if you want a tunnel). Run it anywhere
with `python3 >= 3.8`.

## Idea

The `/dl/` mechanism from Pontifex, cut out and hardened. You drop a file → you get a
128-bit hex token → you send someone the link. Cloudflare provides HTTPS without touching
the router: a quick tunnel (random domain, zero configuration) or a named tunnel (fixed
domain, e.g. `drop.your-domain.com`).

## Quick start

```bash
# browser panel: drag a file in → the link lands in your clipboard
python3 dropgate.py go

# or one command per file
python3 dropgate.py share ~/backup.zip --expires 24h --pass sesame
#   → LINK: https://random-name.trycloudflare.com/d/<token>  (copied to the clipboard)
```

The recipient opens the link → (optionally a password) → file list → download.

## Two servers, deliberately separated

| | port | what it exposes | who can reach it |
|---|---|---|---|
| **public** | 8787 | only `/d/<token>` | the world, through the tunnel |
| **panel** | 8788 | adding / deleting / links | only `127.0.0.1` + session token |

**Only** the public port goes into the tunnel — the panel isn't reachable from outside
even by a configuration mistake. The panel additionally checks the client address, a
session token in a cookie (`HttpOnly; SameSite=Strict`) and requires an `X-Dropgate`
header, which a plain form on a foreign page can't send.

## Commands

| Command | Description |
|---|---|
| `go` | server + tunnel + browser panel (the default when run bare) |
| `share <files...>` | add and immediately publish a link, copied to the clipboard |
| `add <files...>` | database entry only, no server |
| `ls` / `rm <token\|all>` / `url [token]` | list / delete / links |
| `serve [--host H] [--port N]` | public server only |
| `tunnel` | server + tunnel, links on stdout |
| `backup [--status] [--list]` | send a copy of the state to your own server over SSH |
| `restore [NAME] --yes` | restore the state from a copy |
| `config [--mode …] [--hostname …]` | view and change settings |

Common share flags: `-e/--expires 30m|12h|7d|never`, `--max N`, `--once`,
`--pass PASSWORD`, `--label TXT`, `--copy` (copy the file into dropgate's storage).
Tunnel flags: `--quick` (random domain), `--named` (fixed domain from the config),
`--no-tunnel`, `--lan` (no tunnel, a link on the local network), `-v` (cloudflared logs).

Dropping files onto `dropgate.py` (or onto the `.bat` from the portable pack) works like
`share` — a first argument that is an existing path switches that mode on.

## Security

- **Token** = `secrets.token_hex(16)` (128 bit). The URL is a capability — unguessable.
- **Constant-time comparisons** (`hmac.compare_digest`) — no timing oracle on the token,
  the password or the panel token.
- **Anti-traversal**: the server returns only files on the given share's allowlist; the
  name from the URL is reduced to `basename`, never joined with a path.
- **Password** (optional second factor): stored as `salt + sha256`; after unlocking, a
  cookie signed with the server's HMAC (`HttpOnly; SameSite=Strict`); the password never
  lands in the URL or logs.
- Time-based **expiry**, a **download limit** (`--max`), **burn-after-download**
  (`--once`, also deletes copied files from storage).
- **Streaming** in 256 KB chunks + **Range** support (resuming) — large files without
  loading them into RAM. Uploads to the panel are also streamed to disk.
- Default bind is `127.0.0.1` (the tunnel connects locally). `--lan` if you want LAN.

## State

Kept in `~/.dropgate/` (or `$DROPGATE_HOME`, or `state/` next to the script when a
`PORTABLE` marker file is present): `shares.json` (0600, atomic write under a `flock`
lock), `secret.key` (0600, HMAC for cookies), `config.json`, `files/` (copies from the
panel and `--copy`).

Files added with `add`/`share` are referenced **in place** (by path) — deleting the
source → the link returns 410. A path relative to the volume root is stored as well, so a
share from a USB stick survives a drive letter change.

## Portable (USB stick)

```
dropgate\
  dropgate.bat        double-click → browser panel
  wyslij-plik.bat     drag a file onto it → ready link
  dropgate.py
  PORTABLE            marker: keep the state next to the script
  python\             embeddable Python — works on a computer without Python
  bin\cloudflared.exe
  state\              database, HMAC key, tunnel credentials, files\
```

`state/tunnel.json` (named tunnel credentials) is a secret — the whole `portable/`
directory is in `.gitignore`. Lost USB stick → `cloudflared tunnel delete <name>`.

## Backup to your own server

The USB stick is a single point of failure: lose it or have the flash die, and both the
stored files and the token database are gone. So dropgate can push the whole state
directory (`shares.json`, `secret.key`, `config.json`, tunnel credentials, `files/`) to
your own server over SSH.

```bash
python3 dropgate.py backup            # pack and send now
python3 dropgate.py backup --status   # when last, how many copies, how much space
python3 dropgate.py restore --yes     # restore the newest (OVERWRITES the state)
```

In `go` mode a backup runs by itself after every database change (5 s debounce), and the
panel shows "backup 3 min ago" — clicking it forces a copy.

Because `secret.key` and the tokens come back 1:1, **after restoring onto a new USB stick
the old links keep working** (as long as the domain points to where dropgate now runs).

### A key without a shell

Backup doesn't use your regular SSH key. The server has a small receiver pinned to a
separate key:

```
# ~/.ssh/authorized_keys
restrict,command="/home/USER/dropgate-recv.sh" ssh-ed25519 AAAA… dropgate-portable
```

`dropgate-recv.sh` understands only `list | put <file> | get <file> | prune <n> | stat`,
validates the name with a regex and never passes anything to a shell. A lost USB stick
therefore gives access to its own copies, **not to the server** — and you cut even that
off by deleting one line from `authorized_keys`.

The host key is pinned in `state/known_hosts`, so a backup from a foreign network can't
be redirected to a MITM — with a swapped key the connection simply fails.

Windows OpenSSH refuses to use a key stored on a USB stick (ACL "Everyone" →
`bad permissions`). dropgate detects this and for the duration of the transfer makes a
private copy of the key in a temp directory, then overwrites it with random bytes and
deletes it.

The configuration lives in `config.json`:

```json
"backup": {"host": "10.0.0.5", "user": "backup", "key": "backup_key",
           "known_hosts": "known_hosts", "auto": true, "keep": 10, "timeout": 8}
```

Backup works where the server is visible. Use an address from a mesh network
(Tailscale, WireGuard, ZeroTier) instead of the LAN one — then copies are made from any
network, not only behind the home router. When the server isn't visible, copies simply
don't happen: dropgate says so in the panel and doesn't block work, and after a failed
attempt it waits `retry_after` seconds. **Don't remove that grace period** — a series of
failed logins is the easiest way to get banned by fail2ban on the server side.

Receiver script: [`extras/dropgate-recv.sh`](extras/dropgate-recv.sh).

## Fixed domain

```bash
cloudflared tunnel create dropgate
cloudflared tunnel route dns dropgate drop.your-domain.com
cp ~/.cloudflared/<uuid>.json  <state>/tunnel.json
python3 dropgate.py config --mode named --hostname drop.your-domain.com --tunnel-id <uuid>
```

A separate tunnel for dropgate rather than adding a hostname to an existing one: the same
tunnel name running on two machines means replicas, and traffic goes to the
**geographically nearest** — so from a USB stick it would randomly land here one time and
there another.

## Pickup without retyping the link

A new share gets an extra code, e.g. `lis-klon-kawa-482913`. The sender sees it in the
panel (clicking copies the code) and in the `add` and `share` commands. The recipient
opens the main dropgate address and types the code. Case doesn't matter, dashes can be
replaced with spaces. The file's password, download limit and one-time mode still apply.

The code works for **15 minutes from creating the share**, at most until the file
expires. After that use the regular link or create a new share. Existing shares keep
working through their original links.

A short code has about 38 bits of randomness, so it's a weaker secret than the 128-bit
link. That's why the pickup endpoint has a global limit of 30 attempts per minute per
process, including behind the tunnel. The limit can temporarily block code pickup under
heavy traffic; regular links keep working. After a process restart the attempt counter
starts from zero. Don't run multiple replicas with this mechanism.

Tests without a tunnel and without touching the real state:
`python -m unittest test_pickup.py`.

The panel and command output are in Polish.
