# dropgate

Samodzielny, bezpieczny drop plików przez tokenowany link. Jeden plik Python,
**tylko biblioteka standardowa**, zero zależności (poza `cloudflared`, jeśli chcesz tunel).
Postaw gdziekolwiek gdzie jest `python3 >= 3.8`.

## Idea

Wycięty i wzmocniony mechanizm `/dl/` z Pontifexa. Wrzucasz plik → dostajesz
128-bitowy token hex → wysyłasz sobie/komuś link. Cloudflare quick-tunnel daje
świeżą, jednorazową domenę HTTPS bez konfiguracji DNS — idealne na tymczasowy transfer.

## Szybki start

```bash
# 1. dodaj plik (opcje: hasło, wygasanie, limit, jednorazowość)
python3 dropgate.py add ~/backup.zip --expires 24h --pass sezam

# 2. postaw serwer + tunel Cloudflare (tymczasowa domena)
python3 dropgate.py tunnel
#   → PUBLICZNY ADRES: https://losowa-nazwa.trycloudflare.com
#   → link:            https://losowa-nazwa.trycloudflare.com/d/<token>
```

Otwierasz link w przeglądarce → (ewentualnie hasło) → lista plików → pobierasz.

## Komendy

| Komenda | Opis |
|---|---|
| `add <pliki...>` | utwórz share, wypisz token. Flagi: `-e/--expires 30m\|12h\|7d\|never`, `--max N`, `--once`, `--pass HASŁO`, `--label TXT`, `--base URL` |
| `ls` | lista share'ów (token, etykieta, wygasanie, pobrania) |
| `rm <token\|all>` | usuń share (wystarczy prefiks tokenu) |
| `url [token] --base URL` | wypisz pełne linki |
| `serve [--host H] [--port N]` | sam serwer HTTP (domyślnie 127.0.0.1:8787) |
| `tunnel [--port N]` | serwer + Cloudflare quick-tunnel, żywe linki na stdout |

## Bezpieczeństwo

- **Token** = `secrets.token_hex(16)` (128 bit). URL jest capability — nie do zgadnięcia.
- **Porównania stałoczasowe** (`hmac.compare_digest`) — brak timing-oracle na tokenie i haśle.
- **Anti-traversal**: serwer oddaje wyłącznie pliki z allowlisty danego share'a; nazwa z URL
  jest redukowana do `basename`, nigdy nie sklejana ze ścieżką.
- **Hasło** (opcjonalny drugi czynnik): trzymane jako `salt + sha256`, po odblokowaniu
  cookie podpisane HMAC serwera (`HttpOnly; SameSite=Strict`), hasło nie ląduje w URL/logach.
- **Wygasanie** czasowe, **limit pobrań** (`--max`), **burn-after-download** (`--once`).
- **Streaming** w kawałkach 256 KB + obsługa **Range** (wznawianie) — duże pliki bez wczytywania do RAM.
- Domyślny bind `127.0.0.1` (tunel łączy się lokalnie). `serve --host 0.0.0.0` jeśli chcesz LAN.

## Stan

Trzymany w `~/.dropgate/` (albo `$DROPGATE_HOME`): `shares.json` (0600, atomowy zapis pod
blokadą `flock` — bezpieczny przy równoległym `add` i `serve`), `secret.key` (0600, HMAC cookies).
Pliki są referencjonowane **w miejscu** (po ścieżce), nie kopiowane — usunięcie źródła → link zwraca 410.

## Deploy na stałej domenie

Zamiast quick-tunnela możesz wpiąć w nazwany tunel Cloudflare:
```bash
python3 dropgate.py serve --port 8787 &
cloudflared tunnel --url http://127.0.0.1:8787   # albo wpis ingress w config.yml → drop.twojadomena.com
```
