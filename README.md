# dropgate

Samodzielny, bezpieczny drop plików przez tokenowany link. Jeden plik Python,
**tylko biblioteka standardowa**, zero zależności (poza `cloudflared`, jeśli chcesz tunel).
Postaw gdziekolwiek gdzie jest `python3 >= 3.8`.

## Idea

Wycięty i wzmocniony mechanizm `/dl/` z Pontifexa. Wrzucasz plik → dostajesz
128-bitowy token hex → wysyłasz komuś link. Cloudflare daje HTTPS bez grzebania
w routerze: quick-tunnel (losowa domena, zero konfiguracji) albo nazwany tunel
(stała domena, np. `drop.twoja-domena.pl`).

## Szybki start

```bash
# panel w przeglądarce: przeciągasz plik → link ląduje w schowku
python3 dropgate.py go

# albo jedna komenda na jeden plik
python3 dropgate.py share ~/backup.zip --expires 24h --pass sezam
#   → LINK: https://losowa-nazwa.trycloudflare.com/d/<token>  (skopiowany do schowka)
```

Odbiorca otwiera link → (ewentualnie hasło) → lista plików → pobiera.

## Dwa serwery, celowo rozdzielone

| | port | co wystawia | kto ma dostęp |
|---|---|---|---|
| **publiczny** | 8787 | wyłącznie `/d/<token>` | świat, przez tunel |
| **panel** | 8788 | dodawanie / kasowanie / linki | tylko `127.0.0.1` + token sesji |

Do tunelu trafia **wyłącznie** port publiczny — panel nie jest osiągalny z zewnątrz
nawet przez pomyłkę w konfiguracji. Panel dodatkowo sprawdza adres klienta, token
sesji w cookie (`HttpOnly; SameSite=Strict`) i wymaga nagłówka `X-Dropgate`,
którego nie da się wysłać zwykłym formularzem z obcej strony.

## Komendy

| Komenda | Opis |
|---|---|
| `go` | serwer + tunel + panel w przeglądarce (domyślne przy gołym uruchomieniu) |
| `share <pliki...>` | dodaj i od razu wystaw link, skopiowany do schowka |
| `add <pliki...>` | sam wpis w bazie, bez serwera |
| `ls` / `rm <token\|all>` / `url [token]` | lista / kasowanie / linki |
| `serve [--host H] [--port N]` | sam serwer publiczny |
| `tunnel` | serwer + tunel, linki na stdout |
| `backup [--status] [--list]` | wyślij kopię stanu na własny serwer po SSH |
| `restore [NAZWA] --yes` | odtwórz stan z kopii |
| `config [--mode …] [--hostname …]` | podgląd i ustawienia |

Wspólne flagi share'a: `-e/--expires 30m|12h|7d|never`, `--max N`, `--once`,
`--pass HASŁO`, `--label TXT`, `--copy` (skopiuj plik do magazynu dropgate).
Flagi tunelu: `--quick` (losowa domena), `--named` (stała domena z configu),
`--no-tunnel`, `--lan` (bez tunelu, link w sieci lokalnej), `-v` (logi cloudflared).

Przeciągnięcie plików na `dropgate.py` (albo na `.bat` z paczki portable) działa
jak `share` — pierwszy argument będący istniejącą ścieżką włącza ten tryb.

## Bezpieczeństwo

- **Token** = `secrets.token_hex(16)` (128 bit). URL jest capability — nie do zgadnięcia.
- **Porównania stałoczasowe** (`hmac.compare_digest`) — brak timing-oracle na tokenie,
  haśle i tokenie panelu.
- **Anti-traversal**: serwer oddaje wyłącznie pliki z allowlisty danego share'a; nazwa z URL
  jest redukowana do `basename`, nigdy nie sklejana ze ścieżką.
- **Hasło** (opcjonalny drugi czynnik): trzymane jako `salt + sha256`, po odblokowaniu
  cookie podpisane HMAC serwera (`HttpOnly; SameSite=Strict`), hasło nie ląduje w URL/logach.
- **Wygasanie** czasowe, **limit pobrań** (`--max`), **burn-after-download** (`--once`,
  kasuje też skopiowane pliki z magazynu).
- **Streaming** w kawałkach 256 KB + obsługa **Range** (wznawianie) — duże pliki bez wczytywania
  do RAM. Upload do panelu też leci strumieniowo na dysk.
- Domyślny bind `127.0.0.1` (tunel łączy się lokalnie). `--lan` jeśli chcesz LAN.

## Stan

Trzymany w `~/.dropgate/` (albo `$DROPGATE_HOME`, albo `state/` obok skryptu gdy leży
plik-znacznik `PORTABLE`): `shares.json` (0600, atomowy zapis pod blokadą `flock`),
`secret.key` (0600, HMAC cookies), `config.json`, `files/` (kopie z panelu i `--copy`).

Pliki dodane przez `add`/`share` są referencjonowane **w miejscu** (po ścieżce) — usunięcie
źródła → link zwraca 410. Dodatkowo zapisywana jest ścieżka względem korzenia wolumenu,
więc share z pendrive'a przeżyje zmianę litery dysku.

## Portable (pendrive)

```
dropgate\
  dropgate.bat        dwuklik → panel w przeglądarce
  wyslij-plik.bat     przeciągnij na to plik → gotowy link
  dropgate.py
  PORTABLE            znacznik: stan trzymaj obok skryptu
  python\             Python embeddable — działa na komputerze bez Pythona
  bin\cloudflared.exe
  state\              baza, klucz HMAC, poświadczenia tunelu, files\
```

`state/tunnel.json` (poświadczenia nazwanego tunelu) to sekret — cały katalog
`portable/` jest w `.gitignore`. Zgubiony pendrive → `cloudflared tunnel delete <nazwa>`.

## Backup na własny serwer

Pendrive jest pojedynczym punktem awarii: zgubisz go albo padnie kość — znikają
i pliki z magazynu, i baza tokenów. Dlatego dropgate umie wypchnąć cały katalog
stanu (`shares.json`, `secret.key`, `config.json`, poświadczenia tunelu, `files/`)
na własny serwer po SSH.

```bash
python3 dropgate.py backup            # spakuj i wyślij teraz
python3 dropgate.py backup --status   # kiedy ostatnio, ile kopii, ile miejsca
python3 dropgate.py restore --yes     # odtwórz najnowszą (NADPISUJE stan)
```

W trybie `go` backup leci sam po każdej zmianie bazy (5 s wyciszenia), a panel
pokazuje „backup 3 min temu" — kliknięcie wymusza kopię.

Ponieważ `secret.key` i tokeny wracają 1:1, **po odtworzeniu na nowym pendrivie
stare linki działają dalej** (o ile domena wskazuje tam, gdzie teraz stoi dropgate).

### Klucz bez shella

Backup nie używa Twojego zwykłego klucza SSH. Na serwerze siedzi mały odbiornik
przypięty do osobnego klucza:

```
# ~/.ssh/authorized_keys
restrict,command="/home/USER/dropgate-recv.sh" ssh-ed25519 AAAA… dropgate-portable
```

`dropgate-recv.sh` rozumie wyłącznie `list | put <plik> | get <plik> | prune <n> | stat`,
waliduje nazwę regexem i nie skleja niczego z shellem. Zgubiony pendrive daje więc
dostęp do własnych kopii, **nie do serwera** — a i to odcinasz, kasując jedną linijkę
z `authorized_keys`.

Klucz hosta jest przypięty w `state/known_hosts`, więc backup z obcej sieci nie
da się podstawić pod MITM — przy podmienionym kluczu połączenie po prostu pada.

Windows OpenSSH odmawia użycia klucza leżącego na pendrivie (ACL „Everyone" →
`bad permissions`). dropgate wykrywa to i na czas transferu robi prywatną kopię
klucza w katalogu tymczasowym, nadpisuje ją losowymi bajtami i kasuje.

Konfiguracja siedzi w `config.json`:

```json
"backup": {"host": "10.0.0.5", "user": "backup", "key": "backup_key",
           "known_hosts": "known_hosts", "auto": true, "keep": 10, "timeout": 8}
```

Backup działa tam, gdzie widać serwer. Wpisz adres z sieci mesh (Tailscale,
WireGuard, ZeroTier) zamiast LAN-owego — wtedy kopie robią się z każdej sieci,
a nie tylko spod domowego routera. Gdy serwera nie widać, kopie po prostu się nie
robią: dropgate pisze o tym w panelu i nie blokuje pracy, a po nieudanej próbie
czeka `retry_after` sekund. **Nie kasuj tej karencji** — seria nieudanych logowań
to najprostsza droga do bana od fail2ban po stronie serwera.

Skrypt odbiornika: [`extras/dropgate-recv.sh`](extras/dropgate-recv.sh).

## Stała domena

```bash
cloudflared tunnel create dropgate
cloudflared tunnel route dns dropgate drop.twoja-domena.pl
cp ~/.cloudflared/<uuid>.json  <stan>/tunnel.json
python3 dropgate.py config --mode named --hostname drop.twoja-domena.pl --tunnel-id <uuid>
```

Osobny tunel na dropgate'a, nie doklejanie hostname'u do istniejącego: ta sama nazwa
tunelu uruchomiona na dwóch maszynach to repliki, a ruch idzie do **geograficznie
najbliższej** — czyli z pendrive'a trafiałby losowo raz tu, raz tam.
