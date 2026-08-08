#!/bin/bash
# dropgate-recv.sh — odbiornik backupow dropgate.
# Uruchamiany WYLACZNIE jako wymuszona komenda klucza "dropgate-portable"
# w ~/.ssh/authorized_keys (restrict,command="..."). Klucz nie daje shella:
# wszystko, co przyjdzie, ląduje w $SSH_ORIGINAL_COMMAND i przechodzi przez
# ten case + walidacje nazwy. Nic nie jest podawane do shella bez cudzyslowu.

set -euo pipefail

DIR="$HOME/dropgate-backup"
mkdir -p "$DIR"

read -r -a argv <<< "${SSH_ORIGINAL_COMMAND:-}"
action="${argv[0]:-}"
arg="${argv[1]:-}"

valid_name() {
  [[ "$1" =~ ^dropgate-[0-9]{8}-[0-9]{6}\.tar\.gz$ ]]
}

case "$action" in
  list)
    ls -1t "$DIR" 2>/dev/null | grep -E '^dropgate-[0-9]{8}-[0-9]{6}\.tar\.gz$' | head -200 || true
    ;;
  put)
    valid_name "$arg" || { echo "zla nazwa pliku" >&2; exit 2; }
    cat > "$DIR/$arg.part"
    mv -f "$DIR/$arg.part" "$DIR/$arg"
    echo "ok $arg $(stat -c %s "$DIR/$arg")"
    ;;
  get)
    valid_name "$arg" || { echo "zla nazwa pliku" >&2; exit 2; }
    [[ -f "$DIR/$arg" ]] || { echo "brak takiego backupu" >&2; exit 3; }
    cat "$DIR/$arg"
    ;;
  prune)
    [[ "$arg" =~ ^[0-9]+$ ]] || { echo "prune wymaga liczby" >&2; exit 2; }
    ls -1t "$DIR" 2>/dev/null | grep -E '^dropgate-[0-9]{8}-[0-9]{6}\.tar\.gz$' \
      | tail -n +"$((arg + 1))" | while IFS= read -r f; do rm -f -- "$DIR/$f"; done
    echo "ok"
    ;;
  stat)
    echo "count $(ls -1 "$DIR" 2>/dev/null | grep -cE '^dropgate-[0-9]{8}-[0-9]{6}\.tar\.gz$' || true)"
    echo "bytes $(du -sb "$DIR" 2>/dev/null | cut -f1)"
    echo "free $(df -P "$DIR" | awk 'NR==2{print $4*1024}')"
    echo "newest $(ls -1t "$DIR" 2>/dev/null | head -1)"
    ;;
  *)
    echo "dozwolone komendy: list | put <plik> | get <plik> | prune <n> | stat" >&2
    exit 2
    ;;
esac
