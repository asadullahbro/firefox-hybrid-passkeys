#!/bin/sh
# Registers the native-messaging host for deb/tarball Firefox and snap Firefox.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cat > "$DIR/host/run.sh" <<RUN
#!/bin/sh
exec "$DIR/.venv/bin/python" -I "$DIR/host/passkey_host.py"
RUN
chmod +x "$DIR/host/run.sh"
MANIFEST='{"name":"passkey_qr_host","description":"Passkey QR (hybrid) host","path":"'"$DIR"'/host/run.sh","type":"stdio","allowed_extensions":["passkey-qr@local"]}'
for d in "$HOME/.mozilla/native-messaging-hosts" "$HOME/snap/firefox/common/.mozilla/native-messaging-hosts"; do
  mkdir -p "$d" && echo "$MANIFEST" > "$d/passkey_qr_host.json" && echo "installed $d/passkey_qr_host.json"
done
