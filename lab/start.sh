#!/usr/bin/env bash
# Stocked lab: brings up the 192.0.2.2 target and runs an HTTP intranet (port 80) and
# an SMB file server (port 445) on it, both filled with FICTIONAL data.
#
#     sudo lab/start.sh             # stays in the foreground; Ctrl-C stops everything
#
# Then, in another terminal: put 192.0.2.2 in scope.txt, then
# "sudo python -m offense.netns up".
set -euo pipefail

if [ "$(id -u)" != 0 ]; then
    echo "Run as root: sudo lab/start.sh" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
PY="${PYTHON:-python3}"
RUN_AS="${SUDO_USER:-root}"
DATA=/tmp/pc-lab-data
ADDRESS=192.0.2.2

cd "$ROOT"
"$PY" -m offense.lab up

# Inside the lab namespace only: low ports (80, 445) can be opened without root.
ip netns exec pc-lab sysctl -qw net.ipv4.ip_unprivileged_port_start=0

# Working copy: the services never write into the repository.
rm -rf "$DATA"
mkdir -p "$DATA"/samba/{lock,state,cache,pid,private,ncalrpc}
cp -r "$HERE/www" "$HERE/partage" "$DATA/"
sed "s|@DATA@|$DATA|g; s|@RUN_AS@|$RUN_AS|g" "$HERE/smb.conf.template" > "$DATA/samba/smb.conf"

# Account for the "archives" share: the password is the one the intranet leaves lying
# around in sauvegardes/intranet.conf.bak (single source, no drift).
ACCOUNT="$(sed -n 's/^utilisateur *= *//p' "$HERE/www/sauvegardes/intranet.conf.bak")"
SECRET="$(sed -n 's/^mot_de_passe *= *//p' "$HERE/www/sauvegardes/intranet.conf.bak")"
echo "$RUN_AS = $ACCOUNT" > "$DATA/samba/accounts.map"
printf '%s\n%s\n' "$SECRET" "$SECRET" \
    | smbpasswd -c "$DATA/samba/smb.conf" -a -s "$RUN_AS" > /dev/null

chown -R "$RUN_AS" "$DATA"
chmod -R u+rwX,go+rX "$DATA"
chmod 700 "$DATA/samba/private"

PIDS=()
stop_all() {
    trap - INT TERM EXIT
    echo
    echo "[LAB] Stopping services..."
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    "$PY" -m offense.lab down
}
trap stop_all INT TERM EXIT

"$PY" -m offense.lab run -- python3 -m http.server 80 --bind "$ADDRESS" \
    --directory "$DATA/www" > "$DATA/http.log" 2>&1 < /dev/null &
PIDS+=($!)

"$PY" -m offense.lab run -- smbd --foreground --no-process-group \
    --configfile="$DATA/samba/smb.conf" > "$DATA/smbd.out" 2>&1 < /dev/null &
PIDS+=($!)

sleep 2
for pid in "${PIDS[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[LAB] A service failed to start - see $DATA/http.log and $DATA/smbd.out" >&2
        exit 1
    fi
done

echo "[LAB] Intranet: http://$ADDRESS/        Shares: //$ADDRESS/public  //$ADDRESS/archives"
echo "[LAB] Services running as \"$RUN_AS\". Logs: $DATA. Ctrl-C to stop everything."
wait
