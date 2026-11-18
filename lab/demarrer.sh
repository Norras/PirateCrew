#!/usr/bin/env bash
# Lab garni : monte la cible 192.0.2.2 et y lance un intranet HTTP (port 80) et
# un serveur de fichiers SMB (port 445), tous deux remplis de données FICTIVES.
#
#     sudo lab/demarrer.sh          # reste au premier plan ; Ctrl-C arrête tout
#
# Ensuite, dans un autre terminal : mettre 192.0.2.2 dans scope.txt, puis
# « sudo python -m offense.netns up ».
set -euo pipefail

if [ "$(id -u)" != 0 ]; then
    echo "À lancer en root : sudo lab/demarrer.sh" >&2
    exit 2
fi

ICI="$(cd "$(dirname "$0")" && pwd)"
RACINE="$(dirname "$ICI")"
PY="${PYTHON:-python3}"
QUI="${SUDO_USER:-root}"
DONNEES=/tmp/pc-lab-donnees
ADRESSE=192.0.2.2

cd "$RACINE"
"$PY" -m offense.lab up

# Dans le namespace du lab seulement : les ports bas (80, 445) s'ouvrent sans root.
ip netns exec pc-lab sysctl -qw net.ipv4.ip_unprivileged_port_start=0

# Copie de travail : les services n'écrivent jamais dans le dépôt.
rm -rf "$DONNEES"
mkdir -p "$DONNEES"/samba/{lock,state,cache,pid,private,ncalrpc}
cp -r "$ICI/www" "$ICI/partage" "$DONNEES/"
sed "s|@DONNEES@|$DONNEES|g; s|@QUI@|$QUI|g" "$ICI/smb.conf.modele" > "$DONNEES/samba/smb.conf"

# Compte du partage « archives » : le mot de passe est celui que l'intranet laisse
# traîner dans sauvegardes/intranet.conf.bak (une seule source, pas de dérive).
COMPTE="$(sed -n 's/^utilisateur *= *//p' "$ICI/www/sauvegardes/intranet.conf.bak")"
SECRET="$(sed -n 's/^mot_de_passe *= *//p' "$ICI/www/sauvegardes/intranet.conf.bak")"
echo "$QUI = $COMPTE" > "$DONNEES/samba/comptes.map"
printf '%s\n%s\n' "$SECRET" "$SECRET" \
    | smbpasswd -c "$DONNEES/samba/smb.conf" -a -s "$QUI" > /dev/null

chown -R "$QUI" "$DONNEES"
chmod -R u+rwX,go+rX "$DONNEES"
chmod 700 "$DONNEES/samba/private"

PIDS=()
arreter() {
    trap - INT TERM EXIT
    echo
    echo "[LAB] Arrêt des services…"
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    "$PY" -m offense.lab down
}
trap arreter INT TERM EXIT

"$PY" -m offense.lab run -- python3 -m http.server 80 --bind "$ADRESSE" \
    --directory "$DONNEES/www" > "$DONNEES/http.log" 2>&1 < /dev/null &
PIDS+=($!)

"$PY" -m offense.lab run -- smbd --foreground --no-process-group \
    --configfile="$DONNEES/samba/smb.conf" > "$DONNEES/smbd.sortie" 2>&1 < /dev/null &
PIDS+=($!)

sleep 2
for pid in "${PIDS[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[LAB] Un service ne s'est pas lancé — voir $DONNEES/http.log et $DONNEES/smbd.sortie" >&2
        exit 1
    fi
done

echo "[LAB] Intranet : http://$ADRESSE/        Partages : //$ADRESSE/public  //$ADRESSE/archives"
echo "[LAB] Services lancés sous l'identité « $QUI ». Journaux : $DONNEES. Ctrl-C pour tout arrêter."
wait
