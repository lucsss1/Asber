#!/usr/bin/env sh
# Dump the Asber database to ./backups, keeping the 14 most recent files.
#
# A full re-collection is not a backup strategy: the NVD sync alone takes
# 10-40 minutes and only reaches back NVD_TRACK_DAYS, so history that has
# aged out cannot be rebuilt.
#
# Install as a daily cron entry, e.g.
#   0 4 * * *  cd /srv/asber && ./scripts/backup.sh >> /var/log/asber-backup.log 2>&1
set -eu

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
DEST="${ASBER_BACKUP_DIR:-./backups}"
KEEP="${ASBER_BACKUP_KEEP:-14}"

mkdir -p "$DEST"
[ -f .env ] && . ./.env

stamp=$(date -u +%Y%m%dT%H%M%SZ)
target="$DEST/asber-$stamp.sql.gz"

# --clean --if-exists makes the dump restorable over an existing database.
docker compose -f "$COMPOSE_FILE" exec -T db \
  pg_dump -U "${POSTGRES_USER:-asber}" -d "${POSTGRES_DB:-asber}" --clean --if-exists \
  | gzip -9 > "$target.partial"

# Only publish under the final name once the dump completed, so a failed run
# never leaves a truncated file that looks like a good backup.
mv "$target.partial" "$target"
echo "wrote $target ($(du -h "$target" | cut -f1))"

ls -1t "$DEST"/asber-*.sql.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do
  echo "pruning $old"
  rm -f "$old"
done
