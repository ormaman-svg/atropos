#!/usr/bin/env bash
#
# Throwaway local Postgres for development and tests.
#
# Deliberately not Docker: the isolation tests need to run anywhere, including
# CI runners and sandboxes with no Docker daemon. This drives the postgres
# binaries directly and keeps its cluster in .pgdata (gitignored).
#
#   ./scripts/pg-dev.sh start
#   ./scripts/pg-dev.sh stop
#   ./scripts/pg-dev.sh url
#
# The server refuses to run as root, so when invoked as root we drop to the
# `postgres` system user and hand it ownership of the cluster directory.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PGDATA="$ROOT/.pgdata"
PGPORT="${PGPORT:-55432}"
DB="${PGDATABASE:-atropos_dev}"

PGBIN="$(dirname "$(command -v pg_ctl 2>/dev/null || echo /nonexistent/x)")"
if [ ! -x "$PGBIN/pg_ctl" ]; then
  PGBIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1 || true)"
fi
if [ ! -x "${PGBIN:-/nonexistent}/pg_ctl" ]; then
  echo "postgres binaries not found (checked PATH and /usr/lib/postgresql/*/bin)" >&2
  exit 1
fi

# Run a command as the unprivileged cluster owner when we happen to be root.
as_pg() {
  if [ "$(id -u)" -eq 0 ]; then
    su postgres -s /bin/bash -c "$1"
  else
    bash -c "$1"
  fi
}

url() { echo "postgresql://postgres@localhost:$PGPORT/$DB"; }

running() { as_pg "'$PGBIN/pg_ctl' -D '$PGDATA' status" >/dev/null 2>&1; }

case "${1:-}" in
  start)
    if [ ! -d "$PGDATA" ]; then
      mkdir -p "$PGDATA"
      [ "$(id -u)" -eq 0 ] && chown postgres "$PGDATA"
      echo "initialising cluster at $PGDATA"
      as_pg "'$PGBIN/initdb' -D '$PGDATA' -U postgres --auth=trust" >/dev/null
    fi

    if running; then
      echo "already running on port $PGPORT"
    else
      as_pg "'$PGBIN/pg_ctl' -D '$PGDATA' -l '$PGDATA/server.log' \
        -o '-p $PGPORT -k $PGDATA -c listen_addresses=localhost' -w start" >/dev/null
      echo "started on port $PGPORT"
    fi

    if as_pg "'$PGBIN/createdb' -h localhost -p '$PGPORT' -U postgres '$DB'" 2>/dev/null; then
      echo "created database $DB"
    else
      echo "database $DB already exists"
    fi
    url
    ;;
  stop)
    if running; then
      as_pg "'$PGBIN/pg_ctl' -D '$PGDATA' -w stop" >/dev/null
      echo "stopped"
    else
      echo "not running"
    fi
    ;;
  url)
    url
    ;;
  *)
    echo "usage: $0 {start|stop|url}" >&2
    exit 1
    ;;
esac
