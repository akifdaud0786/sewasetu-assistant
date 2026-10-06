#!/bin/sh
# Bring the whole stack up on the VM. Usage: sh deploy/up.sh <public-ip>
set -e
IP="$1"
[ -n "$IP" ] || { echo "usage: sh deploy/up.sh <public-ip>"; exit 1; }
HOST="sewasetu.$(echo "$IP" | tr . -).sslip.io"
if [ ! -f .env ]; then
  cat > .env <<ENV
SITE_HOST=$HOST
PUBLIC_BASE_URL=https://$HOST
ADMIN_PASSWORD=$(openssl rand -hex 8)
SECRET_KEY=$(openssl rand -hex 32)
ENV
fi
docker compose up -d --build
echo "Portal:  https://$HOST"
echo "Citizen MCP: https://$HOST/mcp/citizen"
echo "Officer MCP: https://$HOST/mcp/officer"
echo "Officer login: admin / $(grep ADMIN_PASSWORD .env | cut -d= -f2)"
