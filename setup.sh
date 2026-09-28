#!/usr/bin/env bash
# wazuh-stack/setup.sh — Deploy Wazuh single-node stack on miner (Tailscale-only)
set -euo pipefail

MINER="deploy@example-host"
TAILSCALE_IP="100.64.0.20"
LOCAL_IP="127.0.0.1"
STACK_DIR="/home/soc/wazuh-stack"
WAZUH_MANAGER_IP="$TAILSCALE_IP"  # agents connect via this Tailscale IP

echo "=== Wazuh Stack Deployment ==="
echo "Miner Tailscale IP: $TAILSCALE_IP"
echo ""

# ── 1. Create directories on miner ──────────────────────────────────────────
echo "[1/8] Creating directories on miner..."
ssh -i ~/.ssh/deploy_key "$MINER" "mkdir -p $STACK_DIR/config"
echo "  ✓ Directories created"

# ── 2. Rsync docker-compose and config to miner ─────────────────────────────
echo "[2/8] Copying stack files to miner..."
rsync -az --progress -e "ssh -i ~/.ssh/deploy_key" \
  ~/wazuh-stack/ \
  "$MINER:$STACK_DIR/"
echo "  ✓ Files copied"

# ── 3. Create self-signed certs for dashboard ──────────────────────────────
echo "[3/8] Generating self-signed TLS certs..."
ssh -i ~/.ssh/deploy_key "$MINER" bash << 'ENDSSH'
set -e
STACK_DIR="/home/soc/wazuh-stack"
CERTS_DIR="$STACK_DIR/config/certs"
mkdir -p "$CERTS_DIR"

# Generate CA + cert for dashboard
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout "$CERTS_DIR/wazuh_dashboard.key" \
  -out "$CERTS_DIR/wazuh_dashboard.crt" \
  -subj "/CN=miner-wazuh/O=Wazuh/OU=Security" \
  2>/dev/null

# Generate keystore (pem) for nginx
cat "$CERTS_DIR/wazuh_dashboard.crt" "$CERTS_DIR/wazuh_dashboard.key" \
  > "$CERTS_DIR/wazuh_dashboard.pem"

echo "  Certs generated:"
ls -la "$CERTS_DIR/"
ENDSSH
echo "  ✓ Certs created"

# ── 4. Stop existing wazuh containers (if any) ──────────────────────────────
echo "[4/8] Cleaning up any existing Wazuh containers..."
ssh -i ~/.ssh/deploy_key "$MINER" bash << 'ENDSSH'
set -e
cd /home/soc/wazuh-stack
# Remove old containers/volumes if they exist
docker-compose down -v --remove-orphans 2>/dev/null || true
# Clean up any dangling images
docker image prune -f 2>/dev/null || true
echo "  Cleanup done"
ENDSSH
echo "  ✓ Cleanup complete"

# ── 5. Pull images ───────────────────────────────────────────────────────────
echo "[5/8] Pulling Wazuh Docker images (this may take a few minutes)..."
ssh -i ~/.ssh/deploy_key "$MINER" bash << 'ENDSSH'
set -e
cd /home/soc/wazuh-stack
docker-compose pull
echo "  Images pulled:"
docker images | grep wazuh
ENDSSH
echo "  ✓ Images pulled"

# ── 6. Start stack ──────────────────────────────────────────────────────────
echo "[6/8] Starting Wazuh stack..."
ssh -i ~/.ssh/deploy_key "$MINER" bash << 'ENDSSH'
set -e
cd /home/soc/wazuh-stack
docker-compose up -d
echo "  Containers started:"
docker-compose ps
ENDSSH
echo "  ✓ Stack started"

# ── 7. Wait for services to be healthy ─────────────────────────────────────
echo "[7/8] Waiting for services to come up (~60s)..."
sleep 30
ssh -i ~/.ssh/deploy_key "$MINER" bash << 'ENDSSH'
set -e
cd /home/soc/wazuh-stack
echo "  Container status:"
docker-compose ps
echo ""
echo "  Health checks:"
for container in wazuh.manager wazuh.indexer wazuh.dashboard; do
  status=$(docker inspect -f '{{.State.Health.Status}}' $container 2>/dev/null || echo "no-healthcheck")
  echo "    $container: $status"
done
ENDSSH
echo "  ✓ Services running"

# ── 8. Configure firewall: only Tailscale can reach Wazuh ports ─────────────
echo "[8/8] Configuring firewall (Tailscale-only access)..."
ssh -i ~/.ssh/deploy_key "$MINER" bash << 'ENDSSH'
set -e
sudo iptables -F TS_WAZUH_INPUT 2>/dev/null || true
sudo iptables -N TS_WAZUH_INPUT 2>/dev/null || true

# Accept from Tailscale CGNAT range (100.64.0.0/10) — all Tailscale traffic
sudo iptables -A TS_WAZUH_INPUT -s 100.64.0.0/10 -p tcp \
  -m multiport --dports 1514,1515,55000,5601,9200 \
  -j ACCEPT

# Drop everything else to these ports
sudo iptables -A TS_WAZUH_INPUT -p tcp \
  -m multiport --dports 1514,1515,55000,5601,9200 \
  -j DROP

# Insert TS_WAZUH_INPUT at the top of INPUT chain
sudo iptables -I INPUT 1 -j TS_WAZUH_INPUT

# Save
sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null 2>&1 || \
  sudo netfilter-persistent save 2>/dev/null || true

echo "  Firewall configured:"
sudo iptables -L TS_WAZUH_INPUT -n
ENDSSH
echo "  ✓ Firewall locked down to Tailscale-only"

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Services (Tailscale-only, no public exposure):"
echo "  • Wazuh API:    https://$TAILSCALE_IP:55000"
echo "  • Dashboard:   https://$TAILSCALE_IP:5601"
echo "  • Indexer:     https://$TAILSCALE_IP:9200"
echo "  • Agent port:  $TAILSCALE_IP:1514 (TCP)"
echo "  • Enrollment:  $TAILSCALE_IP:1515 (TCP)"
echo ""
echo "Credentials:"
echo "  admin / <dashboard password from .env>"
echo ""
echo "Tailscale serve (optional — gives you https://miner/ in browser):"
echo "  ssh $MINER"
echo "  sudo tailscale serve https://127.0.0.1:5601"
echo ""
echo "To watch logs:"
echo "  ssh $MINER 'cd $STACK_DIR && docker-compose logs -f'"
echo ""
echo "To stop:"
echo "  ssh $MINER 'cd $STACK_DIR && docker-compose down'"