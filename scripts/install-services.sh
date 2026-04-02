#!/usr/bin/env bash
# ============================================================
# Install systemd services and deploy wrapper. Run as root.
# This is a ONE-TIME setup — conway user cannot modify these.
# ============================================================
set -euo pipefail

echo "==> Installing deploy-restart wrapper..."
cat > /usr/local/bin/conway-deploy-restart << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Sync Caddyfile from repo if present
if [ -f /opt/conway-agent/caddy/Caddyfile ]; then
    cp /opt/conway-agent/caddy/Caddyfile /etc/caddy/Caddyfile
fi
systemctl daemon-reload
systemctl restart api-dashboard
systemctl restart api-router
systemctl restart mcp-server
systemctl restart caddy
EOF
chmod 755 /usr/local/bin/conway-deploy-restart
chown root:root /usr/local/bin/conway-deploy-restart
echo "  Installed /usr/local/bin/conway-deploy-restart (root-owned, 755)"

echo "==> Installing systemd services..."

cat > /etc/systemd/system/api-dashboard.service << 'EOF'
[Unit]
Description=API Dashboard
After=network.target

[Service]
Type=simple
User=conway
Group=conway
WorkingDirectory=/opt/conway-agent
ExecStart=/home/conway/.bun/bin/bun run apis/dashboard/index.ts
Restart=always
RestartSec=5
Environment=NODE_ENV=production
EnvironmentFile=/opt/conway-agent/.env

# Resource limits
MemoryMax=512M
MemoryHigh=400M
CPUQuota=80%
TasksMax=256
LimitNOFILE=4096

# Sandboxing
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/conway-agent/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/api-router.service << 'EOF'
[Unit]
Description=API Router (multi-API subdomain router)
After=network.target

[Service]
Type=simple
User=conway
Group=conway
WorkingDirectory=/opt/conway-agent
ExecStart=/home/conway/.bun/bin/bun run apis/router.ts
Restart=always
RestartSec=5
Environment=NODE_ENV=production
EnvironmentFile=/opt/conway-agent/.env

# Resource limits — higher for multi-API
MemoryMax=1G
MemoryHigh=800M
CPUQuota=80%
TasksMax=512
LimitNOFILE=4096

# Sandboxing
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/conway-agent/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/mcp-server.service << 'EOF'
[Unit]
Description=APIMesh MCP Server (Streamable HTTP)
After=network.target

[Service]
Type=simple
User=conway
Group=conway
WorkingDirectory=/opt/conway-agent/mcp-server
ExecStart=/home/conway/.bun/bin/bun run http.ts
Restart=always
RestartSec=5
Environment=NODE_ENV=production
EnvironmentFile=/opt/conway-agent/.env

# Resource limits
MemoryMax=512M
MemoryHigh=400M
CPUQuota=80%
TasksMax=256
LimitNOFILE=4096

# Sandboxing — needs outbound internet to call *.apimesh.xyz APIs
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/conway-agent/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/conway-brain.service << 'EOF'
[Unit]
Description=Conway Brain — autonomous API scout/build/prune
After=network.target

[Service]
Type=oneshot
User=conway
Group=conway
WorkingDirectory=/opt/conway-agent
ExecStart=/home/conway/.bun/bin/bun run scripts/brain/index.ts
TimeoutStartSec=600
Environment=NODE_ENV=production
EnvironmentFile=/opt/conway-agent/.env

# Resource limits
MemoryMax=1G
MemoryHigh=800M
CPUQuota=80%
TasksMax=256
LimitNOFILE=4096

# Sandboxing — needs outbound internet + write to apis/ and public/
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/conway-agent/data /opt/conway-agent/apis /opt/conway-agent/public
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/conway-brain.timer << 'EOF'
[Unit]
Description=Run Conway Brain daily

[Timer]
OnCalendar=*-*-* 06:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF

echo "==> Stopping old api-web-checker if present..."
systemctl stop api-web-checker 2>/dev/null || true
systemctl disable api-web-checker 2>/dev/null || true
rm -f /etc/systemd/system/api-web-checker.service

echo "==> Installing Caddy config..."

mkdir -p /etc/caddy/conf.d

cat > /etc/caddy/Caddyfile << 'CADDYEOF'
# Import per-service configs (e.g. Tonos) that live outside this file
import /etc/caddy/conf.d/*.caddyfile

(security_headers) {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'none'; frame-ancestors 'none'"
        Permissions-Policy "geolocation=(), camera=(), microphone=()"
        -Server
    }
}

(dashboard_headers) {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src data:; connect-src 'self'"
        Permissions-Policy "geolocation=(), camera=(), microphone=()"
        -Server
    }
}

apimesh.xyz {
    request_body {
        max_size 64KB
    }

    handle /.well-known/* {
        root * /opt/conway-agent/public
        file_server
    }

    handle /llms.txt {
        root * /opt/conway-agent/public
        file_server
    }

    handle /dashboard {
        import dashboard_headers
        reverse_proxy localhost:3000 {
            header_up X-Real-IP {remote_host}
            header_up -X-Forwarded-For
        }
    }

    handle {
        import security_headers
        reverse_proxy localhost:3000 {
            header_up X-Real-IP {remote_host}
            header_up -X-Forwarded-For
        }
    }
}

mcp.apimesh.xyz {
    import security_headers

    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }

    request_body {
        max_size 64KB
    }
    reverse_proxy localhost:3002 {
        header_up X-Real-IP {remote_host}
        header_up -X-Forwarded-For
    }
}

*.apimesh.xyz {
    import security_headers

    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }

    request_body {
        max_size 16KB
    }
    reverse_proxy localhost:3001 {
        header_up X-Real-IP {remote_host}
        header_up -X-Forwarded-For
    }
}
CADDYEOF

echo "==> Updating sudoers..."

cat > /etc/sudoers.d/conway << 'EOF'
conway ALL=(root) NOPASSWD: /usr/local/bin/conway-deploy-restart
conway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active api-dashboard
conway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active api-router
conway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active mcp-server
conway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active caddy
conway ALL=(root) NOPASSWD: /usr/bin/systemctl status api-dashboard
conway ALL=(root) NOPASSWD: /usr/bin/systemctl status api-router
conway ALL=(root) NOPASSWD: /usr/bin/systemctl status mcp-server
conway ALL=(root) NOPASSWD: /usr/bin/systemctl status caddy
# Removed direct systemctl restart — use only conway-deploy-restart wrapper
conway ALL=(root) NOPASSWD: /usr/bin/journalctl -u api-dashboard
conway ALL=(root) NOPASSWD: /usr/bin/journalctl -u api-router
conway ALL=(root) NOPASSWD: /usr/bin/journalctl -u mcp-server
conway ALL=(root) NOPASSWD: /usr/bin/journalctl -u conway-brain
EOF
chmod 440 /etc/sudoers.d/conway
visudo -c

echo "==> Enabling and starting services..."
systemctl daemon-reload
systemctl enable api-dashboard api-router mcp-server conway-brain.timer
systemctl restart api-dashboard api-router mcp-server caddy

sleep 3

echo "==> Verification..."
systemctl is-active api-dashboard api-router caddy
echo ""
echo "Done. Service files are now root-owned and immutable from conway."
echo "conway can only: sudo /usr/local/bin/conway-deploy-restart"
echo ""
echo "NOTE: Caddy requires cloudflare DNS plugin for wildcard TLS."
echo "  Build: xcaddy build --with github.com/caddy-dns/cloudflare"
echo "  Set CF_API_TOKEN in Caddy's environment (e.g. /etc/default/caddy)"
