# NPM Discovery

Self-hosted web app that scans your home network for web services and lets you add them to
[Nginx Proxy Manager](https://nginxproxymanager.com/) (NPM) with one click. Nothing is added
automatically: every discovery waits for you to Add or Dismiss it.

- nmap TCP connect scan (`-sT`, works unprivileged) of your subnets on a schedule or on demand
- HTTP/HTTPS probe of each open port (title, `Server` header, reverse DNS)
- Compares with NPM proxy hosts: already-proxied services are listed separately
- Tabs: **New**, **Already proxied**, **Dismissed** (restorable); services that vanished are flagged **GONE**
- Add creates `<subdomain>.<BASE_DOMAIN>` with Block Common Exploits / Websockets toggles and an optional SSL certificate (Force SSL + HTTP/2 when one is chosen)

DNS is not touched; the app assumes a wildcard `*.BASE_DOMAIN` already points to NPM.

## LXC setup (Proxmox)

1. Create a Debian 12 container (unprivileged is fine; 512 MB RAM, 2 GB disk is plenty).
2. Put it on the same network/VLAN as the devices you want to scan, with a static IP or DHCP reservation.
3. Make sure the container can reach NPM's admin port (default 81).
4. No special features are needed: `-sT` uses normal sockets, so no raw-socket capabilities or nesting.

## Install

Inside the container, as root:

```bash
apt-get update && apt-get install -y git
git clone <this repo URL> /root/npm-discovery
cd /root/npm-discovery
./install.sh
nano /etc/npm-discovery/config.env
systemctl restart npm-discovery
```

The script installs Python and nmap, creates the `npm-discovery` system user, a venv in
`/opt/npm-discovery/venv`, copies the example config to `/etc/npm-discovery/config.env` (only if it
does not exist), and enables a systemd service that starts on boot. Data (SQLite) lives in
`/var/lib/npm-discovery`. Re-running `install.sh` updates the code and keeps your config and data.

## Configuration

`/etc/npm-discovery/config.env` (see [config.env.example](config.env.example)):

| Variable | Default | Meaning |
|---|---|---|
| `NPM_URL` | required | NPM admin URL, e.g. `http://192.168.1.10:81` |
| `NPM_EMAIL`, `NPM_PASSWORD` | required | NPM login (account must not use 2FA) |
| `NPM_VERIFY_TLS` | `true` | Set `false` for an https NPM_URL with a self-signed cert |
| `SCAN_SUBNETS` | required | Comma separated CIDRs, e.g. `192.168.1.0/24,192.168.2.0/24` |
| `SCAN_EXCLUDE` | empty | IPs/ranges to skip, e.g. `192.168.1.1,192.168.1.50-60` |
| `BASE_DOMAIN` | required | Proxy hosts become `<subdomain>.<BASE_DOMAIN>` |
| `SCAN_INTERVAL_HOURS` | `0` | Scheduled scan interval; `0` disables scheduling |
| `SCAN_ON_START` | `false` | Scan shortly after service start |
| `SCAN_PORTS` | common homelab list | Ports to check |
| `SCAN_ALL_PORTS` | `false` | Scan all 65535 ports (slow) |
| `PROBE_TIMEOUT` | `5` | Seconds per HTTP/HTTPS probe |
| `WEB_HOST`, `WEB_PORT` | `0.0.0.0`, `8080` | Web UI bind address and port |

Quote values containing spaces or special characters. The file is readable only by root and the service user.

## Using it

Open `http://<container-ip>:8080`. The header shows the last scan time and status
(running / finished / failed); **Scan now** starts a scan on demand. Errors from NPM (login failure,
unreachable, API errors) appear as red banners, and Add errors show under the row.

The web UI has no login. Keep it on your LAN and do not expose it to the internet.

## Logs and service control

```bash
journalctl -u npm-discovery -f
systemctl status npm-discovery
systemctl restart npm-discovery
```

## NPM API notes

The NPM API is not officially documented; request shapes follow the NPM source
(`backend/schema`): `POST /api/tokens`, `GET /api/tokens` (refresh), `GET/POST /api/nginx/proxy-hosts`,
`GET /api/nginx/certificates`. The token is refreshed an hour before it expires, and a 401 triggers a re-login.
A service counts as "already proxied" when a proxy host's `forward_host` equals its IP (or reverse DNS name) and the port matches.
