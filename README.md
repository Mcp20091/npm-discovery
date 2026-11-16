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

Everything below can be set in the web page on the **Settings** tab (including a Test NPM connection
button). Values saved there are stored in the database and override `/etc/npm-discovery/config.env`
(see [config.env.example](config.env.example)), which only provides the starting values. "Reset all to
config.env" on the Settings tab discards the saved values. The listen address/port need a service restart
(there is a Restart button). Skipped addresses are managed on the **Exclusions** tab; `SCAN_EXCLUDE`
in the file is also honoured.

The NPM password is stored in plain text in the database (`/var/lib/npm-discovery/discovery.db`, readable
only by the service user) and is never sent back to the browser.

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
| `SCAN_GENTLE` | `false` | Slower, rate-limited scan (nmap `-T2`, 20 packets/s, 5 parallel; 3 parallel HTTP probes) that is less likely to trigger security software |
| `SCAN_PORTS` | common homelab list | Ports to check |
| `SCAN_ALL_PORTS` | `false` | Scan all 65535 ports (slow) |
| `PROBE_TIMEOUT` | `5` | Seconds per HTTP/HTTPS probe |
| `WEB_HOST`, `WEB_PORT` | `0.0.0.0`, `8080` | Web UI bind address and port |

Quote values containing spaces or special characters. The file is readable only by root and the service user.

## Using it

Open `http://<container-ip>:8080`. The header shows the last scan time and status
(running / finished / failed); **Scan now** starts a scan on demand. Errors from NPM (login failure,
unreachable, API errors) appear as red banners, and Add errors show under the row.

## Web page password (optional)

By default the web page has no login. To protect it, open **Settings > Web page password**, type a
password (8+ characters) and click **Set password**. From then on every page and API call needs a login
(session cookie, valid 12 hours, HttpOnly + SameSite=Strict; a service restart signs everyone out) and a
**Log out** link appears in the header. After 5 wrong attempts from one IP within 5 minutes that IP is
locked out for 5 minutes. Only a salted scrypt hash is stored, never the password. **Remove password**
on the same tab turns it off again (you must be logged in). "Reset all to config.env" keeps the password.

Without HTTPS the password travels in clear text on your LAN, so this keeps out casual visitors but not
someone sniffing the network. Put the page behind NPM with an SSL certificate for real protection. The
lockout is per client IP as seen by the service, so behind a reverse proxy all users share one address.

**Forgot the password?** Stop the service, delete the stored hash, start it again:

```bash
systemctl stop npm-discovery
sqlite3 /var/lib/npm-discovery/discovery.db "DELETE FROM settings WHERE key='_auth_hash';"
systemctl start npm-discovery
```

Do not expose the web UI to the internet even with a password.

## Backup, restore and history

- **History tab:** the last 100 scans with start time, duration, status, how many services were found,
  how many were new and how many disappeared. Show lists the services a scan found.
- **Settings tab, Backup & restore:** Download backup saves one JSON file with your settings and exclusions,
  and optionally discoveries, dismissals and scan history. Passwords (the NPM password and the web page
  password) are left out unless you tick the box, because anyone with the file could read them.
- **Restore from file** replaces the settings and exclusions, and the discoveries and history if the file
  has them. Saved passwords are kept unless the file carries new ones. The file is checked completely before
  anything changes, so a bad file changes nothing.
- Settings that come only from `config.env` are not in the backup; only values saved in the web page are.

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
