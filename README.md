# ul3

Small anonymous file upload service – successor of ul2 (PHP).

- Upload via button, drag & drop anywhere on the page, or paste (Ctrl+V or the paste button — files, images and text); parallel uploads with progress
- Share to ul3 from Android: install the page as an app first (Chrome/Edge/Samsung Internet, "Install app"), then pick ul3 in the share sheet; shared files and text appear in the preview and upload only after you confirm
- Each browser gets a random UUID (localStorage); the UUID lists and deletes its own uploads
- Files keep their original name; each URL contains a random 128-bit token (`/files/<token>/<name>`), so links can't be guessed
- Files expire after `RETENTION_DAYS` (built-in hourly cleanup, no cron needed)
- Per-client limits on uploads, history lookups and admin login attempts; uploads pause when the disk runs low
- Admin page at `/admin` (all uploads, delete, run cleanup now)
- curl: `curl -T file https://host/` prints the link
- ShareX: per-user `.sxcu` download on the main page; `POST /upload.php` still works for old configs

**Stack:** one Go binary (stdlib HTTP + pure-Go SQLite, no CGO), vanilla HTML/CSS/JS embedded into it, no build step for the frontend. The Docker image is `FROM scratch`, ~15 MB, runs as uid 65532 with a read-only root fs.

## Configuration

| Env var | Default | |
|---|---|---|
| `PUBLIC_URL` | – | Base URL for generated links. If unset, taken from `X-Forwarded-Proto` / `Host` set by the proxy. |
| `MAX_UPLOAD_MB` | `100` | Per-file limit, enforced server-side while streaming. |
| `RETENTION_DAYS` | `7` | |
| `CLEANUP_INTERVAL_MINUTES` | `60` | |
| `ADMIN_PASSWORD` / `ADMIN_PASSWORD_FILE` | – | Unset = admin disabled. Must be at least 16 characters, otherwise admin stays disabled (logged at startup). Failed logins lock out per IPv4 address or IPv6 /48 (10 tries, then one per 10 minutes); there is no global lockout, so others cannot lock you out. Use a random password (`openssl rand -base64 24`). |
| `DATA_DIR` | `/data` | Holds `uploads.db` and `files/`. |
| `UPLOADS_PER_HOUR` | `120` | Per client (IPv4 address / IPv6 /64). `0` = unlimited. |
| `UPLOAD_MB_PER_HOUR` | `2048` | Per client. `0` = unlimited. |
| `MIN_FREE_MB` | `1024` | Uploads get `507` when free disk space minus the bytes reserved by uploads still in progress would drop below this. `0` = off. |
| `UPLOAD_TIMEOUT_MINUTES` | `30` | Maximum time to receive one upload. Other requests must arrive within 1 minute. |
| `TRUSTED_PROXIES` | `none` | Comma-separated CIDRs/IPs whose `X-Forwarded-For` is believed when finding the client IP for the limits above. Behind a reverse proxy, set it to the proxy's network (`compose.yaml` sets the private ranges). Never include addresses clients can connect from directly, or they can spoof their IP. |
| `LISTEN` | `:8080` | |

## Deploy

```bash
openssl rand -base64 24 > admin_password.txt
mkdir -p data && sudo chown 65532:65532 data
docker compose up -d --build
```

Rate limits key on the client IP taken from the proxy's `X-Forwarded-For`, which is only believed from `TRUSTED_PROXIES` (set in `compose.yaml` to the private ranges Docker networks use). If every request is logged with the same `client=` address, the proxy isn't trusted and all users share one limit.

**Upgrading:** `TRUSTED_PROXIES` used to default to the private ranges and now defaults to `none`. If you run ul3 behind a proxy without setting it, add `TRUSTED_PROXIES` (e.g. `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7`).

`compose.yaml` contains Traefik labels (edit host, entrypoint, cert resolver, network). For Caddy, drop the labels and use `Caddyfile.example`. Neither proxy limits body size by default; if you put nginx in between, raise `client_max_body_size`.

## Migrating from ul2

The database schema is unchanged, so the old data can be used directly:

```bash
mkdir -p data
cp /path/to/ul2/inc/uploads.db data/
cp -a /path/to/ul2/files data/
sudo chown -R 65532:65532 data
```

Old file URLs (`/files/<name>`) keep working if the domain points at ul3. New uploads use `/files/<token>/<original name>`. Users keep their history since the UUID lives in each browser's localStorage under the same key (same origin required).

## API

| | |
|---|---|
| `POST /api/upload` | multipart: `file-upload` (any file field works), optional `uuid` → `{success: id, url, filename}` |
| `PUT /{name}` | raw body is the file (`curl -T`), optional `?uuid=` → file URL as plain text |
| `GET /api/history` | header `X-UUID: <uuid>` (or `?uuid=`, which ends up in proxy access logs) → `{files: [...]}` |
| `POST /api/delete` | JSON `{id, uuid}` |
| `GET /api/admin/uploads`, `POST /api/admin/delete`, `POST /api/admin/cleanup` | `Authorization: Bearer <password>` or the session cookie |
| `POST /api/admin/login` `{"password": "…"}`, `POST /api/admin/logout` | Sets / clears the admin session cookie (30 days, HttpOnly, SameSite=Strict; changing the password signs all sessions out) |
| `GET /files/{token}/{name}` | served with `Content-Security-Policy: sandbox`, so uploaded SVG can't run script on this origin; HTML is always sent as a download (`Content-Disposition: attachment`); JavaScript/CSS uploads are served as `text/plain` so they can't be loaded as scripts or styles |
| `GET /files/{name}` | legacy ul2 links |
| `GET /healthz` | |

```bash
curl -T screenshot.png https://ul.example.com/            # prints the URL
some-command | curl -T - https://ul.example.com/log.txt   # from stdin
curl -F "file-upload=@screenshot.png" https://ul.example.com/api/upload  # JSON response
```

Add `?uuid=<your browser UUID>` to have curl uploads show up in that browser's history.
