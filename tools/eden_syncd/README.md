# Eden Syncd

`eden-syncd` is the self-hosted object and snapshot-head service used by Eden Save Sync. It does
not interpret save data. Clients upload encrypted blobs and use compare-and-swap when advancing a
scope's snapshot head, so concurrent saves are reported as conflicts instead of being overwritten.

## Run locally

```sh
export EDEN_SYNCD_TOKEN='replace-with-a-long-random-token'
export EDEN_SYNCD_ADMIN_TOKEN='a-different-long-random-token'
export EDEN_SYNCD_OPENSAVE_USERNAME='opensave'
export EDEN_SYNCD_OPENSAVE_PASSWORD='a-third-long-random-secret'
go run . --data-dir ./data --listen 127.0.0.1:8787
```

The health endpoint is unauthenticated at `GET /healthz`. All `/v1` endpoints require
`Authorization: Bearer <token>`. When both `EDEN_SYNCD_OPENSAVE_USERNAME` and
`EDEN_SYNCD_OPENSAVE_PASSWORD` are set, OpenSave clients can use standard WebDAV at
`http://127.0.0.1:8787/opensave` with those Basic Auth credentials.

## Administrator dashboard

Set the optional `EDEN_SYNCD_ADMIN_TOKEN` (it must differ from `EDEN_SYNCD_TOKEN`; when the two
match the dashboard stays disabled) and open `http://<nas-private-ip>:<port>/admin/` from the home
LAN. Sign in with the administrator token; the session is kept for seven days in an HttpOnly,
SameSite=Strict cookie and repeated wrong tokens are rate limited per address.

The dashboard provides:

- **Overview**: save scopes, snapshots, stored bytes and deduplication savings, online devices,
  free space on the data volume, a 30-day upload/conflict chart and recent activity.
- **Saves**: searchable game list with covers. Eden clients publish the game title and icon
  automatically; a display name and logo URL can also be set manually. Each scope shows its
  snapshot history with the uploading device and size, and supports:
  - *Set as current*: commits a new head that references an older encrypted snapshot. History is
    kept. Devices apply it with **Download latest cloud saves**; existing local saves are never
    overwritten automatically.
  - *Pin*: pinned snapshots are never removed by the retention policy.
  - *Download* the encrypted snapshot (it cannot be read without the Vault key).
  - Delete individual snapshots (never the current one) or the whole scope.
- **Devices**: platform, Eden version, address, last activity, upload counts; devices can be given
  an alias or removed from the list (removal does not revoke access; rotate the sync token for
  that).
- **Activity**: the last 500 uploads, conflicts, restores and maintenance events.
- **Maintenance**: retention policy, storage cleanup with a dry-run preview, and an integrity check
  that rehashes every referenced object.

All dashboard features are also available as a JSON API under `/admin/api/`, which accepts HTTP
Basic Auth (any username, administrator token as the password). State-changing requests must send
`X-Eden-Admin: 1`. Prometheus metrics are served at `/metrics` with the same authentication.
Keep the dashboard on the private LAN; do not publish it on the Internet.

### Retention and garbage collection

By default every snapshot is kept. A retention policy keeps a snapshot when it is among the newest
*N* of its scope **or** younger than *D* days; the current head and pinned snapshots are always
kept. The policy runs after each upload and, together with collection of unreferenced objects,
every `--maintenance-interval` (6 hours by default). Objects uploaded within the last hour are never
collected, so in-flight client uploads are safe. Initial values come from
`EDEN_SYNCD_KEEP_SNAPSHOTS` / `EDEN_SYNCD_KEEP_DAYS`; once saved in the dashboard they are stored in
`data/settings.json` and take precedence.

### Configuration

| Flag | Environment variable | Default |
| --- | --- | --- |
| `--token` | `EDEN_SYNCD_TOKEN` | required |
| `--admin-token` | `EDEN_SYNCD_ADMIN_TOKEN` | dashboard disabled |
| `--opensave-username` | `EDEN_SYNCD_OPENSAVE_USERNAME` | disables the OpenSave WebDAV endpoint unless paired with a password |
| `--opensave-password` | `EDEN_SYNCD_OPENSAVE_PASSWORD` | disables the OpenSave WebDAV endpoint unless paired with a username |
| `--data-dir` | `EDEN_SYNCD_DATA` | `./data` (`/var/lib/eden-syncd` in Docker) |
| `--listen` | `EDEN_SYNCD_LISTEN` | `:8787` |
| `--max-object-mib` | `EDEN_SYNCD_MAX_OBJECT_MIB` | `512` |
| `--keep-snapshots` | `EDEN_SYNCD_KEEP_SNAPSHOTS` | `0` (unlimited) |
| `--keep-days` | `EDEN_SYNCD_KEEP_DAYS` | `0` (unlimited) |
| `--maintenance-interval` | `EDEN_SYNCD_MAINTENANCE_INTERVAL` | `6h` (`0` disables) |
| `--log-format` | `EDEN_SYNCD_LOG_FORMAT` | `text` (or `json`) |

`eden-syncd healthcheck` probes `/healthz` and is used by the Docker `HEALTHCHECK`.
`eden-syncd --version` prints the build version.

### OpenSave WebDAV

OpenSave and Eden use separate protocols and credentials. Setting both
`EDEN_SYNCD_OPENSAVE_USERNAME` and `EDEN_SYNCD_OPENSAVE_PASSWORD` enables only the dedicated
`/opensave/` WebDAV collection. It accepts `OPTIONS`, `PROPFIND`, `PUT`, `HEAD`, `GET`, `DELETE`,
and `MOVE`, which covers desktop OpenSave's cloud mirror and Android OpenSave's staged upload.

Use the `EDEN_SYNCD` provider in OpenSave and enter the service root, for example
`https://nas.example:8788`; the client normalizes it to `https://nas.example:8788/opensave`.
Every PC that uses the same endpoint and Basic Auth credentials shares one cloud mirror. OpenSave
publishes a small current-save marker alongside its ZIP snapshots, so a later-opened PC can safely
take a save that continues from its own history. Divergent saves are offered for review instead of
being overwritten by timestamp.

The OpenSave collection stores ordinary OpenSave ZIP snapshots, not Eden-encrypted objects. Keep it
behind HTTPS, use a unique password that is not either Eden token, and include
`data/opensave/` in the NAS backup policy along with the rest of the data directory.

Clients identify themselves with a local persistent device ID. A device is shown as online while
it has contacted the service within the last 90 seconds. The device ID is not a credential and is
stored only in the client's local save-sync cache.

Normal automatic sync is conflict-safe: a local save never silently replaces a
newer cloud head, and a conflict is retained locally for review. The desktop
Settings > Web Service > Save Sync page also provides **Download latest cloud
saves**. That explicit operation treats the cloud head as authoritative,
moves each existing local save directory to a `.eden-save-sync-backup-*`
directory beside it, then installs the cloud snapshot. Close all games before
using it.

## Run on a NAS

Create a `.env` file next to `compose.yaml` containing `EDEN_SYNCD_TOKEN` and, when the dashboard
is wanted, a separate `EDEN_SYNCD_ADMIN_TOKEN`. To enable OpenSave, also set the independent
`EDEN_SYNCD_OPENSAVE_USERNAME` and `EDEN_SYNCD_OPENSAVE_PASSWORD` pair; create a writable
`data` directory owned by UID `10001`. Run `docker compose up -d --build` from this directory.
The listener binds to `127.0.0.1:8787` by default. Set `EDEN_SYNCD_PORT` to use another host port,
or `EDEN_SYNCD_BIND_ADDRESS` only when a firewall or Tailscale configuration protects it.
Set `EDEN_SYNCD_DATA_DIR` to store the persistent encrypted objects outside the Compose directory.

For a private home LAN, bind to the NAS's fixed private address rather than `0.0.0.0`, for example
`EDEN_SYNCD_BIND_ADDRESS=192.168.12.14`. Do not create a router port-forward for the sync port.
Eden clients require HTTPS by default; plain HTTP for a private IPv4 address requires enabling the
explicit **Allow insecure LAN HTTP** client setting. The save payload remains encrypted, but the
bearer token can be observed on that network.

### Deploy a published image

After copying [`.env.example`](.env.example) to `.env`, replacing the placeholder tokens, and
optionally setting the OpenSave Basic Auth pair, run:

```sh
docker compose -f compose.nas.yaml up -d
```

`compose.nas.yaml` pulls `jun9100/eden-syncd:latest`, persists data at
`/var/lib/eden-syncd`, and binds only to `192.168.12.14:8788` by default. Adjust the three
`EDEN_SYNCD_*` location/address variables for a different NAS. Existing systemd users should not
run this Compose service against the same port and data directory until the systemd service has
been stopped.

For Synology and other NAS systems, set `PUID` and `PGID` in `.env` to the numeric owner of
`EDEN_SYNCD_DATA_DIR`; the container uses these values to avoid changing permissions on existing
encrypted backup data.

### Synology Container Manager

Use [`compose.synology.yaml`](compose.synology.yaml) when deploying through Synology Container
Manager. It intentionally does not use Compose variable interpolation, which some DSM releases
reject during project creation. Copy it as `compose.yaml`, create a sibling `.env` file with only:

```sh
EDEN_SYNCD_TOKEN=replace-with-a-long-random-sync-token
EDEN_SYNCD_ADMIN_TOKEN=replace-with-a-different-long-random-admin-token
EDEN_SYNCD_OPENSAVE_USERNAME=opensave
EDEN_SYNCD_OPENSAVE_PASSWORD=replace-with-a-third-long-random-secret
```

Before starting the project, set the `user` field to the numeric owner of
`/volume1/docker/eden-syncd/data` and adjust the host data path or `8788` port where needed.

## Run with systemd

The [`eden-syncd.service`](eden-syncd.service) template is useful when Docker images cannot be
pulled on the NAS. Build or copy an `eden-syncd` binary to `/usr/local/bin/eden-syncd`, create the
`eden-syncd` system user and `/var/lib/eden-syncd` data directory, then place the token in
`/etc/eden-syncd.env`:

```sh
EDEN_SYNCD_TOKEN=replace-with-a-long-random-token
EDEN_SYNCD_ADMIN_TOKEN=a-different-long-random-token
EDEN_SYNCD_OPENSAVE_USERNAME=opensave
EDEN_SYNCD_OPENSAVE_PASSWORD=replace-with-a-third-long-random-secret
```

Install the unit at `/etc/systemd/system/eden-syncd.service`, then run
`systemctl daemon-reload && systemctl enable --now eden-syncd`. Override the `--listen` address in
the unit when using a protected reverse proxy or Tailscale endpoint.

For an isolated LAN-only installation, set `--listen` to the NAS's fixed private address (for
example `192.168.12.14:8788`) and do not configure a router port-forward. Configure clients with
the matching `http://` URL only after enabling their **Allow insecure LAN HTTP** setting.

Place the service behind HTTPS. A Tailscale network is the recommended home-NAS deployment because
it avoids exposing port 8787 publicly. For a public deployment, use a reverse proxy with a valid
TLS certificate and do not publish the service without authentication.

The `data` directory contains every encrypted object and the snapshot index (`state.json`). When
OpenSave WebDAV is enabled it also contains `opensave/`, which holds its independent ZIP snapshot
mirror. Include the entire directory in the NAS backup policy and test restoration independently of
Eden. It also holds dashboard labels and devices (`dashboard.json`), dashboard settings
(`settings.json`) and the activity log (`events.json`). Data directories from earlier releases are
read without migration.
