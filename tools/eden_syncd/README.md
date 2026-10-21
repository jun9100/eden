# Eden Syncd

`eden-syncd` is the self-hosted object and snapshot-head service used by Eden Save Sync. It does
not interpret save data. Clients upload encrypted blobs and use compare-and-swap when advancing a
scope's snapshot head, so concurrent saves are reported as conflicts instead of being overwritten.

## Run locally

```sh
export EDEN_SYNCD_TOKEN='replace-with-a-long-random-token'
export EDEN_SYNCD_ADMIN_TOKEN='a-different-long-random-token'
go run . --data-dir ./data --listen 127.0.0.1:8787
```

The health endpoint is unauthenticated at `GET /healthz`. All `/v1` endpoints require
`Authorization: Bearer <token>`.

## LAN dashboard

Set the optional `EDEN_SYNCD_ADMIN_TOKEN` to enable `GET /admin/`. Open
`http://<nas-private-ip>:<port>/admin/` from the home LAN and authenticate with
HTTP Basic Auth: the username can be any non-empty value and the password is the
administrator token. This must be a different secret from `EDEN_SYNCD_TOKEN`.
The dashboard shows scope, snapshot, and content-addressed object counts,
including repeated object references, and lets the administrator attach a
display name and HTTPS/HTTP Logo URL to each scope. Eden clients can publish a
game title and icon as metadata; when that metadata is available it is shown
automatically. Manual labels remain available for older clients or unmatched
games. These labels are stored separately in `dashboard.json` and never alter
encrypted snapshots. Embedded client icons are served through the authenticated
dashboard and are not placed in the editable URL field.

Repeated object references are reported for inspection only. The server never
merges scopes or deletes snapshots automatically, because separate scopes may
belong to different games, accounts, or devices. Keep the dashboard on the
private LAN; do not publish it on the Internet.

Clients identify themselves with a local persistent device ID. The dashboard
lists the device name, platform, Eden version, and last activity; a device is
shown as online while it has contacted the service within the last 90 seconds.
The device ID is not a credential and is stored only in the client's local
save-sync cache.

Normal automatic sync is conflict-safe: a local save never silently replaces a
newer cloud head, and a conflict is retained locally for review. The desktop
Settings > Web Service > Save Sync page also provides **Download latest cloud
saves**. That explicit operation treats the cloud head as authoritative,
moves each existing local save directory to a `.eden-save-sync-backup-*`
directory beside it, then installs the cloud snapshot. Close all games before
using it.

## Run on a NAS

Create a `.env` file next to `compose.yaml` containing `EDEN_SYNCD_TOKEN` and, when the dashboard
is wanted, a separate `EDEN_SYNCD_ADMIN_TOKEN`; create a writable
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

After copying [`.env.example`](.env.example) to `.env` and replacing both placeholder tokens, run:

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

The `data` directory contains every encrypted object and the snapshot index. Include it in the
NAS backup policy and test restoration independently of Eden. It also contains the optional
dashboard display labels in `dashboard.json`.
