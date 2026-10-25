<!--
SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
SPDX-License-Identifier: GPL-3.0-or-later
-->
<!-- lang: en-GB -->

# Save Sync

Eden Save Sync creates an encrypted, versioned snapshot after a game closes, then uploads it to an
`eden-syncd` service you control. It synchronizes account saves and device saves only. Game files,
keys, firmware, complete NAND images, SDMC data, mods, shader caches, and logs are never sent.
Each encrypted snapshot is authenticated to its save scope, so the server cannot substitute it into
another title or user scope.

On an orderly game stop or normal application close, Eden first persists the snapshot locally and
then makes an immediate upload pass before the session finishes. A network failure leaves the
snapshot in the local retry queue. On desktop, wait for Eden to exit after closing its window; using
the operating system's task-kill command, a power loss, or a crash can bypass that final pass. Those
events cannot upload progress that has not yet been flushed, so reopen the same device and let it
finish synchronizing before continuing that game elsewhere. Upgrade every Eden client before
upgrading `game-save`: current `game-save` releases reject save writes from older clients to prevent
their obsolete state tracking from advancing a cloud head.

Before launching a game, Eden checks the matching remote scope. If the local save directory is empty,
it downloads, verifies, decrypts, and installs the latest snapshot. When an existing local save still
matches the content digest recorded for its last synchronized snapshot, Eden can also safely advance it
to a newer cloud head. Eden also verifies that the local files still match their confirmed cloud head
before allowing a new upload to continue that head. A stale copy, manual replacement, or interrupted
state is retained as a local and `game-save` conflict snapshot instead of silently becoming the newest
cloud version. During the first v2 sync after an upgrade, Eden ignores the old content cache and
quarantines old pending snapshots; an existing local save is trusted only after its content matches a
read-only download of the current cloud head. If the server confirms that the scope has no cloud head,
Eden retains any pending chain rooted at the missing head locally, clears only its stale baseline, and
creates a new initial snapshot from the current local files. An upload already queued from a confirmed
local state can continue safely after a restart. A locally changed or pending save is never overwritten
automatically; if two devices change the same scope independently, the later upload is kept as a fixed
conflict copy instead of overwriting the server version. Select the desired copy in the `game-save`
dashboard; when the local files match the selected cloud head, Eden clears its local conflict marker
and resumes normal synchronization.

## Configure Eden

On desktop, open `Emulation > Configure > General > Web`. On Android, open the gear icon and
choose **Save Sync**. In the Save Sync section, enable automatic save backup and sync, then enter:

- The HTTPS URL of your `eden-syncd` installation. For an isolated home LAN, you can explicitly
  allow HTTP and use a private IPv4 address (`10.0.0.0/8`, `172.16.0.0/12`, or
  `192.168.0.0/16`). This does not expose the save plaintext, which remains encrypted, but it does
  expose the bearer token to anyone able to observe that network. Never enable it for a public
  endpoint.
- The bearer token configured on the server.
- A 64-character hexadecimal Vault key shared by every device in the same sync group. Use the
  Generate button on one trusted device, then transfer the key using a private channel.

These are global settings, so they apply to every game. Save Sync uses the account UUID and title
ID as its account-save scope. Use the same Eden profile on every device that should share an
account save.

Snapshots are written under Eden's cache directory before any network transfer. Failed uploads stay
in the local queue. Android retries them after the app starts and after emulation stops; desktop
builds retry while Eden remains open and on the next game launch.

## Host eden-syncd

The server source, Docker image, and Compose definition are in
[`tools/eden_syncd`](../../tools/eden_syncd). On a NAS with Docker Compose:

```sh
cd tools/eden_syncd
mkdir data
chown 10001 data
printf 'EDEN_SYNCD_TOKEN=replace-with-a-long-random-token\n' > .env
docker compose up -d --build
```

Run the service behind HTTPS. Tailscale is the recommended home-NAS setup because it avoids
opening a public port. If you publish it on the Internet, use a reverse proxy with a valid TLS
certificate; do not expose the HTTP listener directly.

Compose binds the service to `127.0.0.1:8787` by default. Set `EDEN_SYNCD_PORT` when that port is
occupied. Set `EDEN_SYNCD_BIND_ADDRESS` only when an upstream firewall or Tailscale configuration
restricts access. Set `EDEN_SYNCD_DATA_DIR` to place the persistent encrypted data on a NAS volume.
When Docker image pulls are unavailable, the service source also includes an
[`eden-syncd.service`](../../tools/eden_syncd/eden-syncd.service) systemd template.

### OpenSave cloud mirror

The same service can optionally host a separate WebDAV collection for OpenSave. Set both
`EDEN_SYNCD_OPENSAVE_USERNAME` and `EDEN_SYNCD_OPENSAVE_PASSWORD` in the Compose or systemd
environment, then configure OpenSave's **EDEN_SYNCD** provider with the service address and those
Basic Auth credentials. The OpenSave endpoint is `<service-url>/opensave`; the client adds that
suffix automatically when you enter only the service root.

This WebDAV collection is separate from Eden Save Sync's bearer token and encrypted object store.
It holds normal OpenSave ZIP snapshots, so use HTTPS and an independent password. PC OpenSave
clients that share the endpoint can automatically bring forward a save that continues from their
own history; a divergent save remains a conflict for review rather than silently replacing local
progress. Include `data/opensave/` in the NAS backup policy.

### LAN dashboard

`eden-syncd` includes an administrator dashboard at `/admin/`. Add a separate, long random
`EDEN_SYNCD_ADMIN_TOKEN` to the Compose `.env` file (or systemd `/etc/eden-syncd.env`), restart the
service, open `http://<private-NAS-IP>:<port>/admin/` on the home LAN and sign in with that token.

The dashboard shows every synced game with its snapshot history, connected devices, storage use and
recent activity. From it you can restore an older snapshot as the current cloud version (apply it on
a device with **Download latest cloud saves**), pin snapshots, configure automatic retention, reclaim
unused storage, and verify that every stored snapshot is intact. The server only ever sees encrypted
data; game names and icons come from the Eden clients or from labels you enter. Do not reuse the
sync bearer token as the administrator token, and do not expose this page to the public Internet.
See [`tools/eden_syncd/README.md`](../../tools/eden_syncd/README.md) for all options.

### Private LAN HTTP

For a network you control, bind the service to the NAS's fixed private address rather than all
interfaces, for example `--listen 192.168.12.14:8788`. Do not create a router port-forward for
this port. Configure each Eden device with `http://192.168.12.14:8788`, the same bearer token,
and the same Vault key, then enable **Allow insecure LAN HTTP**. The client rejects public and
hostname-based HTTP endpoints even with this option enabled.

## Development testing

For a local service:

```sh
cd tools/eden_syncd
export EDEN_SYNCD_TOKEN=test-token
go run . --data-dir ./data --listen 127.0.0.1:8787
```

When testing an Android device connected over USB, forward the local listener with:

```sh
adb reverse tcp:8787 tcp:8787
```

Use `http://127.0.0.1:8787` only for this local ADB test. Production configurations require HTTPS.
