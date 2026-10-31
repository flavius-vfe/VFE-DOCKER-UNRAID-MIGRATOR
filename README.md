# VFE Docker Unraid Migrator

**Initial public release: 0.0.1**

Move a Docker container and its persistent data between two paired Unraid servers over a trusted LAN. Install the same agent on **both** servers.

## Install using Unraid Docker Web UI (no terminal required)

The image must first be published by the GitHub Actions workflow. Once public, go to **Unraid → Docker → Add Container** (enable Advanced View only if your Unraid version requires it). Enter the settings from [INSTALL-UNRAID.md](INSTALL-UNRAID.md), and click **Apply**. The image will download from GHCR automatically.

**Repository/image:** `ghcr.io/flavius-vfe/vfe-docker-unraid-migrator:0.0.1`

**Web UI:** `http://YOUR-UNRAID-IP:8210`

A ready-made Docker XML template is supplied in [`templates/vfe-docker-unraid-migrator.xml`](templates/vfe-docker-unraid-migrator.xml); refer to [INSTALL-UNRAID.md](INSTALL-UNRAID.md) for the supported template import and manual UI options. A GitHub source URL is not itself a Docker image.

## Capabilities

- Pair two agents with a one-time code and migrate in either direction.
- Review source container configuration, persistent paths, named volumes and port conflicts.
- Choose registry image pull, existing destination image or verified image archive transfer.
- Perform staged rsync then final sync while the source container is stopped.
- Keep the source data by default for rollback.

## Security

Do not expose the Web UI or transfer port directly to the internet. The Docker socket and host storage bindings grant privileged access to the Unraid host. Choose a **different, strong Web Password** on each server. This repository contains no preconfigured passwords, pairing secrets, session state or production appdata. Live secrets are generated/stored in the mounted `/data` directory at runtime and must stay private. See [SECURITY.md](SECURITY.md).

## Documentation

- [Install from Unraid Docker management](INSTALL-UNRAID.md)
- [Settings and pairing](CONFIGURATION.md)
- [Security](SECURITY.md)
- [Initial release changelog](CHANGELOG.md)

License: MIT.
