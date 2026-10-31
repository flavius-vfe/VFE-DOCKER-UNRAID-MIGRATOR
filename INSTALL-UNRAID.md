# Install version 0.0.1 using Unraid Docker Web UI

## Prerequisite

The repository owner must first publish image `ghcr.io/flavius-vfe/vfe-docker-unraid-migrator:0.0.1` and set its GHCR package visibility to **public**. Until that image exists, Unraid cannot pull it.

## Option A — Add Container entirely in the Web UI

Repeat on **both** Unraid servers:

1. Open **Docker → Add Container**. Enter **Name** `vfe-docker-unraid-migrator`, **Repository** `ghcr.io/flavius-vfe/vfe-docker-unraid-migrator:0.0.1`, **Network Type** `Host`, and WebUI `http://[IP]:[PORT:8210]` where supported.
2. Set **Extra Parameters** to `--restart=unless-stopped` if supported; leave Privileged **off**.
3. Use **Add another Path, Port, Variable, Label or Device** to create the following **Path** mappings (host → container):

   | Host path | Container path | Access |
   |---|---|---|
   | `/var/run/docker.sock` | `/var/run/docker.sock` | read/write |
   | `/mnt` | `/host/mnt` | read/write |
   | `/var/lib/docker/volumes` | `/host/var/lib/docker/volumes` | read/write |
   | `/boot/config/plugins/dockerMan/templates-user` | `/host/boot/config/plugins/dockerMan/templates-user` | read/write |
   | `/dev` | `/host/dev` | read-only (optional) |
   | `/mnt/user/appdata/vfe-docker-unraid-migrator` | `/data` | read/write |

4. Add these **Variables**: `WEB_PORT=8210`, `RSYNC_PORT=8211`, `APP_USERNAME=admin`, `APP_PASSWORD=<your own long unique password>`. **Never commit the password to GitHub.** Optional: `STOP_TIMEOUT=30`, `IMAGE_PULL_TIMEOUT=900`. In Unraid choose the password/masked field option where supported.
5. Click **Apply**. Open `http://YOUR-UNRAID-IP:8210`. If the ports are occupied, change the variables on both servers as required. With host networking, do **not** add Docker port mappings.
6. Repeat on the second server, then configure server IPs and pair the agents within the Web UI. Allow only trusted traffic between the two server LAN addresses on the Web/API and rsync ports.

## Option B — Included Unraid XML template

The project includes [`templates/vfe-docker-unraid-migrator.xml`](templates/vfe-docker-unraid-migrator.xml) containing the settings above. Unraid's built-in Add Container page does **not necessarily** support importing an arbitrary remote XML URL. If your installation supports remote templates, use the template URL in the XML. Otherwise use Option A; or place the XML into the server's `dockerMan/templates-user` directory using your preferred file-management method and select it from the Docker template selector. Review all paths and enter a new password before Apply.

## Publishing the first image (repository owner)

1. Upload this release's files to the `main` branch at `https://github.com/flavius-vfe/VFE-DOCKER-UNRAID-MIGRATOR`.
2. In GitHub Actions, allow workflows to run; create and push tag **`v0.0.1`**. The `Publish Docker image` workflow builds and pushes image `:0.0.1` automatically. Manual workflow dispatch validates the build but deliberately does **not** publish.
3. In GitHub **Packages**, make the GHCR package **public** so Unraid pulls anonymously. Check that `:0.0.1` is visible before installation.

## Uninstall / protect data

Removing this application container should **not** automatically remove the mapped host `/mnt/user/appdata/vfe-docker-unraid-migrator`. That directory contains private pairing secrets and session data: back it up securely or delete manually when no longer needed. Avoid sharing Docker logs containing host paths and network details.
