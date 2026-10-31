# Configuration — 0.0.1

Run the **same version** on both Unraid hosts. Navigate to `http://YOUR-UNRAID-IP:8210`, sign in with `APP_USERNAME` and the private `APP_PASSWORD` you set in Unraid, and configure the local LAN identity in Settings. Pair the second server using the one-time code from the Servers & pairing page.

Default network settings: host network, HTTP API/Web UI port `8210`, and authenticated transfer receiver port `8211`. These ports should be reachable **only between trusted machines**. No public ingress or router forwarding.

The `/data` mount stores local configuration, generated session keys, pairing credentials, job records, and temporary transfer metadata. Do not upload or check in this directory. Host-path mappings and the Docker socket are necessary for operations but grant sensitive host access.

Application release: **0.0.1**. Internal migration protocol: **6** (kept for application compatibility; it is not a published release number).
