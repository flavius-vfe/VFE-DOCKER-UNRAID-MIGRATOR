# Security and privacy

- This release archive includes **source and configuration templates only**. It must never include your actual `APP_PASSWORD`, pairing secrets, session keys, server state, logs, database or host appdata.
- The included Docker XML deliberately leaves `APP_PASSWORD` **blank** and marks it as masked. Set a unique secret through Unraid for each installation.
- `/data` is generated on the Unraid host at runtime; do not commit, publish or share it.
- The app has significant host control through `/var/run/docker.sock` and writable `/mnt` access. Only install on servers you administer.
- Use a **trusted LAN**, restrict access to ports 8210/8211, and never port-forward them directly to the internet. The built-in UI uses HTTP by default; use a secure network or trusted TLS reverse proxy if needed.
- Do not publish container logs, Unraid templates exported after passwords were entered, or diagnostic archives without reviewing them for secrets.
- `.gitignore` and `.dockerignore` block common secret/state filenames, but cannot detect every custom secret. Review changes before every public push.
- Report security problems privately to the repository owner rather than posting credentials or sensitive logs in public issues.
