const state = {
  csrf: "",
  servers: [],
  containers: [],
  selectedContainerId: "",
  analysis: null,
  preflight: null,
  plan: null,
  currentView: "dashboard",
  jobTimer: null,
  currentJobRef: null,
  destinationImages: [],
};

const $ = (id) => document.getElementById(id);
const qsa = (selector) => [...document.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function imageHasExplicitVersion(reference) {
  const value = String(reference || "").trim();
  if (value.includes("@")) return true;
  return value.split("/").pop().includes(":");
}

function imageRepository(reference) {
  let value = String(reference || "").trim();
  if (!value || value.startsWith("sha256:")) return "";
  value = value.split("@", 1)[0];
  const slash = value.lastIndexOf("/");
  const prefix = slash >= 0 ? value.slice(0, slash + 1) : "";
  let final = slash >= 0 ? value.slice(slash + 1) : value;
  const colon = final.lastIndexOf(":");
  if (colon >= 0) final = final.slice(0, colon);
  return `${prefix}${final}`;
}

function updateSourceImageExamples() {
  const source = state.analysis?.container?.image || "qmcgaw/gluetun";
  const repository = imageRepository(source) || "qmcgaw/gluetun";
  $("configuredSourceExample").textContent = source;
  $("latestSourceExample").textContent = `${repository}:latest`;
  $("stableSourceExample").textContent = `${repository}:stable`;
}

const imageModeLabels = {
  pull_configured: "Pull configured source reference",
  pull_latest: "Pull source repository :latest",
  pull_stable: "Pull source repository :stable",
  pull_source: "Pull exact source tag or digest",
  pull_custom: "Pull a custom tag from registry",
  existing: "Use image already on destination",
  transfer: "Transfer exact source image",
};

function selectedImageMode() {
  return document.querySelector('input[name="imageMode"]:checked')?.value || "transfer";
}

function setImageMode(mode) {
  const radio = document.querySelector(`input[name="imageMode"][value="${mode}"]`);
  if (radio) radio.checked = true;
  updateImageModeUI();
}

function updateImageModeUI() {
  const mode = selectedImageMode();
  $("customImageRow").classList.toggle("hidden", mode !== "pull_custom");
  $("existingImageRow").classList.toggle("hidden", mode !== "existing");
  const source = state.analysis?.container?.image || "source image";
  const repository = imageRepository(source);
  const hints = {
    pull_configured: imageHasExplicitVersion(source)
      ? `The destination will pull the configured source reference ${source}.`
      : `The configured reference ${source} has no tag, so the safe pull target is ${repository || source}:latest. Docker has no separate untagged registry object.`,
    pull_latest: `The destination will pull ${repository || source}:latest.`,
    pull_stable: `The destination will pull ${repository || source}:stable. This fails clearly when the repository does not publish a stable tag.`,
    pull_source: imageHasExplicitVersion(source)
      ? `The destination will pull exactly ${source}.`
      : "This option requires an explicit source tag or digest. Choose a repository quick option, custom tag, or exact image transfer.",
    pull_custom: "Enter one explicit tag or digest. The migrator will never request all tags.",
    existing: "The selected image must already exist on the destination server.",
    transfer: "Safest for untagged, private, removed, or locally built images.",
  };
  $("imageModeHint").textContent = hints[mode] || "";
}

async function loadDestinationImages() {
  const destinationId = $("destinationServer").value;
  if (!destinationId) return;
  $("destinationImagesHint").textContent = "Loading destination images…";
  try {
    const payload = await api(`/api/images?server_id=${encodeURIComponent(destinationId)}`);
    state.destinationImages = payload.images || [];
    $("destinationImageChoices").innerHTML = state.destinationImages.map((item) =>
      `<option value="${escapeHtml(item.reference)}">${escapeHtml(item.short_id || "")}</option>`
    ).join("");
    $("destinationImagesHint").textContent = `${state.destinationImages.length} destination image reference(s) available.`;
  } catch (error) {
    state.destinationImages = [];
    $("destinationImageChoices").innerHTML = "";
    $("destinationImagesHint").textContent = `Could not load destination images: ${error.message}`;
  }
}

function formatBytes(value) {
  if (value === null || value === undefined) return "Unknown";
  let number = Number(value);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unit = 0;
  while (number >= 1024 && unit < units.length - 1) { number /= 1024; unit += 1; }
  return `${number >= 10 || unit === 0 ? number.toFixed(0) : number.toFixed(1)} ${units[unit]}`;
}

function flash(message, type = "good") {
  const el = $("flash");
  el.textContent = message;
  el.className = `flash ${type}`;
  clearTimeout(flash.timer);
  flash.timer = setTimeout(() => el.classList.add("hidden"), 6000);
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  if (state.csrf && options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  let payload = {};
  try { payload = await response.json(); } catch { payload = {}; }
  if (!response.ok) {
    const error = new Error(payload.error || `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function showLogin() {
  $("loginView").classList.remove("hidden");
  $("appView").classList.add("hidden");
}

function showApp() {
  $("loginView").classList.add("hidden");
  $("appView").classList.remove("hidden");
}

const titles = {
  dashboard: "Overview",
  migrate: "New migration",
  jobs: "Migration history",
  servers: "Servers & pairing",
  settings: "Settings",
};

function showView(name) {
  state.currentView = name;
  qsa(".view").forEach((item) => item.classList.toggle("active", item.id === `view-${name}`));
  qsa(".nav-link").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  $("pageTitle").textContent = titles[name] || name;
  document.querySelector(".sidebar").classList.remove("open");
  if (name === "jobs") loadJobs();
  if (name === "servers") loadServers();
  if (name === "settings") loadSettings();
  if (name === "migrate") initializeWizard();
}

function localServer() { return state.servers.find((item) => item.local); }
function serverById(id) { return state.servers.find((item) => item.server_id === id); }

async function initialize() {
  try {
    const session = await api("/api/session");
    state.csrf = session.csrf;
    showApp();
    await loadEverything();
  } catch (error) {
    if (error.status === 401) showLogin();
    else { showLogin(); $("loginError").textContent = error.message; }
  }
}

async function loadEverything() {
  await Promise.all([loadServers(), loadJobs(false)]);
  renderDashboard();
}

async function loadServers() {
  try {
    const payload = await api("/api/servers");
    state.servers = payload.servers || [];
    renderServerCards();
    renderPairedServers();
    fillServerSelectors();
    const local = localServer();
    if (local) {
      $("localIdentity").innerHTML = `<strong>${escapeHtml(local.server_name)}</strong><small>${escapeHtml(local.lan_ip || "LAN IP not configured")}:${escapeHtml(local.web_port)}</small>`;
      $("connectionBadge").textContent = state.servers.filter((item) => item.connected).length > 1 ? "Servers connected" : "One server";
      $("connectionBadge").className = `badge ${state.servers.filter((item) => item.connected).length > 1 ? "good" : "warn"}`;
    }
  } catch (error) {
    $("connectionBadge").textContent = "Connection error";
    $("connectionBadge").className = "badge bad";
    flash(error.message, "bad");
  }
}

function renderServerCards() {
  const root = $("serverCards");
  if (!state.servers.length) { root.innerHTML = '<div class="panel muted">No server information available.</div>'; return; }
  root.innerHTML = state.servers.map((server) => `
    <article class="server-card">
      <div class="server-top">
        <div><p class="eyebrow">${server.local ? "THIS SERVER" : "PAIRED SERVER"}</p><h3>${escapeHtml(server.server_name)}</h3></div>
        <span class="badge ${server.connected ? "good" : "bad"}">${server.connected ? "Connected" : "Offline"}</span>
      </div>
      <div class="server-meta">
        <div><small>LAN address</small><strong>${escapeHtml(server.lan_ip || "Not configured")}:${escapeHtml(server.web_port || "")}</strong></div>
        <div><small>Docker</small><strong>${escapeHtml(server.docker_version || "Unknown")}</strong></div>
        <div><small>Containers</small><strong>${escapeHtml(server.container_count ?? "—")}</strong></div>
        <div><small>Transfer port</small><strong>${escapeHtml(server.rsync_port || "—")}</strong></div>
      </div>
    </article>`).join("");
}

function renderPairedServers() {
  const root = $("pairedServers");
  const peers = state.servers.filter((item) => !item.local);
  if (!peers.length) {
    root.innerHTML = '<div class="list-item"><div class="main"><strong>No paired server</strong><small>Generate a code on one server and add it from the other.</small></div></div>';
    return;
  }
  root.innerHTML = peers.map((peer) => `
    <div class="list-item">
      <div class="main"><strong>${escapeHtml(peer.server_name)}</strong><small>${escapeHtml(peer.url || `${peer.lan_ip}:${peer.web_port}`)} · ${peer.connected ? "Connected" : escapeHtml(peer.error || "Offline")}</small></div>
      <button class="secondary remove-peer" data-peer="${escapeHtml(peer.server_id)}">Remove</button>
    </div>`).join("");
  qsa(".remove-peer").forEach((button) => button.addEventListener("click", async () => {
    if (!confirm("Remove this pairing from this server?")) return;
    try {
      await api(`/api/peers/${button.dataset.peer}/delete`, { method: "POST", body: "{}" });
      flash("Pairing removed.");
      await loadServers();
    } catch (error) { flash(error.message, "bad"); }
  }));
}

function renderDashboard() {
  renderServerCards();
  renderRecentJobs();
}

function jobRefs() {
  try { return JSON.parse(localStorage.getItem("unraidMigratorJobRefs") || "[]"); }
  catch { return []; }
}

function saveJobRef(ref) {
  const refs = jobRefs().filter((item) => !(item.source_server_id === ref.source_server_id && item.job_id === ref.job_id));
  refs.unshift(ref);
  localStorage.setItem("unraidMigratorJobRefs", JSON.stringify(refs.slice(0, 50)));
}

async function loadJobs(render = true) {
  try {
    const localPayload = await api("/api/jobs");
    const localId = localServer()?.server_id;
    const jobs = (localPayload.jobs || []).map((job) => ({ ...job, source_server_id: localId }));
    const remoteRefs = jobRefs().filter((ref) => ref.source_server_id !== localId).slice(0, 20);
    const remoteJobs = await Promise.all(remoteRefs.map(async (ref) => {
      try { return { ...(await api(`/api/jobs/${ref.source_server_id}/${ref.job_id}`)), source_server_id: ref.source_server_id }; }
      catch { return null; }
    }));
    state.jobs = [...jobs, ...remoteJobs.filter(Boolean)].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    if (render) renderJobs();
    renderRecentJobs();
  } catch (error) { if (render) flash(error.message, "bad"); }
}

function statusBadge(status) {
  const css = status === "completed" ? "good" : status === "failed" ? "bad" : status === "rolled_back" ? "warn" : "neutral";
  return `<span class="badge ${css}">${escapeHtml(String(status || "unknown").replaceAll("_", " "))}</span>`;
}

function renderRecentJobs() {
  const root = $("recentJobs");
  const jobs = (state.jobs || []).slice(0, 4);
  if (!jobs.length) { root.innerHTML = '<div class="list-item"><div class="main"><strong>No migration jobs yet</strong><small>Start with a paired server and one source container.</small></div></div>'; return; }
  root.innerHTML = jobs.map((job) => `
    <button class="list-item job-open" data-source="${escapeHtml(job.source_server_id)}" data-job="${escapeHtml(job.id)}">
      <div class="main"><strong>${escapeHtml(job.plan?.container_name || "Container")}</strong><small>${escapeHtml(job.phase)} · ${escapeHtml(job.progress_percent)}%</small></div>${statusBadge(job.status)}
    </button>`).join("");
  bindJobButtons();
}

function renderJobs() {
  const root = $("jobsList");
  const jobs = state.jobs || [];
  if (!jobs.length) { root.innerHTML = '<section class="panel muted">No migrations have been recorded.</section>'; return; }
  root.innerHTML = jobs.map((job) => `
    <article class="job-card">
      <div class="job-main">
        <div class="panel-head"><div><strong>${escapeHtml(job.plan?.container_name || "Container")}</strong><small>${escapeHtml(serverById(job.plan?.source_server_id)?.server_name || "Source")} → ${escapeHtml(serverById(job.plan?.destination_server_id)?.server_name || "Destination")}</small></div>${statusBadge(job.status)}</div>
        <div class="progress-track"><div style="width:${Number(job.progress_percent || 0)}%"></div></div>
        <div class="job-meta"><span>${escapeHtml(job.phase)}</span><span>${escapeHtml(job.progress_percent || 0)}%</span><span>${escapeHtml(job.created_at || "")}</span></div>
      </div>
      <button class="secondary job-open" data-source="${escapeHtml(job.source_server_id)}" data-job="${escapeHtml(job.id)}">Details</button>
    </article>`).join("");
  bindJobButtons();
}

function bindJobButtons() {
  qsa(".job-open").forEach((button) => button.onclick = () => openJob(button.dataset.source, button.dataset.job));
}

function fillServerSelectors() {
  const connected = state.servers.filter((item) => item.connected);
  const options = connected.map((server) => `<option value="${escapeHtml(server.server_id)}">${escapeHtml(server.server_name)}${server.local ? " (this server)" : ""}</option>`).join("");
  const oldSource = $("sourceServer").value;
  const oldDestination = $("destinationServer").value;
  $("sourceServer").innerHTML = options;
  $("destinationServer").innerHTML = options;
  if (connected.length > 1) {
    $("sourceServer").value = connected.some((item) => item.server_id === oldSource) ? oldSource : connected[0].server_id;
    $("destinationServer").value = connected.some((item) => item.server_id === oldDestination && item.server_id !== $("sourceServer").value) ? oldDestination : connected[1].server_id;
  }
}

function initializeWizard() {
  fillServerSelectors();
  setWizardStep(1);
  state.selectedContainerId = "";
  state.analysis = null;
  state.preflight = null;
  state.plan = null;
  if (state.servers.filter((item) => item.connected).length < 2) flash("Pair and connect both Unraid servers before starting a migration.", "bad");
}

function setWizardStep(step) {
  qsa(".wizard-panel").forEach((panel) => panel.classList.toggle("active", panel.id === `wizard-${step}`));
  qsa(".wizard-step").forEach((button) => button.classList.toggle("active", Number(button.dataset.step) === step));
}

async function loadSourceContainers() {
  const sourceId = $("sourceServer").value;
  const source = serverById(sourceId);
  $("containerSourceLabel").textContent = source ? `${source.server_name} · ${source.lan_ip}` : "";
  $("containerPicker").innerHTML = '<div class="list-item muted">Loading containers…</div>';
  const payload = await api(`/api/containers?server_id=${encodeURIComponent(sourceId)}`);
  state.containers = payload.containers || [];
  renderContainerPicker();
}

function renderContainerPicker() {
  const query = $("containerSearch").value.trim().toLowerCase();
  const items = state.containers.filter((item) => !query || item.name.toLowerCase().includes(query) || item.image.toLowerCase().includes(query));
  const root = $("containerPicker");
  if (!items.length) { root.innerHTML = '<div class="list-item muted">No matching containers.</div>'; return; }
  root.innerHTML = items.map((item) => `
    <label class="container-option ${state.selectedContainerId === item.id ? "selected" : ""}">
      <input type="radio" name="sourceContainer" value="${escapeHtml(item.id)}" ${state.selectedContainerId === item.id ? "checked" : ""}>
      <span class="details"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.image)}</small></span>
      <span class="badge ${item.state === "running" ? "good" : "neutral"}">${escapeHtml(item.state)}</span>
    </label>`).join("");
  qsa('input[name="sourceContainer"]').forEach((radio) => radio.onchange = () => {
    state.selectedContainerId = radio.value;
    $("containerNext").disabled = false;
    renderContainerPicker();
  });
}

async function analyzeSelectedContainer() {
  const sourceId = $("sourceServer").value;
  $("analysisState").textContent = "Analyzing…";
  $("analysisState").className = "badge neutral";
  setWizardStep(3);
  try {
    state.analysis = await api(`/api/analysis?server_id=${encodeURIComponent(sourceId)}&container_id=${encodeURIComponent(state.selectedContainerId)}`);
    populateMapping();
    $("analysisState").textContent = "Ready";
    $("analysisState").className = "badge good";
  } catch (error) {
    $("analysisState").textContent = "Analysis failed";
    $("analysisState").className = "badge bad";
    flash(error.message, "bad");
  }
}

function populateMapping() {
  const analysis = state.analysis;
  $("selectedContainerTitle").textContent = `${analysis.container.name} · ${analysis.container.image}`;
  updateSourceImageExamples();
  const explicitImageVersion = imageHasExplicitVersion(analysis.container.image);
  setImageMode(explicitImageVersion ? "pull_source" : "transfer");
  $("customImageReference").value = explicitImageVersion ? analysis.container.image : "";
  $("existingImageReference").value = "";
  loadDestinationImages();
  $("destinationName").value = analysis.container.name;
  const mode = analysis.network.mode || "bridge";
  $("networkMode").value = mode;
  $("staticIp").value = ["bridge", "host", "none", "default"].includes(mode) ? "" : (analysis.network.ipv4_address || "");
  updateNetworkInputs();

  const mountRoot = $("mountMappings");
  if (!analysis.mounts.length) mountRoot.innerHTML = '<div class="list-item muted">No persistent mounts were detected.</div>';
  else mountRoot.innerHTML = analysis.mounts.map((mount, index) => {
    const destination = mount.type === "volume" ? (mount.destination_volume || mount.volume_name || "") : (mount.destination_path || mount.source || "");
    return `<div class="mapping-row" data-mount-index="${index}">
      <input class="mount-selected" type="checkbox" ${mount.selected && mount.supported ? "checked" : ""} ${mount.supported ? "" : "disabled"}>
      <div class="source"><strong>${escapeHtml(mount.target)}</strong><small>${escapeHtml(mount.type)} · ${escapeHtml(mount.source)} · ${formatBytes(mount.size_bytes)}</small></div>
      <span class="arrow">→</span>
      <input class="mount-destination" value="${escapeHtml(destination)}" ${mount.supported ? "" : "disabled"}>
      <span class="mapping-policy">Conflicts are resolved during preflight</span>
    </div>`;
  }).join("");

  const portRoot = $("portMappings");
  if (!analysis.ports.length) portRoot.innerHTML = '<div class="list-item muted">No published ports.</div>';
  else portRoot.innerHTML = analysis.ports.map((port, index) => {
    const sourceServer = serverById($("sourceServer").value);
    const destinationServer = serverById($("destinationServer").value);
    const sourceHostIp = port.host_ip || "";
    const destinationHostIp = sourceHostIp && sourceHostIp === sourceServer?.lan_ip ? (destinationServer?.lan_ip || "") : sourceHostIp;
    return `<div class="mapping-row" data-port-index="${index}">
      <span></span>
      <div class="source"><strong>${escapeHtml(port.target)}/${escapeHtml(port.protocol)}</strong><small>Source ${escapeHtml(sourceHostIp || "*")}:${escapeHtml(port.source_host_port)}</small></div>
      <span class="arrow">→</span>
      <div class="port-destination-group"><input class="port-host-ip" placeholder="Host IP or blank" value="${escapeHtml(destinationHostIp)}"><input class="port-destination" type="number" min="1" max="65535" value="${escapeHtml(port.destination_host_port)}"></div>
      <span></span>
    </div>`;
  }).join("");
}

function updateNetworkInputs() {
  const mode = $("networkMode").value.trim() || "bridge";
  const standard = ["bridge", "host", "none", "default"].includes(mode);
  $("staticIp").disabled = standard;
  $("createNetwork").disabled = standard;
  if (standard) { $("staticIp").value = ""; $("createNetwork").checked = false; }
}

function collectPlan() {
  if (!state.analysis) throw new Error("Container analysis is not ready.");
  const analysis = state.analysis;
  const previousPlan = state.plan;
  const mounts = qsa("[data-mount-index]").map((row) => {
    const source = analysis.mounts[Number(row.dataset.mountIndex)];
    const destination = row.querySelector(".mount-destination").value.trim();
    const previous = previousPlan?.mounts?.find((item) => item.id === source.id);
    const sameDestination = source.type === "bind"
      ? previous?.destination_path === destination
      : previous?.destination_volume === destination;
    return {
      ...source,
      selected: row.querySelector(".mount-selected").checked,
      destination_path: source.type === "bind" ? destination : source.destination_path,
      destination_volume: source.type === "volume" ? destination : source.destination_volume,
      existing_policy: sameDestination ? (previous?.existing_policy || "error") : "error",
      destructive_confirmed: sameDestination ? !!previous?.destructive_confirmed : false,
    };
  });
  const ports = qsa("[data-port-index]").map((row) => {
    const source = analysis.ports[Number(row.dataset.portIndex)];
    return { ...source, host_ip: row.querySelector(".port-host-ip").value.trim(), destination_host_port: row.querySelector(".port-destination").value.trim() };
  });
  const destinationName = $("destinationName").value.trim();
  if (!destinationName) throw new Error("Destination container name is required.");
  if (!mounts.some((item) => item.selected) && analysis.mounts.some((item) => item.supported)) {
    if (!confirm("No persistent storage is selected. Continue without copying container data?")) throw new Error("Select at least one storage mapping.");
  }
  const networkMode = $("networkMode").value.trim() || "bridge";
  const sourceServer = serverById($("sourceServer").value);
  const destinationServer = serverById($("destinationServer").value);
  const imageMode = selectedImageMode();
  const previousSameName = previousPlan?.destination_name === destinationName;
  return {
    source_server_id: $("sourceServer").value,
    destination_server_id: $("destinationServer").value,
    source_lan_ip: sourceServer?.lan_ip || "",
    destination_lan_ip: destinationServer?.lan_ip || "",
    container_id: analysis.container.id,
    container_name: analysis.container.name,
    destination_name: destinationName,
    destination_name_policy: previousSameName ? (previousPlan?.destination_name_policy || "error") : "error",
    destination_name_replace_confirmed: previousSameName ? !!previousPlan?.destination_name_replace_confirmed : false,
    image: analysis.container.image,
    source_image: analysis.container.image,
    source_image_id: analysis.container.image_id || "",
    image_mode: imageMode,
    custom_image: $("customImageReference").value.trim(),
    existing_image: $("existingImageReference").value.trim(),
    mounts,
    ports,
    network: {
      mode: networkMode,
      ipv4_address: ["bridge", "host", "none", "default"].includes(networkMode) ? "" : $("staticIp").value.trim(),
      aliases: analysis.network.aliases || [],
      create_if_missing: $("createNetwork").checked,
      blueprint: analysis.network.network || {},
    },
    devices: (previousPlan?.devices || analysis.devices || []).map((item) => ({ ...item })),
    initial_sync: $("initialSync").checked,
    keep_source_container: $("keepSource").checked,
    restart_source_on_failure: $("restartOnFailure").checked,
    template: analysis.template || {},
    privileged: analysis.privileged,
  };
}

async function runPreflight() {
  try {
    state.plan = collectPlan();
    setWizardStep(4);
    await rerunPreflight();
  } catch (error) { flash(error.message, "bad"); }
}

async function rerunPreflight() {
  $("preflightBadge").textContent = "Checking…";
  $("preflightBadge").className = "badge neutral";
  $("preflightResults").innerHTML = '<div class="check-result">Running destination checks…</div>';
  $("startMigration").disabled = true;
  try {
    state.preflight = await api("/api/preflight", { method: "POST", body: JSON.stringify(state.plan) });
    if (state.preflight.destination_image) state.plan.destination_image = state.preflight.destination_image;
    renderPreflight();
  } catch (error) {
    state.preflight = { ok: false, issues: [{ code: "request_failed", message: error.message, actions: [] }], warnings: [] };
    renderPreflight();
  }
}

function conflictActionButtons(issue, issueIndex) {
  return (issue.actions || []).map((action, actionIndex) =>
    `<button class="conflict-action ${action.danger ? "danger compact-action" : "secondary compact-action"}" data-issue-index="${issueIndex}" data-action-index="${actionIndex}">${escapeHtml(action.label)}</button>`
  ).join("");
}

function renderPreflight() {
  const preflight = state.preflight;
  const results = [];
  if (preflight.ok) results.push('<div class="check-result good"><strong>✓</strong><div><span>All required destination checks passed.</span></div></div>');
  (preflight.issues || []).forEach((item, index) => results.push(`
    <div class="check-result bad conflict-card">
      <strong>×</strong>
      <div class="conflict-content"><span>${escapeHtml(item.message)}</span><div class="conflict-actions">${conflictActionButtons(item, index)}</div></div>
    </div>`));
  (preflight.warnings || []).forEach((item) => results.push(`<div class="check-result warn"><strong>!</strong><div><span>${escapeHtml(item.message)}</span></div></div>`));
  $("preflightResults").innerHTML = results.join("") || '<div class="check-result">No preflight output.</div>';
  qsa(".conflict-action").forEach((button) => button.onclick = () => applyConflictAction(
    preflight.issues[Number(button.dataset.issueIndex)],
    preflight.issues[Number(button.dataset.issueIndex)].actions[Number(button.dataset.actionIndex)]
  ));
  $("preflightBadge").textContent = preflight.ok ? "Ready" : "Conflicts found";
  $("preflightBadge").className = `badge ${preflight.ok ? "good" : "bad"}`;
  $("startMigration").disabled = !preflight.ok;
  const source = serverById(state.plan.source_server_id);
  const destination = serverById(state.plan.destination_server_id);
  $("planSummary").innerHTML = `
    <div><small>Direction</small><strong>${escapeHtml(source?.server_name)} → ${escapeHtml(destination?.server_name)}</strong></div>
    <div><small>Container</small><strong>${escapeHtml(state.plan.container_name)}</strong></div>
    <div><small>Storage selected</small><strong>${state.plan.mounts.filter((item) => item.selected).length} mapping(s)</strong></div>
    <div><small>Estimated transfer</small><strong>${formatBytes(preflight.estimated_transfer_bytes)}</strong></div>
    <div><small>Image method</small><strong>${escapeHtml(imageModeLabels[state.plan.image_mode] || state.plan.image_mode)}</strong><small>${escapeHtml(state.plan.destination_image || state.plan.source_image || "")}</small></div>
    <div><small>Network / IP</small><strong>${escapeHtml(state.plan.network.mode)} ${escapeHtml(state.plan.network.ipv4_address || "automatic")}</strong></div>`;
  $("sourcePolicyText").textContent = state.plan.keep_source_container
    ? "The source container will remain installed but stopped. Source appdata will be retained for rollback."
    : "The source container definition will be removed after validation, but its appdata and transferred files will still be retained.";
}

function mappingFromIssue(issue) {
  const id = issue.context?.mount_id;
  return state.plan.mounts.find((item) => item.id === id) || state.plan.mounts[Number(issue.context?.mount_index)];
}

function typedDestructiveConfirmation(message, expected) {
  const typed = prompt(`${message}\n\nType exactly:\n${expected}`);
  return typed === expected;
}

function syncPlanToForm() {
  if (!state.plan) return;
  $("destinationName").value = state.plan.destination_name || "";
  setImageMode(state.plan.image_mode || "transfer");
  $("customImageReference").value = state.plan.custom_image || "";
  $("existingImageReference").value = state.plan.existing_image || "";
  $("networkMode").value = state.plan.network?.mode || "bridge";
  $("staticIp").value = state.plan.network?.ipv4_address || "";
  $("createNetwork").checked = !!state.plan.network?.create_if_missing;
  updateNetworkInputs();
  qsa("[data-mount-index]").forEach((row) => {
    const source = state.analysis.mounts[Number(row.dataset.mountIndex)];
    const mapping = state.plan.mounts.find((item) => item.id === source.id);
    if (!mapping) return;
    row.querySelector(".mount-selected").checked = !!mapping.selected;
    row.querySelector(".mount-destination").value = mapping.type === "volume" ? (mapping.destination_volume || "") : (mapping.destination_path || "");
    const policy = row.querySelector(".mapping-policy");
    if (policy) policy.textContent = mapping.existing_policy && mapping.existing_policy !== "error" ? `Existing data: ${mapping.existing_policy}` : "Conflicts are resolved during preflight";
  });
  qsa("[data-port-index]").forEach((row) => {
    const port = state.plan.ports[Number(row.dataset.portIndex)];
    if (!port) return;
    row.querySelector(".port-host-ip").value = port.host_ip || "";
    row.querySelector(".port-destination").value = port.destination_host_port || "";
  });
}

async function applyConflictAction(issue, action) {
  const context = issue.context || {};
  const mapping = mappingFromIssue(issue);
  let value;
  switch (action.id) {
    case "path_merge":
      mapping.existing_policy = "merge"; mapping.destructive_confirmed = false; break;
    case "path_replace":
      if (!typedDestructiveConfirmation("This deletes all existing destination contents before copying source data.", context.destination)) return;
      mapping.existing_policy = "replace"; mapping.destructive_confirmed = true; break;
    case "path_change":
      value = prompt("Enter a different destination path:", context.destination || mapping?.destination_path || "");
      if (!value) return;
      mapping.destination_path = value.trim(); mapping.existing_policy = "error"; mapping.destructive_confirmed = false; break;
    case "volume_merge":
      mapping.existing_policy = "merge"; mapping.destructive_confirmed = false; break;
    case "volume_replace":
      if (!typedDestructiveConfirmation("This deletes and recreates the existing Docker volume.", context.volume_name)) return;
      mapping.existing_policy = "replace"; mapping.destructive_confirmed = true; break;
    case "volume_skip":
      mapping.existing_policy = "skip"; mapping.destructive_confirmed = false; break;
    case "volume_rename":
      value = prompt("Enter a different destination volume name:", context.volume_name || mapping?.destination_volume || "");
      if (!value) return;
      mapping.destination_volume = value.trim(); mapping.existing_policy = "error"; mapping.destructive_confirmed = false; break;
    case "mount_skip":
      mapping.selected = false; break;
    case "name_change":
      value = prompt("Enter a different destination container name:", state.plan.destination_name || "");
      if (!value) return;
      state.plan.destination_name = value.trim(); state.plan.destination_name_policy = "error"; state.plan.destination_name_replace_confirmed = false; break;
    case "name_replace":
      if (!typedDestructiveConfirmation("This stops and removes the existing destination container definition before creating the migrated container. Its mapped files are not deleted unless separately selected.", context.container_name)) return;
      state.plan.destination_name_policy = "replace"; state.plan.destination_name_replace_confirmed = true; break;
    case "port_auto": {
      const port = state.plan.ports[Number(context.port_index)];
      value = context.suggested_port || prompt("Enter an available destination port:", port?.destination_host_port || "");
      if (!value) return;
      port.destination_host_port = String(value); break;
    }
    case "port_change": {
      const port = state.plan.ports[Number(context.port_index)];
      value = prompt("Enter a different destination port:", port?.destination_host_port || context.host_port || "");
      if (!value) return;
      port.destination_host_port = String(value).trim(); break;
    }
    case "port_host_ip_change": {
      const port = state.plan.ports[Number(context.port_index)];
      value = prompt("Enter the destination host IPv4 address, or leave blank for all interfaces:", port?.host_ip || "");
      if (value === null) return;
      port.host_ip = value.trim(); break;
    }
    case "port_host_ip_clear":
      state.plan.ports[Number(context.port_index)].host_ip = ""; break;
    case "network_create":
      state.plan.network.create_if_missing = true; break;
    case "network_bridge":
      state.plan.network.mode = "bridge"; state.plan.network.ipv4_address = ""; state.plan.network.create_if_missing = false; break;
    case "network_change":
      value = prompt("Enter a destination Docker network name:", state.plan.network.mode || "bridge");
      if (!value) return;
      state.plan.network.mode = value.trim(); state.plan.network.create_if_missing = false; break;
    case "ip_auto":
      state.plan.network.ipv4_address = ""; break;
    case "ip_change":
      value = prompt("Enter another destination static IPv4 address:", state.plan.network.ipv4_address || context.ip || "");
      if (!value) return;
      state.plan.network.ipv4_address = value.trim(); break;
    case "device_skip":
      state.plan.devices[Number(context.device_index)].selected = false; break;
    case "device_change":
      value = prompt("Enter a destination device path:", state.plan.devices[Number(context.device_index)]?.source || context.device || "");
      if (!value) return;
      state.plan.devices[Number(context.device_index)].source = value.trim(); break;
    case "image_transfer":
      state.plan.image_mode = "transfer"; state.plan.custom_image = ""; state.plan.existing_image = ""; break;
    case "image_custom":
      value = prompt("Enter one explicit registry image tag or digest:", state.plan.custom_image || state.plan.source_image || "");
      if (!value) return;
      state.plan.image_mode = "pull_custom"; state.plan.custom_image = value.trim(); break;
    case "image_existing_change":
      value = prompt("Enter or select an image already present on the destination:", state.plan.existing_image || context.image || "");
      if (!value) return;
      state.plan.image_mode = "existing"; state.plan.existing_image = value.trim(); break;
    case "edit_storage":
      syncPlanToForm(); setWizardStep(3); return;
    default:
      flash(`Unsupported conflict action: ${action.id}`, "bad"); return;
  }
  syncPlanToForm();
  await rerunPreflight();
}

async function startMigration() {
  if (!state.preflight?.ok || !state.plan) return;
  const source = serverById(state.plan.source_server_id);
  const destination = serverById(state.plan.destination_server_id);
  const message = `Start migration of ${state.plan.container_name} from ${source?.server_name} to ${destination?.server_name}? The source will be stopped for final synchronization.`;
  if (!confirm(message)) return;
  const button = $("startMigration");
  button.disabled = true;
  button.textContent = "Starting…";
  try {
    const response = await api("/api/migrations", { method: "POST", body: JSON.stringify(state.plan) });
    const ref = { source_server_id: response.source_server_id, job_id: response.job.id };
    saveJobRef(ref);
    flash("Migration job started.");
    await openJob(ref.source_server_id, ref.job_id);
  } catch (error) { flash(error.message, "bad"); }
  finally { button.textContent = "Start migration"; button.disabled = !state.preflight?.ok; }
}

async function openJob(sourceServerId, jobId) {
  state.currentJobRef = { source_server_id: sourceServerId, job_id: jobId };
  if (!$("jobDialog").open) $("jobDialog").showModal();
  clearInterval(state.jobTimer);
  await refreshOpenJob();
  state.jobTimer = setInterval(refreshOpenJob, 2000);
}

async function refreshOpenJob() {
  if (!state.currentJobRef) return;
  try {
    const { source_server_id, job_id } = state.currentJobRef;
    const job = await api(`/api/jobs/${source_server_id}/${job_id}`);
    $("jobDialogTitle").textContent = job.plan?.container_name || "Container migration";
    $("jobStatus").textContent = String(job.status || "").replaceAll("_", " ");
    $("jobPhase").textContent = String(job.phase || "").replaceAll("_", " ");
    $("jobPercent").textContent = `${job.progress_percent || 0}%`;
    $("jobProgressBar").style.width = `${job.progress_percent || 0}%`;
    $("jobError").textContent = job.error || "";
    $("jobLogs").textContent = (job.logs || []).map((item) => `${item.time}  ${item.message}`).join("\n");
    $("jobLogs").scrollTop = $("jobLogs").scrollHeight;
    const rollback = job.status === "completed" && job.plan?.keep_source_container;
    $("rollbackButton").classList.toggle("hidden", !rollback);
    if (["completed", "failed", "rolled_back"].includes(job.status)) {
      clearInterval(state.jobTimer);
      state.jobTimer = null;
      await loadJobs(false);
    }
  } catch (error) {
    $("jobError").textContent = error.message;
    clearInterval(state.jobTimer);
  }
}

function closeJob() {
  clearInterval(state.jobTimer);
  state.jobTimer = null;
  state.currentJobRef = null;
  $("jobDialog").close();
}

async function loadSettings() {
  try {
    const payload = await api("/api/settings");
    const settings = payload.settings;
    $("serverName").value = settings.server_name || "";
    $("lanIp").value = settings.lan_ip || "";
    $("webPort").value = settings.web_port || 8210;
    $("rsyncPort").value = settings.rsync_port || 8211;
  } catch (error) { flash(error.message, "bad"); }
}

// Event wiring
$("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("loginError").textContent = "";
  try {
    const payload = await api("/api/login", { method: "POST", body: JSON.stringify({ username: $("loginUsername").value, password: $("loginPassword").value }) });
    state.csrf = payload.csrf;
    showApp();
    await loadEverything();
  } catch (error) { $("loginError").textContent = error.message; }
});

$("logoutButton").onclick = async () => {
  try { await api("/api/logout", { method: "POST", body: "{}" }); } catch {}
  state.csrf = "";
  showLogin();
};
qsa(".nav-link").forEach((button) => button.onclick = () => showView(button.dataset.view));
qsa("[data-go]").forEach((button) => button.onclick = () => showView(button.dataset.go));
$("mobileMenu").onclick = () => document.querySelector(".sidebar").classList.toggle("open");
$("refreshServers").onclick = loadServers;
$("refreshJobs").onclick = () => loadJobs();

$("generatePairCode").onclick = async () => {
  try {
    const payload = await api("/api/pair-code", { method: "POST", body: "{}" });
    $("pairCode").textContent = payload.code;
    $("pairExpiry").textContent = `Expires ${new Date(payload.expires * 1000).toLocaleTimeString()}`;
    $("pairCodeBox").classList.remove("hidden");
  } catch (error) { flash(error.message, "bad"); }
};

$("addPeerForm").onsubmit = async (event) => {
  event.preventDefault();
  try {
    await api("/api/peers", { method: "POST", body: JSON.stringify({ url: $("peerUrl").value, code: $("peerCode").value }) });
    $("addPeerForm").reset();
    flash("Servers paired successfully.");
    await loadServers();
  } catch (error) { flash(error.message, "bad"); }
};

$("settingsForm").onsubmit = async (event) => {
  event.preventDefault();
  try {
    const payload = await api("/api/settings", { method: "POST", body: JSON.stringify({
      server_name: $("serverName").value,
      lan_ip: $("lanIp").value,
      web_port: Number($("webPort").value),
      rsync_port: Number($("rsyncPort").value),
    }) });
    flash(payload.restart_required ? "Settings saved. Recreate the container with matching port values before pairing." : "Settings saved.", payload.restart_required ? "bad" : "good");
    await loadServers();
  } catch (error) { flash(error.message, "bad"); }
};

$("swapServers").onclick = () => {
  const source = $("sourceServer").value;
  $("sourceServer").value = $("destinationServer").value;
  $("destinationServer").value = source;
};
$("directionNext").onclick = async () => {
  if (!$("sourceServer").value || !$("destinationServer").value || $("sourceServer").value === $("destinationServer").value) {
    flash("Choose two different connected servers.", "bad"); return;
  }
  setWizardStep(2);
  try { await loadSourceContainers(); } catch (error) { flash(error.message, "bad"); }
};
$("containerSearch").oninput = renderContainerPicker;
$("containerNext").onclick = analyzeSelectedContainer;
qsa('input[name="imageMode"]').forEach((radio) => radio.addEventListener("change", updateImageModeUI));
$("networkMode").addEventListener("input", updateNetworkInputs);
$("mappingNext").onclick = runPreflight;
$("startMigration").onclick = startMigration;
qsa("[data-back]").forEach((button) => button.onclick = () => {
  const step = Number(button.dataset.back);
  if (step === 3 && state.plan) syncPlanToForm();
  setWizardStep(step);
});
qsa(".wizard-step").forEach((button) => button.onclick = () => {
  const step = Number(button.dataset.step);
  if (step === 1 || (step === 2 && state.containers.length) || (step === 3 && state.analysis) || (step === 4 && state.preflight)) setWizardStep(step);
});

$("closeJobDialog").onclick = closeJob;
$("closeJobDialog2").onclick = closeJob;
$("rollbackButton").onclick = async () => {
  if (!state.currentJobRef || !confirm("Stop the destination container and restart the original source container?")) return;
  try {
    const ref = state.currentJobRef;
    await api(`/api/jobs/${ref.source_server_id}/${ref.job_id}/rollback`, { method: "POST", body: "{}" });
    flash("Rollback completed.");
    await refreshOpenJob();
  } catch (error) { flash(error.message, "bad"); }
};

initialize();
