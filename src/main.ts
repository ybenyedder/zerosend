import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";

interface DeviceInfo {
  id: string;
  name: string;
  platform: string;
  fingerprint: string;
}

interface Peer {
  id: string;
  name: string;
  platform: string;
  fingerprint: string;
  address: string;
  https_port: number;
  last_seen_ms: number;
}

interface Settings {
  device_name: string;
  download_dir: string;
  require_approval: boolean;
  stealth_mode: boolean;
  max_transfer_mb: number;
}

interface TrustedPeer {
  id: string;
  fingerprint: string;
  name: string | null;
  online: boolean;
}

interface FileMeta {
  id: string;
  name: string;
  size: number;
  mime: string;
}

interface IncomingTransferEvent {
  transfer_id: string;
  sender_id: string;
  sender_name: string;
  sender_fingerprint: string;
  files: FileMeta[];
  auto_accepted: boolean;
}

interface TransferProgressEvent {
  transfer_id: string;
  file_id: string;
  direction: "send" | "receive";
  bytes_done: number;
  bytes_total: number;
}

interface TransferDoneEvent {
  transfer_id: string;
  direction: "send" | "receive";
  ok: boolean;
  error: string | null;
}

const PLATFORM_LABEL: Record<string, string> = {
  windows: "Windows",
  macos: "macOS",
  linux: "Linux",
  android: "Android",
  ios: "iOS",
};

const peers = new Map<string, Peer>();
let settings: Settings | null = null;

const peersGrid = document.querySelector<HTMLElement>("#peers-grid")!;
const emptyState = document.querySelector<HTMLElement>("#empty-state")!;
const mapNodes = document.querySelector<HTMLElement>("#map-nodes")!;
const networkEdges = document.querySelector<SVGSVGElement>("#network-edges")!;
const mapCenterName = document.querySelector<HTMLElement>("#map-center-name")!;
const peerNodeTemplate = document.querySelector<HTMLTemplateElement>("#peer-node-template")!;
const incomingTemplate = document.querySelector<HTMLTemplateElement>("#incoming-card-template")!;
const incomingStack = document.querySelector<HTMLElement>("#incoming-stack")!;
const transferTemplate = document.querySelector<HTMLTemplateElement>("#transfer-card-template")!;
const transfersPanel = document.querySelector<HTMLElement>("#transfers-panel")!;
const toastStack = document.querySelector<HTMLElement>("#toast-stack")!;
const dropOverlay = document.querySelector<HTMLElement>("#drop-overlay")!;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  const units = ["Ko", "Mo", "Go", "To"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[i]}`;
}

function shortFingerprint(fp: string): string {
  const parts = fp.split(":");
  return parts.slice(0, 4).join(":");
}

function toast(message: string) {
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = message;
  toastStack.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

/** Launches a small glowing packet from `fromEl` toward the transfers panel. */
function flyPacket(fromEl: HTMLElement) {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const from = fromEl.getBoundingClientRect();
  const to = transfersPanel.getBoundingClientRect();
  const startX = from.left + from.width / 2;
  const startY = from.top + from.height / 2;
  const endX = to.left + Math.min(24, to.width / 2);
  const endY = to.top + 10;
  const midX = (startX + endX) / 2;
  const midY = Math.min(startY, endY) - 80;

  const dot = document.createElement("span");
  dot.className = "packet-fly";
  document.body.appendChild(dot);

  const anim = dot.animate(
    [
      { transform: `translate(${startX}px, ${startY}px) scale(1)`, opacity: 1, offset: 0 },
      { transform: `translate(${midX}px, ${midY}px) scale(0.85)`, opacity: 1, offset: 0.5 },
      { transform: `translate(${endX}px, ${endY}px) scale(0.4)`, opacity: 0, offset: 1 },
    ],
    { duration: 560, easing: "cubic-bezier(.3,.6,.3,1)" }
  );
  anim.onfinish = () => dot.remove();
  anim.oncancel = () => dot.remove();
}

// ---------------- peers (network map) ----------------

const MAP_SIZE = 560; // fallback box size used before the layout is measured
const NODE_HALF = 52; // half a node's width — keeps nodes inside the map box
const SVG_NS = "http://www.w3.org/2000/svg";

let lastPeersSignature: string | null = null;

/** Everything the map actually draws from — so a re-render is skipped (and the
 *  node animations left running) when nothing visible has changed, instead of
 *  tearing the whole map down on every 5 s poll. `last_seen_ms` is deliberately
 *  excluded: it ticks constantly without changing what's shown. */
function peersSignature(list: Peer[]): string {
  return list
    .map((p) => `${p.id} ${p.name} ${p.platform} ${p.address}:${p.https_port}`)
    .join("");
}

function renderPeers(force = false) {
  const list = [...peers.values()].sort((a, b) => a.name.localeCompare(b.name));
  const signature = peersSignature(list);
  if (!force && signature === lastPeersSignature) return;
  lastPeersSignature = signature;

  peersGrid.hidden = list.length === 0;
  emptyState.hidden = list.length > 0;
  mapNodes.innerHTML = "";
  networkEdges.innerHTML = "";

  // Measure the actual box (reading a layout property after unhiding forces the
  // reflow), so nodes stay inside it on narrow/mobile viewports instead of
  // being positioned in a fixed 560px space that overflows a smaller map.
  const width = peersGrid.clientWidth || MAP_SIZE;
  const height = peersGrid.clientHeight || MAP_SIZE;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.max(0, Math.min(width, height) / 2 - (NODE_HALF + 24));
  const count = list.length;

  list.forEach((peer, i) => {
    const angle = (2 * Math.PI * i) / count - Math.PI / 2;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);

    const line = document.createElementNS(SVG_NS, "line");
    line.setAttribute("x1", String(cx));
    line.setAttribute("y1", String(cy));
    line.setAttribute("x2", String(x));
    line.setAttribute("y2", String(y));
    networkEdges.appendChild(line);

    const node = peerNodeTemplate.content.firstElementChild!.cloneNode(true) as HTMLElement;
    node.dataset.peerId = peer.id;
    node.style.left = `${x}px`;
    node.style.top = `${y}px`;
    node.querySelector(".map-node-initial")!.textContent = peer.name.trim().charAt(0).toUpperCase() || "?";
    node.querySelector(".map-node-name")!.textContent = peer.name;
    node.addEventListener("click", () => openDevicePanel(peer.id));
    mapNodes.appendChild(node);
  });
}

async function refreshPeers() {
  try {
    const list = await invoke<Peer[]>("list_peers");
    peers.clear();
    for (const p of list) peers.set(p.id, p);
    renderPeers();
  } catch (e) {
    console.error(e);
  }
}

async function pickAndSend(peerId: string) {
  const selection = await open({ multiple: true, directory: false });
  if (!selection) return;
  const paths = Array.isArray(selection) ? selection : [selection];
  await sendFiles(peerId, paths);
}

async function sendFiles(peerId: string, paths: string[]) {
  const peer = peers.get(peerId);
  try {
    const localId = await invoke<string>("send_files_to_peer", { peerId, paths });
    registerTransfer(
      localId,
      "send",
      `Vers ${peer?.name ?? "appareil"} — ${paths.length} fichier${paths.length > 1 ? "s" : ""}`
    );
    const originEl = mapNodes.querySelector<HTMLElement>(`[data-peer-id="${cssEscape(peerId)}"]`);
    if (originEl) flyPacket(originEl);
  } catch (e) {
    toast(String(e));
  }
}

// ---------------- device detail panel ----------------

const deviceOverlay = document.querySelector<HTMLElement>("#device-overlay")!;
const devicePanelName = document.querySelector<HTMLElement>("#device-panel-name")!;
const devicePanelPlatform = document.querySelector<HTMLElement>("#device-panel-platform")!;
const devicePanelAddress = document.querySelector<HTMLElement>("#device-panel-address")!;
const devicePanelFingerprint = document.querySelector<HTMLElement>("#device-panel-fingerprint")!;

let activeDevicePeerId: string | null = null;

function openDevicePanel(peerId: string) {
  const peer = peers.get(peerId);
  if (!peer) return;
  activeDevicePeerId = peerId;
  devicePanelName.textContent = peer.name;
  devicePanelPlatform.textContent = PLATFORM_LABEL[peer.platform] ?? peer.platform;
  devicePanelAddress.textContent = `${peer.address}:${peer.https_port}`;
  devicePanelFingerprint.textContent = peer.fingerprint;
  deviceOverlay.hidden = false;
}

function closeDevicePanel() {
  deviceOverlay.hidden = true;
  activeDevicePeerId = null;
}

// ---------------- incoming transfers ----------------

const incomingTimers = new Map<string, number>();

function addIncoming(evt: IncomingTransferEvent) {
  const title = `De ${evt.sender_name} — ${evt.files.length} fichier${evt.files.length > 1 ? "s" : ""}`;

  // Already accepted server-side without asking (require_approval off, and the
  // sender is an already-trusted peer): no accept/reject card would have any
  // effect, so just track progress.
  if (evt.auto_accepted) {
    registerTransfer(evt.transfer_id, "receive", title);
    return;
  }

  const node = incomingTemplate.content.firstElementChild!.cloneNode(true) as HTMLElement;
  node.dataset.transferId = evt.transfer_id;
  node.querySelector(".incoming-sender")!.textContent = evt.sender_name;
  node.querySelector(".incoming-fp")!.textContent = shortFingerprint(evt.sender_fingerprint);

  const list = node.querySelector(".incoming-files")!;
  for (const f of evt.files) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = f.name;
    const size = document.createElement("span");
    size.textContent = formatBytes(f.size);
    li.append(name, size);
    list.appendChild(li);
  }

  node.querySelector(".incoming-accept")!.addEventListener("click", () => {
    // Register the progress card only now: before acceptance nothing lands on
    // disk, so a rejected or expired request must not leave a card stuck at
    // "Réception…" (the backend never emits a completion for those).
    registerTransfer(evt.transfer_id, "receive", title);
    respond(evt.transfer_id, true);
  });
  node.querySelector(".incoming-reject")!.addEventListener("click", () => respond(evt.transfer_id, false));

  const bar = node.querySelector<HTMLElement>(".incoming-timer-bar")!;
  bar.style.transition = "transform 120s linear";
  requestAnimationFrame(() => {
    bar.style.transform = "scaleX(0)";
  });

  incomingStack.appendChild(node);

  const timeoutId = window.setTimeout(() => removeIncoming(evt.transfer_id), 120_000);
  incomingTimers.set(evt.transfer_id, timeoutId);
}

function removeIncoming(transferId: string) {
  const node = incomingStack.querySelector<HTMLElement>(`[data-transfer-id="${cssEscape(transferId)}"]`);
  node?.remove();
  const timerId = incomingTimers.get(transferId);
  if (timerId) {
    clearTimeout(timerId);
    incomingTimers.delete(transferId);
  }
}

async function respond(transferId: string, accept: boolean) {
  removeIncoming(transferId);
  try {
    await invoke("respond_to_transfer", { transferId, accept });
  } catch (e) {
    toast(String(e));
  }
}

function cssEscape(s: string): string {
  return s.replace(/[^a-zA-Z0-9_-]/g, "\\$&");
}

// ---------------- transfer progress panel ----------------

interface TransferUI {
  el: HTMLElement;
  bar: HTMLElement;
  status: HTMLElement;
  stamp: HTMLElement;
}

const transfersUI = new Map<string, TransferUI>();

function registerTransfer(transferId: string, direction: "send" | "receive", title: string) {
  if (transfersUI.has(transferId)) return;
  const node = transferTemplate.content.firstElementChild!.cloneNode(true) as HTMLElement;
  node.querySelector(".transfer-title")!.textContent = title;
  const status = node.querySelector<HTMLElement>(".transfer-status")!;
  status.textContent = direction === "send" ? "Envoi…" : "Réception…";
  const bar = node.querySelector<HTMLElement>(".transfer-progress-bar")!;
  const stamp = node.querySelector<HTMLElement>(".transfer-stamp")!;
  transfersPanel.appendChild(node);
  transfersUI.set(transferId, { el: node, bar, status, stamp });
}

function updateProgress(evt: TransferProgressEvent) {
  const ui = transfersUI.get(evt.transfer_id);
  if (!ui || evt.bytes_total === 0) return;
  const pct = Math.min(100, (evt.bytes_done / evt.bytes_total) * 100);
  ui.bar.style.width = `${pct}%`;
  ui.status.textContent = `${formatBytes(evt.bytes_done)} / ${formatBytes(evt.bytes_total)}`;
}

function completeTransfer(evt: TransferDoneEvent) {
  const ui = transfersUI.get(evt.transfer_id);
  if (!ui) return;
  ui.bar.style.width = "100%";
  ui.bar.classList.add(evt.ok ? "done" : "error");
  ui.status.classList.add(evt.ok ? "ok" : "error");
  ui.status.textContent = evt.ok ? "Terminé" : evt.error ?? "Échec";
  ui.stamp.textContent = evt.ok ? "✓" : "✕";
  ui.stamp.classList.add(evt.ok ? "ok" : "error", "show");
  setTimeout(() => {
    ui.el.remove();
    transfersUI.delete(evt.transfer_id);
  }, evt.ok ? 3500 : 6000);
}

// ---------------- drag & drop ----------------

let hoveredPeerEl: HTMLElement | null = null;

function setHoveredPeer(el: HTMLElement | null) {
  if (hoveredPeerEl === el) return;
  hoveredPeerEl?.classList.remove("drop-hover");
  hoveredPeerEl = el;
  hoveredPeerEl?.classList.add("drop-hover");
}

async function setupDragDrop() {
  const webview = getCurrentWebview();
  await webview.onDragDropEvent((event) => {
    const payload = event.payload as { type: string; position?: { x: number; y: number }; paths?: string[] };
    if (payload.type === "over" && payload.position) {
      dropOverlay.hidden = false;
      const cssX = payload.position.x / window.devicePixelRatio;
      const cssY = payload.position.y / window.devicePixelRatio;
      const el = (document.elementFromPoint(cssX, cssY) as HTMLElement | null)?.closest<HTMLElement>(".peer-card") ?? null;
      setHoveredPeer(el);
    } else if (payload.type === "drop") {
      dropOverlay.hidden = true;
      const peerId = hoveredPeerEl?.dataset.peerId;
      setHoveredPeer(null);
      const paths = payload.paths ?? [];
      if (peerId && paths.length > 0) {
        void sendFiles(peerId, paths);
      } else if (paths.length > 0) {
        toast("Déposez les fichiers directement sur un appareil");
      }
    } else {
      dropOverlay.hidden = true;
      setHoveredPeer(null);
    }
  });
}

// ---------------- settings ----------------

const settingsOverlay = document.querySelector<HTMLElement>("#settings-overlay")!;
const settingsForm = document.querySelector<HTMLFormElement>("#settings-form")!;
const settingNameInput = document.querySelector<HTMLInputElement>("#setting-name")!;
const settingDirInput = document.querySelector<HTMLInputElement>("#setting-dir")!;
const settingApprovalInput = document.querySelector<HTMLInputElement>("#setting-approval")!;
const settingStealthInput = document.querySelector<HTMLInputElement>("#setting-stealth")!;
const settingMaxTransferInput = document.querySelector<HTMLInputElement>("#setting-max-transfer")!;
const settingFingerprint = document.querySelector<HTMLElement>("#setting-fingerprint")!;
const stealthBadge = document.querySelector<HTMLElement>("#stealth-badge")!;

function updateStealthBadge() {
  stealthBadge.hidden = !settings?.stealth_mode;
}
const trustedList = document.querySelector<HTMLElement>("#trusted-list")!;
const trustedEmpty = document.querySelector<HTMLElement>("#trusted-empty")!;
const trustedRowTemplate = document.querySelector<HTMLTemplateElement>("#trusted-row-template")!;

async function renderTrustedPeers() {
  let list: TrustedPeer[] = [];
  try {
    list = await invoke<TrustedPeer[]>("list_trusted_peers");
  } catch (e) {
    console.error(e);
  }
  trustedList.innerHTML = "";
  trustedEmpty.hidden = list.length > 0;
  for (const peer of list) {
    const row = trustedRowTemplate.content.firstElementChild!.cloneNode(true) as HTMLElement;
    if (!peer.online) row.classList.add("offline");
    row.querySelector(".trusted-name")!.textContent =
      (peer.name ?? "Appareil inconnu") + (peer.online ? "" : " (hors ligne)");
    row.querySelector(".trusted-fp")!.textContent = shortFingerprint(peer.fingerprint);
    row.querySelector(".trusted-forget")!.addEventListener("click", async () => {
      try {
        await invoke("forget_peer", { peerId: peer.id });
        toast("Appareil oublié — il devra être confirmé à nouveau");
        await renderTrustedPeers();
      } catch (e) {
        toast(String(e));
      }
    });
    trustedList.appendChild(row);
  }
}

async function openSettings() {
  settings = await invoke<Settings>("get_settings");
  settingNameInput.value = settings.device_name;
  settingDirInput.value = settings.download_dir;
  settingApprovalInput.checked = settings.require_approval;
  settingStealthInput.checked = settings.stealth_mode;
  settingMaxTransferInput.value = String(settings.max_transfer_mb);
  const device = await invoke<DeviceInfo>("get_device");
  settingFingerprint.textContent = device.fingerprint;
  await renderTrustedPeers();
  settingsOverlay.hidden = false;
}

function closeSettings() {
  settingsOverlay.hidden = true;
}

async function saveSettings(e: SubmitEvent) {
  e.preventDefault();
  const maxTransferMb = Math.max(0, Math.floor(Number(settingMaxTransferInput.value) || 0));
  try {
    settings = await invoke<Settings>("update_settings", {
      deviceName: settingNameInput.value,
      downloadDir: settingDirInput.value,
      requireApproval: settingApprovalInput.checked,
      stealthMode: settingStealthInput.checked,
      maxTransferMb,
    });
    updateStealthBadge();
    await refreshHeader();
    closeSettings();
    toast("Paramètres enregistrés");
  } catch (e) {
    toast(String(e));
  }
}

// ---------------- header ----------------

const myDeviceName = document.querySelector<HTMLElement>("#my-device-name")!;
const myFingerprint = document.querySelector<HTMLElement>("#my-fingerprint")!;

async function refreshHeader() {
  const device = await invoke<DeviceInfo>("get_device");
  myDeviceName.textContent = device.name;
  myFingerprint.textContent = shortFingerprint(device.fingerprint);
  mapCenterName.textContent = device.name;
}

async function openReceivedFolder() {
  try {
    const s = await invoke<Settings>("get_settings");
    await revealItemInDir(s.download_dir);
  } catch (e) {
    toast(String(e));
  }
}

// ---------------- wiring ----------------

function closeTopOverlay() {
  if (!settingsOverlay.hidden) closeSettings();
  else if (!deviceOverlay.hidden) closeDevicePanel();
}

window.addEventListener("DOMContentLoaded", async () => {
  // Static UI wiring first (no awaits): buttons, keyboard, and window resize.
  document.querySelector("#settings-btn")!.addEventListener("click", () => void openSettings());
  document.querySelector("#my-device-btn")!.addEventListener("click", () => void openSettings());
  document.querySelector("#settings-close")!.addEventListener("click", closeSettings);
  document.querySelector("#settings-backdrop")!.addEventListener("click", closeSettings);
  settingsForm.addEventListener("submit", (e) => void saveSettings(e));

  document.querySelector("#setting-dir-pick")!.addEventListener("click", async () => {
    const dir = await open({ directory: true, multiple: false });
    if (dir && typeof dir === "string") settingDirInput.value = dir;
  });

  document.querySelector("#setting-open-folder")!.addEventListener("click", async () => {
    if (settingDirInput.value) {
      try {
        await revealItemInDir(settingDirInput.value);
      } catch (e) {
        toast(String(e));
      }
    }
  });

  document.querySelector("#open-received-btn")!.addEventListener("click", () => void openReceivedFolder());

  document.querySelector("#device-panel-close")!.addEventListener("click", closeDevicePanel);
  document.querySelector("#device-backdrop")!.addEventListener("click", closeDevicePanel);
  document.querySelector("#device-panel-send")!.addEventListener("click", () => {
    const peerId = activeDevicePeerId;
    if (!peerId) return;
    closeDevicePanel();
    void pickAndSend(peerId);
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeTopOverlay();
  });

  // The map is positioned from the measured box size, so re-lay it out (forced,
  // past the no-change guard) when the window is resized.
  let resizeTimer = 0;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => renderPeers(true), 120);
  });

  // Register backend event listeners BEFORE the initial data fetches below:
  // otherwise an "incoming-transfer" arriving during startup (the server is
  // already accepting connections) would be dropped on the floor.
  await listen("peers-changed", () => {
    void refreshPeers();
  });
  await listen<IncomingTransferEvent>("incoming-transfer", (e) => addIncoming(e.payload));
  await listen<TransferProgressEvent>("transfer-progress", (e) => updateProgress(e.payload));
  await listen<TransferDoneEvent>("transfer-complete", (e) => completeTransfer(e.payload));
  await setupDragDrop();

  await refreshHeader();
  await refreshPeers();
  try {
    settings = await invoke<Settings>("get_settings");
    updateStealthBadge();
  } catch (e) {
    console.error(e);
  }

  setInterval(() => void refreshPeers(), 5000);
});
