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

const reducedMotionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");

function reducedMotion(): boolean {
  return reducedMotionQuery.matches;
}

type ToastKind = "info" | "success" | "error";

function toast(message: string, kind: ToastKind = "info") {
  const el = document.createElement("div");
  el.className = `toast toast-${kind}`;
  const dot = document.createElement("span");
  dot.className = "toast-dot";
  const text = document.createElement("span");
  text.textContent = message;
  el.append(dot, text);
  toastStack.appendChild(el);
  window.setTimeout(() => {
    el.classList.add("toast-out");
    window.setTimeout(() => el.remove(), 350);
  }, 4200);
}

/** Collapses a stacked card (height and padding) while sliding it out, so the
 *  cards around it glide into place instead of snapping when it disappears. */
function collapseAndRemove(el: HTMLElement) {
  if (reducedMotion()) {
    el.remove();
    return;
  }
  el.style.height = `${el.offsetHeight}px`;
  void el.offsetHeight; // commit the fixed height before transitioning to 0
  el.classList.add("collapsing");
  window.setTimeout(() => el.remove(), 360);
}

/** Launches a small glowing packet from `fromEl` toward the transfers panel. */
function flyPacket(fromEl: HTMLElement) {
  if (reducedMotion()) return;

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
const EDGE_TWEEN_MS = 480;

interface MapEntry {
  node: HTMLElement;
  edge: SVGLineElement;
  tween: number; // rAF handle of the running edge tween, 0 when idle
}

const mapEntries = new Map<string, MapEntry>();
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

function easeOutCubic(t: number): number {
  return 1 - Math.pow(1 - t, 3);
}

/** Glides an edge's endpoints to their new coordinates so the constellation
 *  reflows smoothly instead of snapping when a peer joins or leaves. SVG line
 *  geometry can't be CSS-transitioned portably, hence the rAF tween. */
function tweenEdge(entry: MapEntry, x1: number, y1: number, x2: number, y2: number) {
  cancelAnimationFrame(entry.tween);
  const line = entry.edge;
  const set = (a: number, b: number, c: number, d: number) => {
    line.setAttribute("x1", String(a));
    line.setAttribute("y1", String(b));
    line.setAttribute("x2", String(c));
    line.setAttribute("y2", String(d));
  };
  if (reducedMotion()) {
    set(x1, y1, x2, y2);
    return;
  }
  const from = ["x1", "y1", "x2", "y2"].map((attr) => Number(line.getAttribute(attr)));
  const start = performance.now();
  const step = (now: number) => {
    const t = Math.min(1, (now - start) / EDGE_TWEEN_MS);
    const k = easeOutCubic(t);
    set(
      from[0] + (x1 - from[0]) * k,
      from[1] + (y1 - from[1]) * k,
      from[2] + (x2 - from[2]) * k,
      from[3] + (y2 - from[3]) * k
    );
    if (t < 1) entry.tween = requestAnimationFrame(step);
  };
  entry.tween = requestAnimationFrame(step);
}

function renderPeers(force = false) {
  const list = [...peers.values()].sort((a, b) => a.name.localeCompare(b.name));
  const signature = peersSignature(list);
  if (!force && signature === lastPeersSignature) return;
  lastPeersSignature = signature;

  peersGrid.hidden = list.length === 0;
  emptyState.hidden = list.length > 0;

  // Measure the actual box (reading a layout property after unhiding forces the
  // reflow), so nodes stay inside it on narrow/mobile viewports instead of
  // being positioned in a fixed 560px space that overflows a smaller map.
  const width = peersGrid.clientWidth || MAP_SIZE;
  const height = peersGrid.clientHeight || MAP_SIZE;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.max(0, Math.min(width, height) / 2 - (NODE_HALF + 24));
  const count = list.length;

  const present = new Set<string>();
  let arrivals = 0;

  list.forEach((peer, i) => {
    const angle = (2 * Math.PI * i) / count - Math.PI / 2;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);
    present.add(peer.id);

    let entry = mapEntries.get(peer.id);
    if (entry) {
      // Existing node: the CSS transition on left/top (and the edge tween)
      // glides it to its new spot instead of tearing the DOM down.
      entry.node.style.left = `${x}px`;
      entry.node.style.top = `${y}px`;
      tweenEdge(entry, cx, cy, x, y);
    } else {
      const delay = Math.min(arrivals, 6) * 70;
      arrivals++;

      const edge = document.createElementNS(SVG_NS, "line");
      edge.setAttribute("pathLength", "1"); // lets CSS draw it in via dash offset
      edge.setAttribute("x1", String(cx));
      edge.setAttribute("y1", String(cy));
      edge.setAttribute("x2", String(x));
      edge.setAttribute("y2", String(y));
      edge.classList.add("drawing");
      edge.style.animationDelay = `${delay}ms`;
      // Timeout rather than animationend: the event can be lost if the map is
      // hidden mid-animation, which would leave the class (and its delay) on.
      window.setTimeout(() => {
        edge.classList.remove("drawing");
        edge.style.animationDelay = "";
      }, delay + 700);
      networkEdges.appendChild(edge);

      const node = peerNodeTemplate.content.firstElementChild!.cloneNode(true) as HTMLElement;
      node.dataset.peerId = peer.id;
      node.style.left = `${x}px`;
      node.style.top = `${y}px`;
      node.classList.add("entering");
      node.style.animationDelay = `${delay}ms`;
      window.setTimeout(() => {
        node.classList.remove("entering");
        node.style.animationDelay = "";
      }, delay + 700);
      node.addEventListener("click", () => openDevicePanel(peer.id));
      mapNodes.appendChild(node);

      entry = { node, edge, tween: 0 };
      mapEntries.set(peer.id, entry);
    }

    entry.node.querySelector(".map-node-initial")!.textContent = peer.name.trim().charAt(0).toUpperCase() || "?";
    entry.node.querySelector(".map-node-name")!.textContent = peer.name;
  });

  for (const [id, entry] of mapEntries) {
    if (present.has(id)) continue;
    mapEntries.delete(id);
    cancelAnimationFrame(entry.tween);
    if (peersGrid.hidden || reducedMotion()) {
      entry.node.remove();
      entry.edge.remove();
    } else {
      entry.node.classList.add("leaving");
      entry.edge.classList.add("fading");
      window.setTimeout(() => {
        entry.node.remove();
        entry.edge.remove();
      }, 360);
    }
  }
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
    if (originEl) {
      flyPacket(originEl);
      originEl.classList.add("sending");
      window.setTimeout(() => originEl.classList.remove("sending"), 700);
    }
  } catch (e) {
    toast(String(e), "error");
  }
}

// ---------------- side panels (settings + device) ----------------

function showOverlay(overlay: HTMLElement) {
  overlay.classList.remove("closing");
  overlay.hidden = false;
  overlay.querySelector<HTMLElement>(".settings-panel")?.focus();
}

function hideOverlay(overlay: HTMLElement) {
  if (overlay.hidden || overlay.classList.contains("closing")) return;
  if (reducedMotion()) {
    overlay.hidden = true;
    return;
  }
  overlay.classList.add("closing");
  window.setTimeout(() => {
    if (!overlay.classList.contains("closing")) return; // reopened meanwhile
    overlay.hidden = true;
    overlay.classList.remove("closing");
  }, 240);
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
  showOverlay(deviceOverlay);
}

function closeDevicePanel() {
  hideOverlay(deviceOverlay);
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
  bar.classList.add("running");
  requestAnimationFrame(() => {
    bar.style.transform = "scaleX(0)";
  });

  incomingStack.appendChild(node);

  const timeoutId = window.setTimeout(() => removeIncoming(evt.transfer_id), 120_000);
  incomingTimers.set(evt.transfer_id, timeoutId);
}

function removeIncoming(transferId: string) {
  const node = incomingStack.querySelector<HTMLElement>(`[data-transfer-id="${cssEscape(transferId)}"]`);
  if (node) {
    node.removeAttribute("data-transfer-id"); // a collapsing card must not be found again
    collapseAndRemove(node);
  }
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
    toast(String(e), "error");
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
    collapseAndRemove(ui.el);
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

let dropHideTimer = 0;

function showDropOverlay() {
  window.clearTimeout(dropHideTimer);
  dropOverlay.classList.remove("out");
  dropOverlay.hidden = false;
}

function hideDropOverlay() {
  if (dropOverlay.hidden) return;
  if (reducedMotion()) {
    dropOverlay.hidden = true;
    return;
  }
  dropOverlay.classList.add("out");
  window.clearTimeout(dropHideTimer);
  dropHideTimer = window.setTimeout(() => {
    dropOverlay.hidden = true;
    dropOverlay.classList.remove("out");
  }, 200);
}

async function setupDragDrop() {
  const webview = getCurrentWebview();
  await webview.onDragDropEvent((event) => {
    const payload = event.payload as { type: string; position?: { x: number; y: number }; paths?: string[] };
    if (payload.type === "over" && payload.position) {
      showDropOverlay();
      const cssX = payload.position.x / window.devicePixelRatio;
      const cssY = payload.position.y / window.devicePixelRatio;
      const el = (document.elementFromPoint(cssX, cssY) as HTMLElement | null)?.closest<HTMLElement>(".peer-card") ?? null;
      setHoveredPeer(el);
    } else if (payload.type === "drop") {
      hideDropOverlay();
      const peerId = hoveredPeerEl?.dataset.peerId;
      setHoveredPeer(null);
      const paths = payload.paths ?? [];
      if (peerId && paths.length > 0) {
        void sendFiles(peerId, paths);
      } else if (paths.length > 0) {
        toast("Déposez les fichiers directement sur un appareil");
      }
    } else {
      hideDropOverlay();
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
        toast("Appareil oublié — il devra être confirmé à nouveau", "success");
        await renderTrustedPeers();
      } catch (e) {
        toast(String(e), "error");
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
  showOverlay(settingsOverlay);
}

function closeSettings() {
  hideOverlay(settingsOverlay);
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
    toast("Paramètres enregistrés", "success");
  } catch (e) {
    toast(String(e), "error");
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
    toast(String(e), "error");
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
        toast(String(e), "error");
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
