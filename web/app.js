"use strict";

const $ = (sel) => document.querySelector(sel);
const UUID_RE = /^[A-Za-z0-9-]{8,64}$/;

function newUUID() {
	if (crypto.randomUUID) return crypto.randomUUID();
	// fallback for non-secure contexts (plain http)
	const b = crypto.getRandomValues(new Uint8Array(16));
	b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
	const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
	return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function store(key, val) {
	try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch { return null; }
}

let uuid = store("uuid");
if (!uuid || !UUID_RE.test(uuid)) { uuid = newUUID(); store("uuid", uuid); }

let cfg = { maxBytes: 100 << 20, retentionDays: 7, baseUrl: location.origin, admin: false };

// ---------- utils ----------

function el(tag, props = {}, ...children) {
	const e = document.createElement(tag);
	for (const [k, v] of Object.entries(props)) {
		if (k === "class") e.className = v;
		else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
		else if (k in e) e[k] = v;
		else e.setAttribute(k, v);
	}
	for (const c of children) if (c != null) e.append(c);
	return e;
}

function fmtSize(n) {
	if (!n) return "–";
	const u = ["B", "KB", "MB", "GB"];
	let i = 0;
	while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
	return `${n.toFixed(i && n < 10 ? 1 : 0)} ${u[i]}`;
}

const dateFmt = new Intl.DateTimeFormat("de-DE", { dateStyle: "medium", timeStyle: "short" });
const fmtDate = (unix) => dateFmt.format(new Date(unix * 1000));

let toastTimer;
function toast(msg) {
	const t = $("#toast");
	t.textContent = msg;
	t.classList.add("show");
	clearTimeout(toastTimer);
	toastTimer = setTimeout(() => t.classList.remove("show"), 1800);
}

async function copy(text) {
	try { await navigator.clipboard.writeText(text); toast("In die Zwischenablage kopiert"); }
	catch { prompt("Kopieren:", text); }
}

// ---------- history ----------

const tbody = $("#history-body");

function emptyRow() {
	return el("tr", { id: "empty" }, el("td", { colSpan: 4, class: "muted" }, el("em", {}, "Noch nichts hochgeladen")));
}

function fileRow(f, fresh = false) {
	const link = el("a", { href: f.url, target: "_blank", rel: "noopener", title: fmtDate(f.time) }, f.filename);
	const actions = el("span", { class: "actions" },
		el("button", { type: "button", class: "btn btn-ghost btn-sm", onclick: () => copy(f.url) }, "Link kopieren"),
		el("button", { type: "button", class: "btn btn-ghost btn-sm btn-danger", onclick: (e) => deleteFile(f, row, e.currentTarget) }, "Löschen"),
	);
	const row = el("tr", { class: fresh ? "fresh" : "" },
		el("td", { class: "fname" }, link),
		el("td", { class: "hide-sm muted" }, fmtDate(f.time)),
		el("td", { class: "hide-sm num muted" }, fmtSize(f.size)),
		el("td", { class: "num" }, actions),
	);
	return row;
}

async function loadHistory() {
	try {
		const r = await fetch(`/api/history?uuid=${encodeURIComponent(uuid)}`);
		const data = await r.json();
		if (!r.ok) throw new Error(data.error);
		tbody.replaceChildren(...(data.files.length ? data.files.map((f) => fileRow(f)) : [emptyRow()]));
	} catch (e) {
		tbody.replaceChildren(el("tr", {}, el("td", { colSpan: 4, class: "muted" }, el("em", {}, `Fehler beim Laden: ${e.message}`))));
	}
}

async function deleteFile(f, row, btn) {
	if (!confirm(`„${f.filename}“ wirklich löschen?`)) return;
	btn.disabled = true;
	try {
		const r = await fetch("/api/delete", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ id: f.id, uuid }),
		});
		const data = await r.json();
		if (!r.ok) throw new Error(data.error);
		row.querySelector(".fname a").classList.add("gone");
		row.lastChild.replaceChildren(el("span", { class: "muted" }, "✓ Gelöscht"));
	} catch (e) {
		btn.disabled = false;
		toast(`Fehler beim Löschen: ${e.message}`);
	}
}

// ---------- upload ----------

const queue = [];
let active = 0;
const MAX_PARALLEL = 3;

function addFiles(files) {
	for (const file of files) {
		if (!(file instanceof File)) continue;
		const item = progressItem(file);
		if (file.size > cfg.maxBytes) {
			item.fail(`zu groß (max. ${fmtSize(cfg.maxBytes)})`);
			continue;
		}
		queue.push({ file, item });
	}
	pump();
}

function pump() {
	while (active < MAX_PARALLEL && queue.length) {
		const job = queue.shift();
		active++;
		upload(job).finally(() => { active--; pump(); });
	}
}

function progressItem(file) {
	const bar = el("div");
	const status = el("span", { class: "status" }, "wartet…");
	const li = el("li", { class: "pitem" },
		el("div", { class: "row" }, el("span", { class: "name", title: file.name }, file.name), status),
		el("div", { class: "bar" }, bar),
	);
	$("#progress").prepend(li);
	return {
		progress(p) { bar.style.width = `${p}%`; status.textContent = `${p} %`; },
		fail(msg) { li.classList.add("err"); status.textContent = msg; },
		done(url) {
			li.classList.add("ok");
			bar.style.width = "100%";
			status.textContent = fmtSize(file.size);
			const input = el("input", { type: "text", readOnly: true, value: url, onfocus: (e) => e.target.select() });
			li.append(el("div", { class: "link" },
				input,
				el("button", { type: "button", class: "btn btn-sm", onclick: () => copy(url) }, "Kopieren"),
				el("a", { class: "btn btn-sm", href: url, target: "_blank", rel: "noopener" }, "Öffnen"),
			));
		},
	};
}

function upload({ file, item }) {
	return new Promise((resolve) => {
		const fd = new FormData();
		fd.append("uuid", uuid);
		fd.append("file-upload", file);
		const xhr = new XMLHttpRequest();
		xhr.open("POST", "/api/upload");
		xhr.responseType = "json";
		xhr.upload.onprogress = (e) => { if (e.lengthComputable) item.progress(Math.round((e.loaded / e.total) * 100)); };
		xhr.onload = () => {
			const res = xhr.response || {};
			if (xhr.status === 200 && res.success != null) {
				item.done(res.url);
				$("#empty")?.remove();
				tbody.prepend(fileRow({ id: res.success, filename: res.filename, url: res.url, time: Date.now() / 1000, size: file.size }, true));
			} else {
				item.fail(res.error || `Fehler (HTTP ${xhr.status})`);
			}
			resolve();
		};
		xhr.onerror = () => { item.fail("Netzwerkfehler"); resolve(); };
		item.progress(0);
		xhr.send(fd);
	});
}

// ---------- wiring ----------

$("#file-input").addEventListener("change", (e) => { addFiles(e.target.files); e.target.value = ""; });

let dragDepth = 0;
const overlay = $("#drop-overlay");
const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes("Files");
window.addEventListener("dragenter", (e) => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth++; overlay.hidden = false; });
window.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
window.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; overlay.hidden = true; } });
window.addEventListener("drop", (e) => {
	if (!hasFiles(e)) return;
	e.preventDefault();
	dragDepth = 0; overlay.hidden = true;
	addFiles(e.dataTransfer.files);
	$("#upload").scrollIntoView();
});

window.addEventListener("paste", (e) => {
	if (e.target.closest?.("input, textarea")) return;
	const files = [...(e.clipboardData?.items || [])]
		.filter((i) => i.kind === "file").map((i) => i.getAsFile()).filter(Boolean)
		.map((f) => (f.name && f.name !== "image.png") ? f : new File([f], `paste-${Date.now()}.${(f.type.split("/")[1] || "bin").replace(/\W/g, "")}`, { type: f.type }));
	if (files.length) { e.preventDefault(); addFiles(files); }
});

$("#refresh").addEventListener("click", loadHistory);
$("#copy-uuid").addEventListener("click", () => copy(uuid));
$("#set-uuid").addEventListener("click", () => {
	const v = prompt("UUID eines anderen Geräts eingeben, um dessen Dateien zu sehen:", uuid)?.trim();
	if (!v || v === uuid) return;
	if (!UUID_RE.test(v)) { toast("Ungültige UUID"); return; }
	uuid = v; store("uuid", uuid); renderUUID(); loadHistory();
});

function sharexConfig() {
	return JSON.stringify({
		Version: "15.0.0",
		Name: `ul3 (${new URL(cfg.baseUrl).host})`,
		DestinationType: "ImageUploader, TextUploader, FileUploader",
		RequestMethod: "POST",
		RequestURL: `${cfg.baseUrl}/api/upload`,
		Body: "MultipartFormData",
		Arguments: { uuid },
		FileFormName: "file-upload",
		URL: "{json:url}",
		ErrorMessage: "{json:error}",
	}, null, 2);
}

function renderUUID() {
	$("#uuid").textContent = uuid;
	$("#sharex-config").textContent = sharexConfig();
}

$("#sharex-download").addEventListener("click", () => {
	const blob = new Blob([sharexConfig()], { type: "application/json" });
	const a = el("a", { href: URL.createObjectURL(blob), download: `ul3-${new URL(cfg.baseUrl).host}.sxcu` });
	document.body.append(a); a.click(); a.remove();
	setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

async function init() {
	try {
		const r = await fetch("/api/config");
		if (r.ok) cfg = await r.json();
	} catch { /* keep defaults */ }
	$("#maxsize").textContent = fmtSize(cfg.maxBytes);
	$("#retention").textContent = `${cfg.retentionDays} ${cfg.retentionDays === 1 ? "Tag" : "Tage"}`;
	$("#admin-link").hidden = !cfg.admin;
	renderUUID();
	loadHistory();
}
init();
