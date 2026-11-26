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
		const r = await fetch("/api/history", { headers: { "X-UUID": uuid } });
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

// A job is one file: state "queued" → "uploading" → "done" | "failed" | "cancelled".
const pending = (job) => job.state === "queued" || job.state === "uploading";

function addFiles(files) {
	const list = [...files].filter((f) => f instanceof File);
	if (!list.length) return;
	const batch = list.length > 1 ? batchItem(list.length) : null;
	for (const file of list) {
		const job = { file, state: "queued", xhr: null, batch };
		job.item = progressItem(file, () => cancel(job));
		(batch ? batch.list : $("#progress"))[batch ? "append" : "prepend"](job.item.li);
		batch?.jobs.push(job);
		if (file.size > cfg.maxBytes) {
			setState(job, "failed");
			job.item.fail(`zu groß (max. ${fmtSize(cfg.maxBytes)})`);
			continue;
		}
		queue.push(job);
	}
	batch?.update();
	pump();
}

function setState(job, state) {
	job.state = state;
	if (!pending(job)) job.item.settle();
	job.batch?.update();
}

function cancel(job) {
	if (job.state === "queued") {
		queue.splice(queue.indexOf(job), 1);
		setState(job, "cancelled");
		job.item.cancelled();
	} else if (job.state === "uploading") {
		job.xhr.abort(); // onabort finishes the job
	}
}

function pump() {
	while (active < MAX_PARALLEL && queue.length) {
		const job = queue.shift();
		active++;
		upload(job).finally(() => { active--; pump(); });
	}
}

function batchItem(total) {
	const summary = el("span", { class: "status" });
	const cancelAll = el("button", {
		type: "button", class: "btn btn-ghost btn-sm btn-danger",
		onclick: () => {
			// queued ones first, so aborting a running upload cannot start them
			const jobs = [...b.jobs].sort((x, y) => (y.state === "queued") - (x.state === "queued"));
			jobs.forEach(cancel);
		},
	}, "Alle abbrechen");
	const list = el("ul", { class: "progress-list" });
	const li = el("li", { class: "pbatch" },
		el("div", { class: "row" }, el("span", { class: "name" }, `${total} Dateien`), summary, cancelAll),
		list,
	);
	$("#progress").prepend(li);
	const b = {
		jobs: [], list,
		update() {
			const n = (st) => b.jobs.filter((j) => j.state === st).length;
			const parts = [`${n("done")}/${total} fertig`];
			if (n("failed")) parts.push(`${n("failed")} fehlgeschlagen`);
			if (n("cancelled")) parts.push(`${n("cancelled")} abgebrochen`);
			summary.textContent = parts.join(" · ");
			cancelAll.hidden = !b.jobs.some(pending);
		},
	};
	return b;
}

function progressItem(file, onCancel) {
	const bar = el("div");
	const status = el("span", { class: "status" }, "wartet…");
	const cancelBtn = el("button", {
		type: "button", class: "btn btn-ghost btn-sm btn-icon", title: "Abbrechen", "aria-label": `${file.name} abbrechen`, onclick: onCancel,
	}, "✕");
	const li = el("li", { class: "pitem" },
		el("div", { class: "row" }, el("span", { class: "name", title: file.name }, file.name), status, cancelBtn),
		el("div", { class: "bar" }, bar),
	);
	return {
		li,
		settle() { cancelBtn.remove(); },
		progress(p) { bar.style.width = `${p}%`; status.textContent = `${p} %`; },
		fail(msg) { li.classList.add("err"); status.textContent = msg; },
		cancelled() { li.classList.add("cancelled"); status.textContent = "abgebrochen"; },
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

function upload(job) {
	const { file, item } = job;
	return new Promise((resolve) => {
		const fd = new FormData();
		fd.append("uuid", uuid);
		fd.append("file-upload", file);
		const xhr = new XMLHttpRequest();
		job.xhr = xhr;
		xhr.open("POST", "/api/upload");
		xhr.responseType = "json";
		xhr.upload.onprogress = (e) => { if (e.lengthComputable) item.progress(Math.round((e.loaded / e.total) * 100)); };
		xhr.onload = () => {
			const res = xhr.response || {};
			if (xhr.status === 200 && res.success != null) {
				setState(job, "done");
				item.done(res.url);
				$("#empty")?.remove();
				tbody.prepend(fileRow({ id: res.success, filename: res.filename, url: res.url, time: Date.now() / 1000, size: file.size }, true));
			} else {
				setState(job, "failed");
				item.fail(res.error || `Fehler (HTTP ${xhr.status})`);
			}
			resolve();
		};
		xhr.onerror = () => { setState(job, "failed"); item.fail("Netzwerkfehler"); resolve(); };
		xhr.onabort = () => { setState(job, "cancelled"); item.cancelled(); resolve(); };
		setState(job, "uploading");
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

// Clipboard → File[]: real files/images first; otherwise plain text becomes a .txt file.
const MIME_EXT = { "text/plain": "txt", "image/jpeg": "jpg", "image/svg+xml": "svg", "text/html": "html" };
let pasteSeq = 0;
function pastedFile(blob, type = blob.type) {
	if (blob.name && blob.name !== "image.png") return blob;
	const ext = MIME_EXT[type] || (type.split("/")[1] || "bin").split("+")[0].replace(/\W/g, "") || "bin";
	const stamp = new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
	return new File([blob], `paste-${stamp}-${++pasteSeq}.${ext}`, { type });
}
const textFile = (text) => text && text.trim() ? pastedFile(new Blob([text], { type: "text/plain" })) : null;

// ---------- lightbox ----------
// Modal <dialog>: focus trap, Esc to close and focus return come from the browser.

const lightbox = {
	dlg: $("#lightbox"),
	stage: $("#lightbox-stage"),
	img: $("#lightbox-img"),
	zoomBtn: $("#lightbox-zoom"),
};

function openLightbox(src, name, info) {
	const { dlg, stage, img } = lightbox;
	stage.classList.remove("actual");
	img.alt = name;
	img.src = src;
	$("#lightbox-name").textContent = name;
	$("#lightbox-info").textContent = info;
	dlg.showModal();
	$("#lightbox-close").focus();
	if (img.complete) updateZoomable(); else img.onload = updateZoomable;
}

// "Original size" only makes sense when fitting actually shrank the image.
function updateZoomable() {
	const { stage, img, zoomBtn } = lightbox;
	if (!lightbox.dlg.open || stage.classList.contains("actual")) return;
	const zoomable = img.naturalWidth > img.clientWidth + 1 || img.naturalHeight > img.clientHeight + 1;
	img.classList.toggle("zoomable", zoomable);
	zoomBtn.hidden = !zoomable;
	zoomBtn.textContent = "Originalgröße";
	zoomBtn.setAttribute("aria-pressed", "false");
}

function toggleActualSize() {
	const { stage, img, zoomBtn } = lightbox;
	const actual = stage.classList.toggle("actual");
	zoomBtn.textContent = actual ? "An Fenster anpassen" : "Originalgröße";
	zoomBtn.setAttribute("aria-pressed", String(actual));
	if (actual) {
		// start centred on the image
		stage.scrollLeft = (stage.scrollWidth - stage.clientWidth) / 2;
		stage.scrollTop = (stage.scrollHeight - stage.clientHeight) / 2;
	}
}

lightbox.stage.addEventListener("click", (e) => {
	// clicking the image toggles zoom when there is something to zoom; clicking around it closes
	if (e.target === lightbox.img && (lightbox.img.classList.contains("zoomable") || lightbox.stage.classList.contains("actual"))) toggleActualSize();
	else lightbox.dlg.close();
});
lightbox.zoomBtn.addEventListener("click", toggleActualSize);
$("#lightbox-close").addEventListener("click", () => lightbox.dlg.close());
lightbox.dlg.addEventListener("close", () => { lightbox.img.removeAttribute("src"); });
window.addEventListener("resize", updateZoomable);

// ---------- paste preview ----------
// Pasted images are staged in a preview panel and only uploaded once confirmed,
// so a stray Ctrl+V (e.g. a screenshot with sensitive content) never goes out unseen.

const isImage = (f) => f.type.startsWith("image/");
const preview = {
	box: $("#paste-preview"),
	list: $("#paste-preview-list"),
	summary: $("#paste-preview-summary"),
	confirmBtn: $("#paste-confirm"),
	items: [], // { file, url, li }
	returnFocus: null,
};

function stagePaste(files) {
	if (!files.some(isImage)) { addFiles(files); return; }
	if (preview.box.hidden) preview.returnFocus = document.activeElement;
	for (const file of files) {
		const url = isImage(file) ? URL.createObjectURL(file) : null;
		const info = el("span", { class: "info" }, fmtSize(file.size));
		const thumb = url
			? el("button", {
				type: "button", class: "thumb", title: "Vergrößern", "aria-label": `${file.name} vergrößern`,
				onclick: () => openLightbox(url, file.name, info.textContent),
			})
			: el("div", { class: "thumb" });
		const tooBig = file.size > cfg.maxBytes;
		const broken = (msg) => { thumb.classList.add("broken"); thumb.disabled = true; thumb.replaceChildren(msg); };
		if (url) {
			thumb.append(el("img", {
				src: url, alt: `Vorschau: ${file.name}`, decoding: "async",
				onload: (e) => { info.textContent = `${e.target.naturalWidth} × ${e.target.naturalHeight} px · ${info.textContent}`; },
				onerror: () => broken("Keine Vorschau verfügbar"),
			}));
		} else broken("Keine Vorschau verfügbar");
		if (tooBig) info.textContent += ` – zu groß (max. ${fmtSize(cfg.maxBytes)})`;
		const entry = { file, url, li: null };
		entry.li = el("li", { class: tooBig ? "too-big" : "" },
			thumb,
			el("div", { class: "meta" },
				el("span", { class: "name", title: file.name }, file.name),
				info,
				el("button", {
					type: "button", class: "btn btn-ghost btn-sm btn-icon", title: "Entfernen", "aria-label": `${file.name} entfernen`,
					onclick: () => unstage(entry),
				}, "✕"),
			),
		);
		preview.items.push(entry);
		preview.list.append(entry.li);
	}
	renderPreview();
	preview.box.hidden = false;
	// bring the buttons (bottom of the panel) into view; the image itself may be taller than the viewport
	preview.confirmBtn.scrollIntoView({ block: "nearest", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
	preview.confirmBtn.focus({ preventScroll: true });
}

function renderPreview() {
	const n = preview.items.length;
	const total = preview.items.reduce((s, i) => s + i.file.size, 0);
	preview.list.classList.toggle("multi", n > 1);
	preview.summary.textContent = `${n} ${n === 1 ? "Datei" : "Dateien"} · ${fmtSize(total)}`;
	preview.confirmBtn.textContent = n === 1 ? "Hochladen" : `${n} Dateien hochladen`;
}

function unstage(entry) {
	const idx = preview.items.indexOf(entry);
	if (entry.url) URL.revokeObjectURL(entry.url);
	entry.li.remove();
	preview.items.splice(idx, 1);
	if (!preview.items.length) { closePreview(); return; }
	renderPreview();
	// keep keyboard focus inside the panel
	(preview.items[Math.min(idx, preview.items.length - 1)].li.querySelector("button") || preview.confirmBtn).focus();
}

function closePreview() {
	for (const i of preview.items) if (i.url) URL.revokeObjectURL(i.url);
	preview.items = [];
	preview.list.replaceChildren();
	preview.box.hidden = true;
	const back = preview.returnFocus;
	preview.returnFocus = null;
	if (back?.isConnected && back !== document.body) back.focus({ preventScroll: true });
}

preview.confirmBtn.addEventListener("click", () => {
	const files = preview.items.map((i) => i.file);
	closePreview(); // revoking the preview URLs doesn't affect the File objects
	addFiles(files);
});
$("#paste-discard").addEventListener("click", () => { closePreview(); toast("Einfügen verworfen"); });
window.addEventListener("keydown", (e) => {
	// Esc inside the lightbox only closes the lightbox (native <dialog> behaviour), not the paste preview.
	if (preview.box.hidden || lightbox.dlg.open || e.isComposing) return;
	if (e.key === "Escape") { e.preventDefault(); closePreview(); toast("Einfügen verworfen"); }
	// Enter on a focused button already clicks it; handle it only when nothing specific has focus.
	else if (e.key === "Enter" && (e.target === document.body || e.target === preview.box)) { e.preventDefault(); preview.confirmBtn.click(); }
});

window.addEventListener("paste", (e) => {
	if (e.target.closest?.("input, textarea, [contenteditable]")) return;
	const dt = e.clipboardData;
	if (!dt) return;
	let files = [...dt.items].filter((i) => i.kind === "file").map((i) => i.getAsFile()).filter(Boolean).map((f) => pastedFile(f));
	if (!files.length) {
		// Text-only paste: ask first, so a stray Ctrl+V doesn't upload e.g. a password.
		const text = textFile(dt.getData("text/plain"));
		if (!text) return;
		e.preventDefault();
		if (confirm(`Text aus der Zwischenablage (${fmtSize(text.size)}) als Datei hochladen?`)) addFiles([text]);
		return;
	}
	e.preventDefault();
	stagePaste(files);
});

const pasteBtn = $("#paste-btn");
if (navigator.clipboard?.read || navigator.clipboard?.readText) {
	pasteBtn.hidden = false;
	pasteBtn.addEventListener("click", async () => {
		const files = [];
		try {
			if (navigator.clipboard.read) {
				for (const item of await navigator.clipboard.read()) {
					const type = item.types.find((t) => !t.startsWith("text/")) || (item.types.includes("text/plain") && "text/plain");
					if (!type) continue;
					const blob = await item.getType(type);
					files.push(type === "text/plain" ? textFile(await blob.text()) : pastedFile(blob, type));
				}
			} else {
				files.push(textFile(await navigator.clipboard.readText()));
			}
		} catch (err) {
			// Chrome throws DataError for an empty clipboard or unreadable content (e.g. files copied in a file manager).
			toast(err?.name === "NotAllowedError" ? "Zugriff auf Zwischenablage verweigert"
				: err?.name === "DataError" ? "Zwischenablage ist leer – kopierte Dateien bitte mit Strg+V einfügen"
				: "Zwischenablage konnte nicht gelesen werden");
			return;
		}
		const list = files.filter(Boolean);
		if (list.length) stagePaste(list); else toast("Zwischenablage ist leer");
	});
}

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
