"use strict";

const $ = (s) => document.querySelector(s);

function el(tag, props = {}, ...children) {
	const e = document.createElement(tag);
	for (const [k, v] of Object.entries(props)) {
		if (k === "class") e.className = v;
		else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
		else e[k] = v;
	}
	for (const c of children) if (c != null) e.append(c);
	return e;
}

const fmtSize = (n) => {
	if (!n) return "–";
	const u = ["B", "KB", "MB", "GB"]; let i = 0;
	while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
	return `${n.toFixed(i && n < 10 ? 1 : 0)} ${u[i]}`;
};
const dateFmt = new Intl.DateTimeFormat("de-DE", { dateStyle: "short", timeStyle: "medium" });
const fmtDate = (t) => dateFmt.format(new Date(t * 1000));

let toastTimer;
function toast(msg) {
	const t = $("#toast"); t.textContent = msg; t.classList.add("show");
	clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
}

async function api(path, body) {
	const r = await fetch(path, {
		method: body ? "POST" : "GET",
		headers: body ? { "Content-Type": "application/json" } : {},
		body: body ? JSON.stringify(body) : undefined,
	});
	const data = await r.json().catch(() => ({}));
	if (r.status === 401 && path !== "/api/admin/login") { showLogin(); throw new Error(data.error || "Nicht angemeldet"); }
	if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
	return data;
}

function cronText(c) {
	if (!c) return "noch nie";
	return `${fmtDate(c.time)}, ${c.numDeleted} gelöscht, ${c.errors} Fehler`;
}

async function load() {
	const data = await api("/api/admin/uploads");
	$("#login-card").hidden = true;
	$("#panel").hidden = false;
	const active = data.files.filter((f) => !f.deleted);
	const total = active.reduce((s, f) => s + f.size, 0);
	$("#stats").replaceChildren(
		el("span", {}, "Aktiv: ", el("strong", {}, String(active.length))),
		el("span", {}, "Gesamt: ", el("strong", {}, String(data.files.length))),
		el("span", {}, "Belegt: ", el("strong", {}, fmtSize(total))),
		el("span", {}, "Letztes Aufräumen: ", el("strong", {}, cronText(data.cron))),
	);
	$("#rows").replaceChildren(...data.files.map((f) => {
		const row = el("tr", { class: f.deleted ? "deleted" : "" },
			el("td", { class: "mono" }, String(f.id)),
			el("td", { class: "fname" }, f.deleted ? f.filename : el("a", { href: f.url, target: "_blank", rel: "noopener" }, f.filename)),
			el("td", { class: "hide-sm mono" }, f.owner || "–"),
			el("td", { class: "hide-sm" }, fmtDate(f.time)),
			el("td", { class: "num" }, f.deleted ? "gelöscht" : fmtSize(f.size)),
			el("td", { class: "hide-sm mono" }, f.crc32.toString(16).padStart(8, "0")),
			el("td", { class: "num" }, f.deleted ? "" : el("span", { class: "actions" },
				f.inline ? downloadLink(f.url, f.filename) : "",
				el("button", {
					type: "button", class: "btn btn-ghost btn-sm btn-danger",
					onclick: async (e) => {
						if (!confirm(`${f.filename} löschen?`)) return;
						e.currentTarget.disabled = true;
						try { await api("/api/admin/delete", { id: f.id }); load(); }
						catch (err) { toast(err.message); }
					},
				}, "Löschen"))),
		);
		return row;
	}));
}

function showLogin() {
	$("#panel").hidden = true; $("#login-card").hidden = false;
}

async function logout() {
	try { await api("/api/admin/logout", {}); } catch {}
	showLogin();
}

$("#login").addEventListener("submit", async (e) => {
	e.preventDefault();
	$("#login-msg").textContent = "Prüfe…";
	try {
		await api("/api/admin/login", { password: $("#pw").value });
		$("#pw").value = "";
		await load();
		$("#login-msg").textContent = "";
	}
	catch (err) { $("#login-msg").textContent = err.message; }
});
$("#logout").addEventListener("click", logout);
$("#cleanup").addEventListener("click", async () => {
	try { const c = await api("/api/admin/cleanup", {}); toast(`Aufgeräumt: ${c.numDeleted} gelöscht, ${c.errors} Fehler`); load(); }
	catch (err) { toast(err.message); }
});

try { sessionStorage.removeItem("ul3-admin"); } catch {} // password kept there by older versions
load().catch(() => {}); // signed in already if the session cookie is still valid
