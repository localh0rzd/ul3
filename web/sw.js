"use strict";

// Receives "Share to" (Web Share Target) POSTs, parks the payload in the Cache
// API and redirects to the page, which picks it up and stages it for preview.
// Nothing else is intercepted.
const CACHE = "ul3-share";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (e) => {
	const url = new URL(e.request.url);
	if (e.request.method === "POST" && url.origin === location.origin && url.pathname === "/share") {
		e.respondWith(receiveShare(e.request));
	}
});

async function receiveShare(request) {
	try {
		const form = await request.formData();
		const files = form.getAll("files").filter((f) => f instanceof File && (f.size > 0 || f.name));
		const meta = { title: form.get("title") || "", text: form.get("text") || "", url: form.get("url") || "", files: [] };
		await caches.delete(CACHE);
		const cache = await caches.open(CACHE);
		for (const [i, f] of files.entries()) {
			await cache.put(`/share-data/${i}`, new Response(f));
			meta.files.push({ name: f.name, type: f.type });
		}
		await cache.put("/share-data/meta", new Response(JSON.stringify(meta), { headers: { "Content-Type": "application/json" } }));
		return Response.redirect("/?share=1", 303);
	} catch {
		await caches.delete(CACHE).catch(() => {}); // don't leave a half-written payload behind
		return Response.redirect("/?share=failed", 303);
	}
}
