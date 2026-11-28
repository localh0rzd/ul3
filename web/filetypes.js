"use strict";

// File-type detection and icons for the paste preview.
// fileKind(file) → { kind, label, ext }; fileIcon(kind, ext) → element.

const FILE_KINDS = {
	// label: shown in the preview's info line; glyph: inner SVG (24×24, stroked), drawn inside a page outline.
	image: { label: "Bild", glyph: '<rect x="4" y="6" width="16" height="12" rx="1"/><circle cx="15" cy="10" r="1.5"/><path d="M4 16l5-5 4 4 2-2 5 5"/>' },
	video: { label: "Video", glyph: '<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M10 9.5v5l4.5-2.5z" fill="currentColor"/>' },
	audio: { label: "Audio", glyph: '<path d="M9 17V6l10-2v11"/><circle cx="7" cy="17" r="2"/><circle cx="17" cy="15" r="2"/>' },
	pdf: { label: "PDF-Dokument", glyph: '<path d="M6 7h12M6 11h12M6 15h7"/><path d="M15 15.5c1.5-3 3-1 1.5.5s-3 2-2.5 3 2-1 3-2.5"/>' },
	document: { label: "Dokument", glyph: '<path d="M6 6h12M6 10h12M6 14h12M6 18h8"/>' },
	spreadsheet: { label: "Tabelle", glyph: '<rect x="4" y="5" width="16" height="14" rx="1"/><path d="M4 9.5h16M4 14h16M9.5 5v14"/>' },
	presentation: { label: "Präsentation", glyph: '<rect x="3" y="5" width="18" height="11" rx="1"/><path d="M12 16v3M9 19h6M8 13v-3M12 13V8M16 13v-2"/>' },
	archive: { label: "Archiv", glyph: '<path d="M11 2h2M11 4h2M11 6h2M11 8h2M11 10h2"/><path d="M10 12h4v5a2 2 0 0 1-4 0z"/><path d="M12 15v1"/>' },
	ebook: { label: "E-Book", glyph: '<path d="M5 5a2 2 0 0 1 2-2h12v15H7a2 2 0 0 0-2 2z"/><path d="M5 20a2 2 0 0 0 2 1h12v-3"/>' },
	code: { label: "Quelltext", glyph: '<path d="M9 8l-4 4 4 4M15 8l4 4-4 4M13 6l-2 12"/>' },
	text: { label: "Text", glyph: '<path d="M6 6h12M6 10h12M6 14h12M6 18h6"/>' },
	font: { label: "Schriftart", glyph: '<path d="M3 18l5-12 5 12M5 14h6"/><circle cx="17.5" cy="15.5" r="2.5"/><path d="M20 12v6"/>' },
	package: { label: "Paket", glyph: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/>' },
	executable: { label: "Programm", glyph: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 10l3 2-3 2M12 15h5"/>' },
	disk: { label: "Abbild", glyph: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2"/>' },
	file: { label: "Datei", glyph: "" },
};

const KIND_BY_EXT = new Map(Object.entries({
	archive: "zip rar 7z tar gz tgz bz2 tbz2 xz txz zst lz lzma lz4 cab br z",
	pdf: "pdf",
	document: "doc docx docm odt rtf pages wpd tex",
	spreadsheet: "xls xlsx xlsm ods csv tsv numbers",
	presentation: "ppt pptx odp key",
	ebook: "epub mobi azw azw3 fb2 djvu cbz cbr",
	audio: "mp3 wav flac ogg oga opus m4a aac wma aif aiff mid midi amr weba",
	video: "mp4 m4v webm mkv mov avi wmv flv mpg mpeg 3gp ogv",
	image: "png jpg jpeg jfif gif webp avif bmp ico svg tif tiff heic heif psd xcf raw cr2 nef arw dng",
	font: "ttf otf woff woff2 eot",
	package: "apk aab deb rpm dmg pkg msi msix appimage jar flatpak snap whl",
	executable: "exe com bat cmd ps1 bin run elf",
	disk: "iso img vhd vhdx vmdk qcow2",
	code: "js mjs cjs ts tsx jsx py go rs c h cpp hpp cc cs java kt kts swift rb php pl lua sql html htm css scss sass less json jsonc xml yaml yml toml ini conf cfg env vue svelte dart r scala zig nim ex exs erl hs ml clj sh bash zsh fish makefile dockerfile gradle",
	text: "txt text md markdown log rst nfo srt vtt ics vcf diff patch",
}).flatMap(([kind, exts]) => exts.split(" ").map((e) => [e, kind])));

const KIND_BY_MIME = [
	[/^image\//, "image"], [/^video\//, "video"], [/^audio\//, "audio"], [/^application\/pdf$/, "pdf"],
	[/(zip|x-tar|gzip|x-7z|x-rar|x-bzip|x-xz|zstd|compressed)/, "archive"],
	[/(msword|wordprocessing|opendocument\.text|rtf)/, "document"],
	[/(ms-excel|spreadsheet)/, "spreadsheet"], [/(powerpoint|presentation)/, "presentation"],
	[/^font\/|font-/, "font"], [/epub/, "ebook"],
	[/(json|xml|javascript|ecmascript|x-sh|yaml|toml|sql)/, "code"], [/^text\//, "text"],
	[/(x-msdownload|x-executable|x-mach-binary|x-elf)/, "executable"],
	[/(android\.package|x-debian|x-rpm|x-apple-diskimage|x-msi)/, "package"],
	[/(x-iso9660|x-raw-disk)/, "disk"],
];

// Content we can show as text: anything text/*, plus well-known textual formats.
const TEXT_MIME = /^text\/|json|xml|javascript|ecmascript|x-sh|yaml|toml|sql|x-subrip|csv/;
const TEXT_EXT = new Set([...KIND_BY_EXT].filter(([, k]) => k === "code" || k === "text").map(([e]) => e).concat(["csv", "tsv", "svg"]));

function fileExt(name) {
	const base = name.toLowerCase().split("/").pop();
	if (base === "makefile" || base === "dockerfile") return base;
	const i = base.lastIndexOf(".");
	return i > 0 ? base.slice(i + 1) : "";
}

function fileKind(file) {
	const ext = fileExt(file.name || "");
	const type = (file.type || "").toLowerCase();
	// Extension first: it is more specific than the often generic MIME type (e.g. application/zip for .docx).
	let kind = KIND_BY_EXT.get(ext);
	if (!kind) kind = KIND_BY_MIME.find(([re]) => re.test(type))?.[1] || "file";
	const textual = TEXT_MIME.test(type) || TEXT_EXT.has(ext);
	return { kind, ext, label: FILE_KINDS[kind].label, textual };
}

// Static icon markup, never user input.
const ICONS = {
	download: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M11 3h2v9.2l3.3-3.3 1.4 1.4L12 16l-5.7-5.7 1.4-1.4 3.3 3.3V3zM5 18h14v3H5v-3z"/></svg>',
	copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11v14z"/></svg>',
};

// Icon-only button or link; the label goes to title and aria-label.
function iconEl(tag, icon, label, props = {}) {
	const e = el(tag, { ...props, title: label });
	e.setAttribute("aria-label", label);
	e.classList.add("btn-sq");
	e.innerHTML = ICONS[icon];
	return e;
}

// "?dl" makes the server answer with Content-Disposition: attachment.
function downloadLink(url, name, cls = "btn btn-ghost btn-sm") {
	return iconEl("a", "download", "Herunterladen", { class: cls, href: url + (url.includes("?") ? "&" : "?") + "dl", download: name });
}

function copyButton(label, onclick, cls = "btn btn-ghost btn-sm") {
	return iconEl("button", "copy", label, { type: "button", class: cls, onclick });
}

const SVG_NS = "http://www.w3.org/2000/svg";
function fileIcon(kind, ext) {
	const wrap = document.createElement("span");
	wrap.className = `ficon ft-${kind}`;
	const svg = document.createElementNS(SVG_NS, "svg");
	svg.setAttribute("viewBox", "0 0 40 48");
	svg.setAttribute("aria-hidden", "true");
	// page with folded corner, glyph centred in the page body; markup is static, never user input
	svg.innerHTML =
		'<path class="page" d="M7 2h19l10 10v32a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z"/>' +
		'<path class="fold" d="M26 2v8a2 2 0 0 0 2 2h8"/>' +
		`<g class="glyph" transform="translate(11 9) scale(.75)">${FILE_KINDS[kind].glyph}</g>`;
	wrap.append(svg);
	if (ext) {
		const badge = document.createElement("span");
		badge.className = "ext";
		badge.textContent = ext.length > 5 ? ext.slice(0, 4) + "…" : ext;
		wrap.append(badge);
	}
	return wrap;
}
