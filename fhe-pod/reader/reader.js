const state = {
  data: null,
  selectedId: localStorage.getItem("reader:selectedId") || "__index",
  query: "",
  fontSize: Number(localStorage.getItem("reader:fontSize") || 18),
  wide: localStorage.getItem("reader:wide") === "true",
  theme: localStorage.getItem("reader:theme") || "experiment",
  autoRefresh: true,
};
let readerEventsSource = null;

const els = {
  searchInput: document.querySelector("#searchInput"),
  content: document.querySelector("#content"),
  chapterMeta: document.querySelector("#chapterMeta"),
  outlineList: document.querySelector("#outlineList"),
  readerState: document.querySelector("#readerState"),
  progress: document.querySelector("#progress"),
  refreshButton: document.querySelector("#refreshButton"),
  prevButton: document.querySelector("#prevButton"),
  nextButton: document.querySelector("#nextButton"),
  decreaseFont: document.querySelector("#decreaseFont"),
  increaseFont: document.querySelector("#increaseFont"),
  widthButton: document.querySelector("#widthButton"),
  themeSelect: document.querySelector("#themeSelect"),
  autoRefresh: document.querySelector("#autoRefresh"),
  indexButton: document.querySelector("#indexButton"),
};

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function slugify(value) {
  return value
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function resolveReaderPath(currentPath, href) {
  const cleanHref = href.split("#")[0];
  if (!cleanHref || cleanHref.startsWith("http") || cleanHref.startsWith("mailto:")) return null;
  const baseParts = currentPath.split("/").slice(0, -1);
  const rawParts = cleanHref.startsWith("docs/reader/")
    ? cleanHref.split("/")
    : [...baseParts, ...cleanHref.split("/")];
  const normalized = [];
  for (const part of rawParts) {
    if (!part || part === ".") continue;
    if (part === "..") normalized.pop();
    else normalized.push(part);
  }
  const resolved = normalized.join("/");
  return resolved.startsWith("docs/reader/") && resolved.endsWith(".md") ? resolved : null;
}

function externalLink(href, label = null) {
  const cleanHref = href.replace(/&amp;/g, "&");
  const text = label === null ? cleanHref : label;
  return `<a href="${escapeHtml(cleanHref)}" target="_blank" rel="noreferrer">${escapeHtml(text)}</a>`;
}

function restoreInlineTokens(html, tokens) {
  return html.replace(/@@INLINE_TOKEN_(\d+)@@/g, (_match, index) => tokens[Number(index)] || "");
}

function autolinkUrls(html, stash) {
  html = html.replace(/&lt;(https?:\/\/[^\s]+?)&gt;/g, (_match, href) => stash(externalLink(href)));
  html = html.replace(/\bhttps?:\/\/[^\s<]+/g, (match) => {
    const trailing = match.match(/[),.;:!?]+$/)?.[0] || "";
    const href = trailing ? match.slice(0, -trailing.length) : match;
    return `${externalLink(href)}${trailing}`;
  });
  html = html.replace(/(^|[\s(])(www\.[^\s<]+)/g, (_match, prefix, match) => {
    const trailing = match.match(/[),.;:!?]+$/)?.[0] || "";
    const href = trailing ? match.slice(0, -trailing.length) : match;
    return `${prefix}${externalLink(`https://${href}`, href)}${trailing}`;
  });
  return html;
}

function inlineMarkdown(text, currentPath) {
  const tokens = [];
  const stash = (html) => {
    const token = `@@INLINE_TOKEN_${tokens.length}@@`;
    tokens.push(html);
    return token;
  };

  let raw = text.replace(/`([^`]+)`/g, (_match, code) => stash(`<code>${escapeHtml(code)}</code>`));
  raw = raw.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, label, href) => {
    const resolved = resolveReaderPath(currentPath, href);
    if (resolved) return stash(`<a href="#" data-doc="${resolved}">${escapeHtml(label)}</a>`);
    return stash(externalLink(href, label));
  });

  let html = escapeHtml(raw);
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  html = autolinkUrls(html, stash);
  return restoreInlineTokens(html, tokens);
}

function buildMarkdownRenderer(currentPath) {
  const markedApi = window.marked?.marked || window.marked;
  const renderer = new markedApi.Renderer();

  renderer.heading = (token) => {
    const level = token.depth;
    const title = token.text.trim();
    return `<h${level} id="${slugify(title)}">${markedApi.parseInline(title)}</h${level}>`;
  };

  renderer.link = (token) => {
    const resolved = resolveReaderPath(currentPath, token.href || "");
    const label = markedApi.parseInline(token.text || token.href || "");
    if (resolved) return `<a href="#" data-doc="${resolved}">${label}</a>`;
    return `<a href="${escapeHtml(token.href || "")}" target="_blank" rel="noreferrer">${label}</a>`;
  };

  renderer.code = (token) => {
    const lang = (token.lang || "").trim().toLowerCase();
    if (lang === "mermaid") {
      return `<div class="mermaid-block"><div class="mermaid">${escapeHtml(token.text)}</div></div>`;
    }
    return `<pre><code>${escapeHtml(token.text)}</code></pre>`;
  };

  return renderer;
}

function renderMarkdown(markdown, currentPath) {
  const markedApi = window.marked?.marked || window.marked;
  if (!markedApi) return `<pre><code>${escapeHtml(markdown)}</code></pre>`;
  const html = markedApi.parse(markdown, {
    gfm: true,
    breaks: false,
    renderer: buildMarkdownRenderer(currentPath),
  });
  return html.replace(/<table>/g, '<div class="table-wrap"><table>').replace(/<\/table>/g, "</table></div>");
}

async function renderMermaidDiagrams() {
  const mermaid = window.mermaid;
  const nodes = [...els.content.querySelectorAll(".mermaid")];
  if (!nodes.length || !mermaid) return;

  mermaid.initialize({
    startOnLoad: false,
    securityLevel: "strict",
    theme: state.theme === "dark" ? "dark" : "default",
    flowchart: {
      htmlLabels: false,
      curve: "basis",
    },
  });

  try {
    await mermaid.run({ nodes });
  } catch (error) {
    for (const node of nodes) {
      if (node.querySelector("svg")) continue;
      const source = node.textContent;
      node.outerHTML = `<pre class="mermaid-error"><code>${escapeHtml(source)}</code></pre>`;
    }
    console.error("Mermaid render failed", error);
  }
}

function getDocs() {
  return state.data?.documents || [];
}

function getSelectedDoc() {
  if (state.selectedId === "__index") return null;
  const docs = getDocs();
  return docs.find((doc) => doc.id === state.selectedId) || null;
}

function getDocById(id) {
  return getDocs().find((doc) => doc.id === id) || null;
}

function getFilteredDocs() {
  const query = state.query.trim().toLowerCase();
  if (!query) return getDocs();
  return getDocs().filter((doc) => {
    const haystack = [
      doc.title,
      doc.summary,
      doc.path,
      doc.headings.map((heading) => heading.title).join(" "),
      doc.markdown,
    ]
      .join(" ")
      .toLowerCase();
    return query.split(/\s+/).every((token) => haystack.includes(token));
  });
}

function chapterNumber(doc, fallback) {
  if (doc.order === 0) return "Intro";
  return doc.order || fallback;
}

async function loadDocs({ keepScroll = false } = {}) {
  const response = await fetch("/api/reader-docs", { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const previousDoc = getSelectedDoc();
  state.data = await response.json();
  if (!state.selectedId || (state.selectedId !== "__index" && !getDocs().some((doc) => doc.id === state.selectedId))) {
    state.selectedId = "__index";
  }
  render();
  if (keepScroll && previousDoc?.id === state.selectedId) restoreScroll(previousDoc.id);
}

function renderIndexButton() {
  els.indexButton.classList.toggle("active", state.selectedId === "__index");
}

function renderOutline(doc) {
  els.outlineList.innerHTML = doc.headings
    .filter((heading) => heading.level <= 3)
    .map(
      (heading) =>
        `<a class="level-${heading.level}" href="#${heading.slug}">${escapeHtml(heading.title)}</a>`,
    )
    .join("");
}

function renderReader(doc) {
  if (!doc) {
    renderIndexPage();
    return;
  }
  document.title = `${doc.title} · FHE-POD Reader`;
  els.chapterMeta.innerHTML = `
    <span>${escapeHtml(doc.path)}</span>
    <span>${doc.readingMinutes} min</span>
    <span>Atualizado ${new Intl.DateTimeFormat("pt-BR", {
      dateStyle: "short",
      timeStyle: "short",
    }).format(new Date(doc.modifiedAt))}</span>
  `;
  els.content.innerHTML = renderMarkdown(doc.markdown, doc.path);
  renderMermaidDiagrams();
  renderOutline(doc);
}

function renderIndexPage() {
  const docs = getDocs();
  const filteredDocs = getFilteredDocs();
  document.title = "Índice · FHE-POD Reader";
  els.chapterMeta.innerHTML = `
    <span>docs/reader</span>
    <span>${docs.length} arquivos .md</span>
    <span>Atualizado ${new Intl.DateTimeFormat("pt-BR", {
      dateStyle: "short",
      timeStyle: "short",
    }).format(new Date(state.data.generatedAt))}</span>
  `;
  els.content.innerHTML = `
    <section class="reader-index">
      <h1>Índice dos documentos</h1>
      <p class="index-lead">Use esta página como sumário principal quando a coleção crescer. A lista é atualizada dinamicamente a partir dos arquivos <code>.md</code> em <code>docs/reader/</code>.</p>
      <div class="index-stats">
        <span><strong>${filteredDocs.length}</strong> listados</span>
        <span><strong>${docs.length}</strong> arquivos</span>
        <span><strong>${filteredDocs.reduce((sum, doc) => sum + doc.wordCount, 0)}</strong> palavras</span>
        <span><strong>${filteredDocs.reduce((sum, doc) => sum + doc.readingMinutes, 0)}</strong> min de leitura</span>
      </div>
      <div class="index-grid">
        ${filteredDocs
          .map(
            (doc, index) => `
              <button class="index-card" data-doc="${doc.id}" type="button">
                <span class="index-number">${chapterNumber(doc, index + 1)}</span>
                <span class="index-card-body">
                  <strong>${escapeHtml(doc.title)}</strong>
                  <small>${doc.readingMinutes} min · ${doc.wordCount} palavras</small>
                  <em>${escapeHtml(doc.summary)}</em>
                </span>
              </button>
            `,
          )
          .join("") || `<p class="empty-index">Nenhum arquivo encontrado para a busca atual.</p>`}
      </div>
    </section>
  `;
  els.outlineList.innerHTML = filteredDocs
    .map((doc, index) => `<a href="#" data-doc="${doc.id}">${chapterNumber(doc, index + 1)}. ${escapeHtml(doc.title)}</a>`)
    .join("");
}

function renderState() {
  const docs = getDocs();
  const selected = getSelectedDoc();
  els.readerState.textContent = selected
    ? `${docs.length} arquivos em docs/reader. Índice atualizado em ${new Intl.DateTimeFormat("pt-BR", {
        dateStyle: "short",
        timeStyle: "medium",
      }).format(new Date(state.data.generatedAt))}.`
    : `${docs.length} arquivos em docs/reader. Índice principal aberto.`;
}

function renderNavButtons() {
  const docs = getDocs();
  if (state.selectedId === "__index") {
    els.prevButton.disabled = true;
    els.nextButton.disabled = docs.length === 0;
    return;
  }
  const index = docs.findIndex((doc) => doc.id === state.selectedId);
  els.prevButton.disabled = index <= 0;
  els.nextButton.disabled = index < 0 || index >= docs.length - 1;
}

function applyPreferences() {
  document.documentElement.style.setProperty("--reader-font-size", `${state.fontSize}px`);
  document.body.classList.toggle("wide", state.wide);
  document.body.dataset.theme = state.theme;
  els.themeSelect.value = state.theme;
  els.autoRefresh.checked = state.autoRefresh;
}

function render() {
  applyPreferences();
  renderIndexButton();
  const doc = getSelectedDoc();
  renderReader(doc);
  renderState();
  renderNavButtons();
  updateProgress();
}

function selectDoc(id) {
  saveScroll();
  state.selectedId = id;
  localStorage.setItem("reader:selectedId", id);
  render();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function selectIndex() {
  saveScroll();
  state.selectedId = "__index";
  localStorage.setItem("reader:selectedId", "__index");
  render();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function saveScroll() {
  if (!state.selectedId) return;
  localStorage.setItem(`reader:scroll:${state.selectedId}`, String(window.scrollY));
}

function restoreScroll(id) {
  const scrollY = Number(localStorage.getItem(`reader:scroll:${id}`) || 0);
  requestAnimationFrame(() => window.scrollTo({ top: scrollY }));
}

function moveChapter(offset) {
  const docs = getDocs();
  if (state.selectedId === "__index") {
    const first = offset > 0 ? docs[0] : null;
    if (first) selectDoc(first.id);
    return;
  }
  const index = docs.findIndex((doc) => doc.id === state.selectedId);
  const next = docs[index + offset];
  if (next) selectDoc(next.id);
}

function updateProgress() {
  const scrollable = document.documentElement.scrollHeight - window.innerHeight;
  const progress = scrollable > 0 ? Math.min(1, Math.max(0, window.scrollY / scrollable)) : 0;
  els.progress.style.transform = `scaleX(${progress})`;
}

els.content.addEventListener("click", (event) => {
  const link = event.target.closest("[data-doc]");
  if (!link) return;
  event.preventDefault();
  selectDoc(link.dataset.doc);
});

els.outlineList.addEventListener("click", (event) => {
  const link = event.target.closest("[data-doc]");
  if (!link) return;
  event.preventDefault();
  selectDoc(link.dataset.doc);
});

els.indexButton.addEventListener("click", selectIndex);

els.searchInput.addEventListener("input", (event) => {
  state.query = event.target.value;
  state.selectedId = "__index";
  localStorage.setItem("reader:selectedId", "__index");
  render();
});

els.refreshButton.addEventListener("click", () => loadDocs({ keepScroll: true }));
els.prevButton.addEventListener("click", () => moveChapter(-1));
els.nextButton.addEventListener("click", () => moveChapter(1));

els.decreaseFont.addEventListener("click", () => {
  state.fontSize = Math.max(15, state.fontSize - 1);
  localStorage.setItem("reader:fontSize", String(state.fontSize));
  applyPreferences();
});

els.increaseFont.addEventListener("click", () => {
  state.fontSize = Math.min(24, state.fontSize + 1);
  localStorage.setItem("reader:fontSize", String(state.fontSize));
  applyPreferences();
});

els.widthButton.addEventListener("click", () => {
  state.wide = !state.wide;
  localStorage.setItem("reader:wide", String(state.wide));
  applyPreferences();
});

els.themeSelect.addEventListener("change", (event) => {
  state.theme = event.target.value;
  localStorage.setItem("reader:theme", state.theme);
  render();
});

els.autoRefresh.addEventListener("change", (event) => {
  state.autoRefresh = event.target.checked;
});

window.addEventListener("scroll", () => {
  saveScroll();
  updateProgress();
});

window.addEventListener("keydown", (event) => {
  if (event.target.matches("input, textarea, select")) return;
  if (event.key === "ArrowLeft") moveChapter(-1);
  if (event.key === "ArrowRight") moveChapter(1);
});

setInterval(() => {
  if (state.autoRefresh) loadDocs({ keepScroll: true }).catch(console.error);
}, 10000);

function setupLiveUpdates() {
  if (typeof EventSource === "undefined") return;
  readerEventsSource = new EventSource("/api/reader-events");
  readerEventsSource.addEventListener("docs-changed", () => {
    if (state.autoRefresh) loadDocs({ keepScroll: true }).catch(console.error);
  });
  readerEventsSource.onerror = () => {
    if (readerEventsSource) {
      readerEventsSource.close();
      readerEventsSource = null;
    }
    setTimeout(setupLiveUpdates, 1500);
  };
}

window.addEventListener("beforeunload", () => {
  if (readerEventsSource) readerEventsSource.close();
});

loadDocs().catch((error) => {
  els.readerState.textContent = `Erro ao carregar docs/reader: ${error.message}`;
});
setupLiveUpdates();
