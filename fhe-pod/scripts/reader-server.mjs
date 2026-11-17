import fs from "node:fs/promises";
import { watch } from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const readerRoot = path.join(projectRoot, "docs", "reader");
const uiRoot = path.join(projectRoot, "reader");
const mermaidRoot = path.join(projectRoot, "node_modules", "mermaid", "dist");
const markedRoot = path.join(projectRoot, "node_modules", "marked", "lib");
const port = Number(process.env.READER_PORT || process.env.PORT || 5174);

const mimeTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "application/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);

const sseClients = new Set();
let watchBroadcastTimer = null;

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function slugify(value) {
  return value
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function extractTitle(markdown, filePath) {
  const match = markdown.match(/^#\s+(.+)$/m);
  if (match) return match[1].replace(/`/g, "").trim();
  return path.basename(filePath, ".md").replace(/[_-]+/g, " ");
}

function extractSummary(markdown) {
  const line = markdown
    .split(/\r?\n/)
    .map((item) => item.trim())
    .find((item) => item && !item.startsWith("#") && !item.startsWith("- ") && !item.startsWith("```"));
  return (line || "Sem resumo inicial.").replace(/\s+/g, " ").slice(0, 220);
}

function extractHeadings(markdown) {
  return [...markdown.matchAll(/^(#{1,4})\s+(.+)$/gm)].map((match) => ({
    level: match[1].length,
    title: match[2].replace(/`/g, "").trim(),
    slug: slugify(match[2]),
  }));
}

function parseSimpleYamlBlock(source) {
  const result = {};
  const lines = source.split(/\r?\n/);
  let currentListKey = null;
  for (const line of lines) {
    if (!line.trim()) continue;
    const listMatch = line.match(/^\s*-\s+(.+)$/);
    if (listMatch && currentListKey) {
      if (!Array.isArray(result[currentListKey])) result[currentListKey] = [];
      result[currentListKey].push(listMatch[1].trim());
      continue;
    }
    const keyMatch = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!keyMatch) continue;
    const [, rawKey, rawValue] = keyMatch;
    const key = rawKey.trim();
    const value = rawValue.trim();
    if (!value) {
      result[key] = [];
      currentListKey = key;
      continue;
    }
    currentListKey = null;
    result[key] = value;
  }
  return result;
}

function normalizePathReference(reference, fromPath) {
  if (!reference) return null;
  if (reference.startsWith("http")) return null;
  const base = path.posix.dirname(fromPath);
  return path.posix.normalize(path.posix.join(base, reference));
}

function extractMarkdownFrontmatter(markdown, relativePath) {
  const match = markdown.match(/^---\s*\n([\s\S]*?)\n---\s*(?:\n|$)/);
  if (!match) return { metadata: {}, markdown };
  const parsed = parseSimpleYamlBlock(match[1]);
  const related = Array.isArray(parsed.related)
    ? parsed.related.map((item) => normalizePathReference(item, relativePath)).filter(Boolean)
    : [];
  const refs = Array.isArray(parsed.refs) ? parsed.refs : [];
  return {
    metadata: {
      id: typeof parsed.id === "string" ? parsed.id : null,
      topic: typeof parsed.topic === "string" ? parsed.topic : null,
      related,
      refs,
    },
    markdown: markdown.slice(match[0].length),
  };
}

function extractLinks(markdown, relativePath) {
  const base = path.posix.dirname(relativePath);
  const links = [];
  for (const match of markdown.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    const href = match[1].split("#")[0].trim();
    if (!href || href.startsWith("http") || href.startsWith("mailto:")) continue;
    const resolved = path.posix.normalize(path.posix.join(base, href));
    if (resolved.startsWith("docs/reader/") && resolved.endsWith(".md")) links.push(resolved);
  }
  return [...new Set(links)];
}

function parseReadingOrder(readme) {
  const order = new Map();
  let index = 1;
  for (const match of readme.matchAll(/`(docs\/reader\/[^`]+\.md)`/g)) {
    if (!order.has(match[1])) order.set(match[1], index++);
  }
  return order;
}

async function buildReaderIndex() {
  const files = (await fs.readdir(readerRoot, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .map((entry) => path.join(readerRoot, entry.name));
  const readme = await fs.readFile(path.join(readerRoot, "README.md"), "utf8").catch(() => "");
  const readingOrder = parseReadingOrder(readme);

  const documents = await Promise.all(
    files.map(async (file) => {
      const markdown = await fs.readFile(file, "utf8");
      const stats = await fs.stat(file);
      const relativePath = toPosix(path.relative(projectRoot, file));
      const parsed = extractMarkdownFrontmatter(markdown, relativePath);
      return {
        id: parsed.metadata.id || relativePath,
        path: relativePath,
        type: "markdown",
        topic: parsed.metadata.topic || null,
        title: extractTitle(parsed.markdown, relativePath),
        summary: extractSummary(parsed.markdown),
        headings: extractHeadings(parsed.markdown),
        links: extractLinks(parsed.markdown, relativePath),
        related: parsed.metadata.related,
        refs: parsed.metadata.refs,
        wordCount: (parsed.markdown.match(/\S+/g) || []).length,
        readingMinutes: Math.max(1, Math.round((parsed.markdown.match(/\S+/g) || []).length / 220)),
        modifiedAt: stats.mtime.toISOString(),
        order: readingOrder.get(relativePath) || (relativePath.endsWith("/README.md") ? 0 : 999),
        markdown: parsed.markdown,
      };
    }),
  );

  const byPath = new Map(documents.map((doc) => [doc.path, doc.id]));

  documents.forEach((doc) => {
    doc.related = [...new Set((doc.related || []).map((item) => byPath.get(item) || item).filter(Boolean))];
  });

  const backlinks = new Map();
  const citedBy = new Map();
  const topicToDocs = new Map();
  documents.forEach((doc) => {
    if (doc.topic) {
      if (!topicToDocs.has(doc.topic)) topicToDocs.set(doc.topic, new Set());
      topicToDocs.get(doc.topic).add(doc.id);
    }
    const internalLinks = doc.links
      .map((linkedPath) => byPath.get(linkedPath))
      .filter(Boolean);
    const explicit = doc.related || [];
    for (const target of [...internalLinks, ...explicit]) {
      if (!backlinks.has(target)) backlinks.set(target, new Set());
      backlinks.get(target).add(doc.id);
    }
    for (const ref of doc.refs || []) {
      if (!citedBy.has(ref)) citedBy.set(ref, new Set());
      citedBy.get(ref).add(doc.id);
    }
  });

  documents.forEach((doc) => {
    const sameTopic = doc.topic && topicToDocs.has(doc.topic) ? [...topicToDocs.get(doc.topic)] : [];
    doc.sameTopic = sameTopic.filter((id) => id !== doc.id);
    doc.backlinks = [...(backlinks.get(doc.id) || [])];
    doc.references = (doc.refs || []).map((key) => ({
      key,
      entry: null,
      citedBy: [...(citedBy.get(key) || [])],
    }));
  });

  documents.sort((left, right) => left.order - right.order || left.path.localeCompare(right.path));

  return {
    generatedAt: new Date().toISOString(),
    root: "docs/reader",
    documents,
    references: [],
  };
}

function sendJson(response, status, payload) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

function broadcastReaderChange() {
  const payload = `event: docs-changed\ndata: ${JSON.stringify({ ts: Date.now() })}\n\n`;
  for (const response of sseClients) response.write(payload);
}

function scheduleBroadcastReaderChange() {
  if (watchBroadcastTimer) clearTimeout(watchBroadcastTimer);
  watchBroadcastTimer = setTimeout(() => {
    broadcastReaderChange();
    watchBroadcastTimer = null;
  }, 120);
}

function attachReaderWatcher() {
  const onFsEvent = (_eventType, filename) => {
    if (!filename || !filename.endsWith(".md")) return;
    scheduleBroadcastReaderChange();
  };
  try {
    watch(readerRoot, { recursive: true }, onFsEvent);
  } catch {
    watch(readerRoot, {}, onFsEvent);
  }
}

async function serveStatic(request, response) {
  const url = new URL(request.url, `http://${request.headers.host}`);
  if (url.pathname.startsWith("/vendor/mermaid/")) {
    await serveFileFromRoot(
      response,
      mermaidRoot,
      url.pathname.replace("/vendor/mermaid/", ""),
      "public, max-age=3600",
    );
    return;
  }
  if (url.pathname.startsWith("/vendor/marked/")) {
    await serveFileFromRoot(
      response,
      markedRoot,
      url.pathname.replace("/vendor/marked/", ""),
      "public, max-age=3600",
    );
    return;
  }

  const requestedPath = decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname);
  await serveFileFromRoot(response, uiRoot, `.${requestedPath}`, "no-cache");
}

async function serveFileFromRoot(response, root, requestedPath, cacheControl) {
  const resolved = path.resolve(root, requestedPath);
  if (!resolved.startsWith(root)) {
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }

  try {
    const body = await fs.readFile(resolved);
    response.writeHead(200, {
      "Content-Type": mimeTypes.get(path.extname(resolved)) || "application/octet-stream",
      "Cache-Control": cacheControl,
    });
    response.end(body);
  } catch {
    response.writeHead(404);
    response.end("Not found");
  }
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (url.pathname === "/api/reader-docs") {
      sendJson(response, 200, await buildReaderIndex());
      return;
    }
    if (url.pathname === "/api/reader-events") {
      response.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });
      response.write("event: connected\ndata: ok\n\n");
      sseClients.add(response);
      request.on("close", () => sseClients.delete(response));
      return;
    }
    await serveStatic(request, response);
  } catch (error) {
    sendJson(response, 500, { error: error.message });
  }
});

attachReaderWatcher();
server.listen(port, "0.0.0.0", () => {
  console.log(`Reader running at http://localhost:${port}/`);
  console.log("Dynamic source: docs/reader/*.md");
});
