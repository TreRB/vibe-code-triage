// Test helpers: build a synthetic file index in-memory.

export function mkFile(relPath, content, { size } = {}) {
  return {
    path: "/virtual/" + relPath,
    relPath,
    size: size != null ? size : Buffer.byteLength(content || "", "utf8"),
    content: content,
    lines: null,
    oversized: false,
    textual: true
  };
}

export function mkIndex(files) {
  return { root: "/virtual", files };
}

export function fileLines(file) {
  if (file.lines) return file.lines;
  if (file.content == null) return [];
  file.lines = file.content.split(/\r?\n/);
  return file.lines;
}
