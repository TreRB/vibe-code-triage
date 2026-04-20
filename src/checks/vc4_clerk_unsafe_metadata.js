// VC4 — Clerk unsafeMetadata used for auth decisions.
//
// Flag HIGH when unsafeMetadata (any property) is referenced in a
// conditional, comparison, or membership check. Clerk's unsafeMetadata
// is client-writable by design — using it to gate features / roles is
// a direct privilege-escalation footgun.

// Match usage like:
//   user.unsafeMetadata.role === "admin"
//   user.unsafeMetadata?.isAdmin
//   if (user.unsafeMetadata.plan === "pro")
//   if (session.user.unsafeMetadata.role) ...
//   currentUser.unsafeMetadata.admin
const UNSAFE_METADATA = /(?:\w+(?:\?\.|\.))?unsafeMetadata(?:\?\.|\.)([a-zA-Z_][\w]*)/g;

// Patterns that indicate a conditional / auth-decision context around it.
// We look at the line plus the 1 lines around it.
const CONDITIONAL_HINT = /\b(?:if|while|&&|\|\||\?|===|!==|==|!=|switch|case|guard|require|assert|is[A-Z]|has[A-Z])/;
const ROLE_LIKE = /\b(?:role|isAdmin|admin|plan|tier|subscription|permission|perm|level|owner|isOwner|canAccess|superuser|access|rights)\b/i;

function isCodeFile(relPath) {
  const lower = relPath.toLowerCase();
  return lower.endsWith(".ts") || lower.endsWith(".tsx")
    || lower.endsWith(".js") || lower.endsWith(".jsx")
    || lower.endsWith(".mjs") || lower.endsWith(".cjs");
}

function lineNumberAt(content, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

function lineTextAt(content, idx) {
  // Return the surrounding line text.
  const start = content.lastIndexOf("\n", idx - 1) + 1;
  let end = content.indexOf("\n", idx);
  if (end === -1) end = content.length;
  return content.slice(start, end);
}

export default {
  id: "VC4",
  title: "Clerk unsafeMetadata used for auth",
  severity: "high",
  run({ index }) {
    const findings = [];
    const seen = new Set(); // dedupe by file:line:prop

    for (const f of index.files) {
      if (!f.content) continue;
      if (!isCodeFile(f.relPath)) continue;
      if (!f.content.includes("unsafeMetadata")) continue;

      UNSAFE_METADATA.lastIndex = 0;
      let m;
      while ((m = UNSAFE_METADATA.exec(f.content)) !== null) {
        const prop = m[1];
        const line = lineNumberAt(f.content, m.index);
        const key = `${f.relPath}:${line}:${prop}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const lineText = lineTextAt(f.content, m.index);
        const roleLike = ROLE_LIKE.test(prop) || ROLE_LIKE.test(lineText);
        const conditional = CONDITIONAL_HINT.test(lineText);

        if (roleLike || conditional) {
          findings.push({
            severity: "high",
            file: f.relPath,
            line,
            title: `Clerk unsafeMetadata.${prop} referenced in a conditional / role check`,
            evidence: `Line ${line}: ${lineText.trim()}\nunsafeMetadata is writable by the signed-in user from the client. Any user can call user.update({ unsafeMetadata: { ${prop}: <anything> } }) and flip this check in their favour.`,
            fix: `Use publicMetadata (server-writable, client-readable) or privateMetadata (server-only). Never make authorisation decisions on unsafeMetadata.`
          });
        }
      }
    }

    return findings;
  }
};
