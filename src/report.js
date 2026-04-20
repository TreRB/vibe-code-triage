// report.js — human terminal, JSON, and SARIF 2.1.0 output.

import chalk from "chalk";
import Table from "cli-table3";

export const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];

export function severityRank(s) {
  const idx = SEVERITY_ORDER.indexOf(String(s || "").toLowerCase());
  return idx === -1 ? 0 : idx;
}

export function shouldFail(findings, threshold) {
  if (!threshold) return false;
  const min = severityRank(threshold);
  return findings.some((f) => severityRank(f.severity) >= min);
}

function sevBadge(sev) {
  switch (String(sev).toLowerCase()) {
    case "critical": return chalk.bgRed.white.bold(" CRITICAL ");
    case "high":     return chalk.red.bold(" HIGH     ");
    case "medium":   return chalk.yellow.bold(" MEDIUM   ");
    case "low":      return chalk.blue(" LOW      ");
    case "info":     return chalk.gray(" INFO     ");
    default:         return chalk.gray(` ${sev} `);
  }
}

function severityToSarifLevel(sev) {
  switch (String(sev).toLowerCase()) {
    case "critical":
    case "high":    return "error";
    case "medium":  return "warning";
    case "low":
    case "info":    return "note";
    default:        return "none";
  }
}

export function renderHuman(result) {
  const lines = [];
  lines.push("");
  lines.push(chalk.bold.cyan("VIBE-CODE-TRIAGE") + "  " + chalk.gray("target: ") + result.root);
  lines.push(chalk.gray(`  scanned ${result.fileCount} files, ran ${result.checks.length} checks`));
  lines.push("");

  const byCheck = {};
  for (const c of result.checks) byCheck[c.id] = c;

  if (result.findings.length === 0) {
    lines.push(chalk.green("  No findings. No vibe-coded anti-patterns detected."));
    lines.push("");
  } else {
    // Sort by severity desc, then file, then line.
    const sorted = [...result.findings].sort((a, b) =>
      severityRank(b.severity) - severityRank(a.severity)
      || String(a.file).localeCompare(String(b.file))
      || Number(a.line || 0) - Number(b.line || 0)
    );

    lines.push(chalk.bold(`  Findings (${sorted.length}):`));
    lines.push("");
    for (const f of sorted) {
      const where = `${f.file}:${f.line || 1}`;
      lines.push(`  ${sevBadge(f.severity)} ${chalk.bold(f.checkId)} ${chalk.cyan(where)}`);
      lines.push(`              ${chalk.bold(f.title)}`);
      if (f.evidence) {
        for (const ln of String(f.evidence).split("\n")) {
          lines.push(`              ${chalk.gray("Evidence:")} ${ln}`);
        }
      }
      if (f.fix) {
        for (const ln of String(f.fix).split("\n")) {
          lines.push(`              ${chalk.gray("Fix:     ")} ${ln}`);
        }
      }
      lines.push("");
    }
  }

  // Summary table.
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of result.findings) {
    const s = String(f.severity).toLowerCase();
    if (counts[s] != null) counts[s]++;
  }

  const table = new Table({
    head: [chalk.bold("SEVERITY"), chalk.bold("COUNT")],
    style: { head: [], border: ["gray"] }
  });
  table.push(
    [chalk.bgRed.white.bold(" CRITICAL "), counts.critical],
    [chalk.red.bold(" HIGH     "), counts.high],
    [chalk.yellow.bold(" MEDIUM   "), counts.medium],
    [chalk.blue(" LOW      "), counts.low],
    [chalk.gray(" INFO     "), counts.info]
  );
  lines.push(chalk.bold("  Summary"));
  for (const row of table.toString().split("\n")) lines.push("  " + row);
  lines.push("");
  lines.push(chalk.gray("  Docs: https://github.com/TreRB/vibe-code-triage"));
  lines.push("");
  return lines.join("\n");
}

export function renderJSON(result) {
  return JSON.stringify(result, null, 2);
}

export function renderSARIF(result) {
  const rules = [];
  const seenRules = new Set();
  const results = [];

  for (const f of result.findings) {
    const ruleId = f.checkId || "UNKNOWN";
    if (!seenRules.has(ruleId)) {
      seenRules.add(ruleId);
      const check = result.checks.find((c) => c.id === ruleId);
      rules.push({
        id: ruleId,
        name: ruleId,
        shortDescription: { text: check?.title || ruleId },
        fullDescription: { text: check?.title || ruleId },
        defaultConfiguration: { level: severityToSarifLevel(f.severity) },
        helpUri: `https://github.com/TreRB/vibe-code-triage#${ruleId.toLowerCase()}`
      });
    }

    results.push({
      ruleId,
      level: severityToSarifLevel(f.severity),
      message: {
        text: `${f.title}\n\nEvidence: ${f.evidence || ""}\n\nFix: ${f.fix || ""}`
      },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: { startLine: Math.max(1, Number(f.line || 1)) }
        }
      }],
      properties: { severity: f.severity }
    });
  }

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "valtik-vibe-code-triage",
          version: "0.1.0",
          informationUri: "https://github.com/TreRB/vibe-code-triage",
          rules
        }
      },
      results
    }]
  };
  return JSON.stringify(sarif, null, 2);
}
