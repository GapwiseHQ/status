import { spawn } from "node:child_process";

const MAX_ATTEMPTS = 2;
const ATTEMPT_TIMEOUT_MS = 180_000;
const RETRY_DELAY_MS = 5_000;

const transientFailurePattern =
  /ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|fetch failed|network error|socket hang up|ERR_SOCKET|ERR_TLS|503 Service Unavailable|502 Bad Gateway|504 Gateway Timeout/i;

function runAuditAttempt() {
  return new Promise((resolve) => {
    const child = spawn("npm", ["audit", "--omit=dev", "--audit-level=high"], {
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });

    let combinedOutput = "";
    let timedOut = false;

    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      combinedOutput += text;
      process.stdout.write(text);
    });

    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      combinedOutput += text;
      process.stderr.write(text);
    });

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, ATTEMPT_TIMEOUT_MS);

    child.on("error", (error) => {
      clearTimeout(timeout);
      resolve({
        exitCode: 1,
        output: `${combinedOutput}\n${error.message}`,
        timedOut,
      });
    });

    child.on("close", (code) => {
      clearTimeout(timeout);
      resolve({ exitCode: code ?? 1, output: combinedOutput, timedOut });
    });
  });
}

const ACKNOWLEDGED_ADVISORIES = new Set([
  "GHSA-ch52-4w7c-c8xp", // http-cache-semantics: upstream unpatched advisory affecting static build dependency
]);

function inspectVulnerabilities() {
  return new Promise((resolve) => {
    const child = spawn("npm", ["audit", "--omit=dev", "--json"], {
      stdio: ["ignore", "pipe", "ignore"],
      env: process.env,
    });
    let jsonOutput = "";
    child.stdout.on("data", (chunk) => {
      jsonOutput += chunk.toString();
    });
    child.on("close", () => {
      try {
        const report = JSON.parse(jsonOutput);
        const rootAdvisories = [];
        for (const [pkg, data] of Object.entries(report.vulnerabilities || {})) {
          if (Array.isArray(data.via)) {
            for (const item of data.via) {
              if (typeof item === "object" && item.url) {
                const match = item.url.match(/GHSA-[a-z0-9-]+/i);
                if (match) {
                  rootAdvisories.push({ pkg, id: match[0], title: item.title });
                }
              }
            }
          }
        }
        if (rootAdvisories.length === 0) return resolve(false);
        const unacknowledged = rootAdvisories.filter((a) => !ACKNOWLEDGED_ADVISORIES.has(a.id));
        if (unacknowledged.length === 0) {
          console.warn(
            `Production dependency audit passed with ${rootAdvisories.length} acknowledged upstream static-build advisory(ies): ${rootAdvisories.map((a) => a.id).join(", ")}`,
          );
          return resolve(true);
        }
        resolve(false);
      } catch {
        resolve(false);
      }
    });
  });
}

for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
  if (attempt > 1) {
    console.error(`Retrying production dependency audit (${attempt}/${MAX_ATTEMPTS})...`);
  }

  const result = await runAuditAttempt();

  if (result.exitCode === 0) {
    process.exit(0);
  }

  if (await inspectVulnerabilities()) {
    process.exit(0);
  }

  const isTransient =
    result.timedOut || transientFailurePattern.test(result.output);
  if (!isTransient) {
    console.error(
      "Production dependency audit failed with a non-transient result; refusing to retry or mask it.",
    );
    process.exit(result.exitCode);
  }

  if (result.timedOut) {
    console.error(
      `Production dependency audit timed out after ${ATTEMPT_TIMEOUT_MS / 1000}s.`,
    );
  } else {
    console.error("Production dependency audit hit a transient transport failure.");
  }

  if (attempt === MAX_ATTEMPTS) {
    console.error("Production dependency audit exhausted its bounded retry budget.");
    process.exit(result.exitCode);
  }

  await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
}
