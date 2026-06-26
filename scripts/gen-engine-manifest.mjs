// Build the signed engine manifest (engine-manifest.json) from the cli-ml `.sha256` sidecars on the
// draft release. Lists per-platform {url, sha256} for the `vigil-cli-ml` engine variant so the
// desktop GUI can SHA-pin the ML engine download against a **minisign-signed** manifest — the SHA
// trust anchor (the download source itself can't forge a valid signature). The manifest also carries
// the per-platform URLs, so the GUI never hardcodes asset names (solves the naming/format divergence:
// Windows `.zip` / Unix `.tar.gz`).
//
// Usage: node gen-engine-manifest.mjs <tag> <repo> <sumsDir>
//   <tag>     release tag, e.g. v0.4.2
//   <repo>    owner/name, e.g. duncatzat/vigils
//   <sumsDir> dir containing the downloaded `vigils-cli-ml-*.sha256` sidecars
// Emits engine-manifest.json in CWD. Platform keys (windows-x64 / linux-x64 / macos-arm64) align with
// the desktop `engine_platform()`.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [tag, repo, sumsDir] = process.argv.slice(2);
if (!tag || !repo || !sumsDir) {
  console.error("usage: gen-engine-manifest.mjs <tag> <repo> <sumsDir>");
  process.exit(2);
}

const cliMl = {};
for (const f of readdirSync(sumsDir)) {
  if (!f.startsWith("vigils-cli-ml-") || !f.endsWith(".sha256")) continue;
  // sidecar content: "<hex-sha256>  <filename>"
  const [hash, fname] = readFileSync(join(sumsDir, f), "utf8").trim().split(/\s+/);
  if (!hash || !fname) continue;
  // vigils-cli-ml-windows-x64.zip → plat = windows-x64
  const m = fname.match(/^vigils-cli-ml-(.+?)\.(zip|tar\.gz)$/);
  if (!m) continue;
  cliMl[m[1]] = {
    url: `https://github.com/${repo}/releases/download/${tag}/${fname}`,
    sha256: hash,
  };
}

const platforms = Object.keys(cliMl);
if (platforms.length === 0) {
  console.error(`FAIL: no vigils-cli-ml-*.sha256 sidecars found in ${sumsDir}`);
  process.exit(1);
}

const manifest = { schema: 1, version: tag.replace(/^v/, ""), artifacts: { "vigil-cli-ml": cliMl } };
// Newline-terminated; these exact bytes are what gets signed and what the GUI verifies.
writeFileSync("engine-manifest.json", JSON.stringify(manifest, null, 2) + "\n");
console.error(`engine-manifest.json: vigil-cli-ml platforms = ${platforms.join(", ")}`);
