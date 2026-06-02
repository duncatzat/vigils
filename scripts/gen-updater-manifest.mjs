// Generate a Tauri v2 updater manifest (latest-<plat>.json) for ONE platform,
// pointing at that platform's signed updater artifact hosted as a GitHub release asset.
//
// Run once per platform inside the release workflow's desktop matrix job (after build):
//   node scripts/gen-updater-manifest.mjs <tag> <plat> <bundleDir> <repo> [notes]
//   e.g. node scripts/gen-updater-manifest.mjs v0.1.5 windows-x86_64 target/release/bundle duncatzat/vigils "..."
//
// Emits ./latest-<plat>.json in CWD (uploaded as a release asset; the vigils.ai mirror
// pulls it to /desktop-updates/<plat>/latest.json). Exits 0 with no output file if no
// signed artifact is found (e.g. that bundle target failed) so the job can soft-skip.

import fs from "node:fs";
import path from "node:path";

const [, , tag, plat, bundleDir, repo, notes] = process.argv;
if (!tag || !plat || !bundleDir || !repo) {
  console.error("usage: gen-updater-manifest.mjs <tag> <plat> <bundleDir> <repo> [notes]");
  process.exit(2);
}
const version = tag.replace(/^v/, "");

// Per-platform Tauri v2 updater artifact signature suffix candidates (the .sig sits next
// to the artifact the updater downloads). Windows=NSIS setup.exe, macOS=.app.tar.gz,
// Linux=AppImage (v2 may emit either the AppImage directly or a .tar.gz wrapper — try both,
// most-specific first).
const SIG_SUFFIXES = {
  "windows-x86_64": ["-setup.exe.sig"],
  "darwin-aarch64": [".app.tar.gz.sig"],
  "linux-x86_64": [".AppImage.tar.gz.sig", ".AppImage.sig"],
};
const suffixes = SIG_SUFFIXES[plat];
if (!suffixes) { console.error(`unknown platform ${plat}`); process.exit(2); }

// Walk bundleDir for a .sig matching one of the candidate suffixes (in priority order).
function findSig(dir) {
  for (const suffix of suffixes) {
    const hits = [];
    (function walk(d) {
      if (!fs.existsSync(d)) return;
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name.endsWith(suffix)) hits.push(p);
      }
    })(dir);
    if (hits.length) return hits[0];
  }
  return null;
}

const sigFile0 = findSig(bundleDir);
if (!sigFile0) {
  console.log(`no ${suffixes.join("|")} artifact under ${bundleDir} — skipping manifest for ${plat}`);
  process.exit(0);
}
const artifactName = path.basename(sigFile0).replace(/\.sig$/, "");
const signature = fs.readFileSync(sigFile0, "utf8").trim();
const url = `https://github.com/${repo}/releases/download/${tag}/${artifactName}`;

const manifest = {
  version,
  notes: notes || `Vigils ${version}`,
  pub_date: new Date().toISOString(),
  platforms: { [plat]: { signature, url } },
};

const outFile = `latest-${plat}.json`;
fs.writeFileSync(outFile, JSON.stringify(manifest, null, 2));
console.log(`wrote ${outFile}: version=${version} artifact=${artifactName} sig=${signature.length}B`);
