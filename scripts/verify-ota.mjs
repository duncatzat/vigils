// Automated OTA verification test — faithfully reproduces what the Tauri v2 updater
// does before applying an update: fetch manifest → semver-gate → download artifact →
// verify the minisign signature against the pubkey baked into tauri.conf.
//
// Tauri signatures use minisign with the *prehashed* algorithm ('ED'): the signed
// message is Blake2b-512(file), verified with Ed25519. Node's crypto has both.
//
// Self-validating: a POSITIVE check (real artifact must verify) AND a NEGATIVE control
// (one flipped byte must fail) — so a always-true bug can't pass silently.
//
// Usage: node ota-verify-test.mjs <manifestUrl> <currentVersion> <pubkeyB64>
// Exit 0 = OTA chain valid; 1 = any check failed.

import crypto from "node:crypto";

const [, , MANIFEST_URL, CURRENT_VERSION, PUBKEY_B64] = process.argv;
if (!MANIFEST_URL || !CURRENT_VERSION || !PUBKEY_B64) {
  console.log("usage: node ota-verify-test.mjs <manifestUrl> <currentVersion> <pubkeyB64>");
  process.exit(1);
}

const fail = (m) => { console.log("  ✗ " + m); process.exitCode = 1; };
const ok = (m) => console.log("  ✓ " + m);

// minisign pubkey/sig text → { alg, keyId, payload }
function parseMinisignLine2(text) {
  const lines = text.split("\n").filter((l) => l.length);
  const bin = Buffer.from(lines[1], "base64"); // 2nd line is base64(binary blob)
  return { alg: bin.subarray(0, 2).toString("latin1"), keyId: bin.subarray(2, 10), payload: bin.subarray(10) };
}

function semverGt(a, b) {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0); }
  return false;
}

// Wrap a raw 32-byte Ed25519 public key in SPKI DER so Node can import it.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function ed25519VerifyRaw(rawPub32, message, sig64) {
  const key = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawPub32]), format: "der", type: "spki" });
  return crypto.verify(null, message, key, sig64);
}

function tauriVerify(fileBuf, sigText, pubText) {
  const pub = parseMinisignLine2(pubText);
  const sig = parseMinisignLine2(sigText);
  if (Buffer.compare(pub.keyId, sig.keyId) !== 0)
    throw new Error(`key id mismatch: pub=${pub.keyId.toString("hex")} sig=${sig.keyId.toString("hex")}`);
  // 'ED' = prehashed (Blake2b-512(file)); 'Ed' = legacy (raw file).
  const message = sig.alg === "ED" ? crypto.createHash("blake2b512").update(fileBuf).digest() : fileBuf;
  return ed25519VerifyRaw(pub.payload.subarray(0, 32), message, sig.payload.subarray(0, 64));
}

async function main() {
  console.log(`OTA verify: ${MANIFEST_URL}  (installed=${CURRENT_VERSION})`);
  if (!crypto.getHashes().includes("blake2b512")) { fail("node crypto lacks blake2b512 — cannot verify"); return; }

  // 1. Fetch manifest (as the updater does).
  const res = await fetch(MANIFEST_URL);
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("json")) fail(`manifest content-type is '${ct}' (expected JSON — SPA fallback?)`);
  else ok(`manifest content-type ${ct}`);
  const manifest = await res.json();

  // 2. Structure + semver gate.
  const plat = Object.keys(manifest.platforms || {})[0];
  if (!manifest.version || !plat) { fail("manifest missing version/platforms"); return; }
  ok(`manifest version ${manifest.version}, platform ${plat}`);
  if (semverGt(manifest.version, CURRENT_VERSION)) ok(`semver gate: ${manifest.version} > ${CURRENT_VERSION} (update offered)`);
  else fail(`semver gate: ${manifest.version} !> ${CURRENT_VERSION}`);

  const entry = manifest.platforms[plat];
  if (!entry.signature || !entry.url) { fail("platform entry missing signature/url"); return; }
  ok(`artifact url ${entry.url}`);

  // 3. Download artifact (must be reachable + non-trivial).
  const aRes = await fetch(entry.url);
  if (!aRes.ok) { fail(`artifact HTTP ${aRes.status}`); return; }
  const fileBuf = Buffer.from(await aRes.arrayBuffer());
  ok(`artifact downloaded ${fileBuf.length} bytes`);

  // 4. Decode signature (manifest signature = base64(minisig text file)) + pubkey.
  const sigText = Buffer.from(entry.signature, "base64").toString("utf8");
  const pubText = Buffer.from(PUBKEY_B64, "base64").toString("utf8");

  // 5a. POSITIVE: real artifact must verify.
  let pass;
  try { pass = tauriVerify(fileBuf, sigText, pubText); } catch (e) { fail("verify threw: " + e.message); return; }
  pass ? ok("signature VALID against tauri.conf pubkey (updater would accept)") : fail("signature INVALID (updater would reject)");

  // 5b. NEGATIVE control: tamper one byte → must fail (proves the check is real).
  const tampered = Buffer.from(fileBuf);
  tampered[Math.floor(tampered.length / 2)] ^= 0xff;
  let tamperPass;
  try { tamperPass = tauriVerify(tampered, sigText, pubText); } catch { tamperPass = false; }
  !tamperPass ? ok("negative control: tampered artifact correctly REJECTED") : fail("negative control FAILED: tampered artifact accepted (verifier is broken)");
}

main().then(() => {
  console.log(process.exitCode ? "\nVERDICT: FAIL" : "\nVERDICT: PASS — OTA signature chain is cryptographically valid end-to-end.");
}).catch((e) => { console.log("error:", e.message); process.exit(1); });
