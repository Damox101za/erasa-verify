// Vusi Erasa certificate verification for the browser (and Node 20+).
// Copyright (C) 2026 Hilton Vusi Kholokholo
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Must produce exactly the same canonical bytes as internal/cert/canonical.go.

export const SPEC = "erasa/0.1";

/** Canonical JSON: sorted keys, no whitespace, JSON.stringify string escaping, safe integers only. */
export function canonicalize(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error("canonical form allows only safe integers, got " + v);
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  throw new Error("unexpected JSON value of type " + typeof v);
}

export function base64ToBytes(s) {
  s = s.trim().replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/**
 * Decode the certificate carried in a verify link's fragment:
 * "#z=" raw-deflated JSON (what the PDF QR code uses) or "#c=" plain JSON, both base64url.
 */
export async function certFromHash(hash) {
  const m = /(?:^#|&)([zc])=([A-Za-z0-9_-]+)/.exec(hash || "");
  if (!m) return null;
  let bytes = base64ToBytes(m[2]);
  if (m[1] === "z") {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
    bytes = new Uint8Array(await new Response(stream).arrayBuffer());
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}

/** Accept "erasa-public-key <base64>" or bare base64; returns 32 raw bytes. */
export function parsePublicKey(text) {
  const b64 = text.trim().replace(/^erasa-public-key\s+/, "");
  const bytes = base64ToBytes(b64);
  if (bytes.length !== 32) throw new Error("an Ed25519 public key is 32 bytes, this one is " + bytes.length);
  return bytes;
}

export async function fingerprint(pubBytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", pubBytes));
  return "SHA256:" + bytesToBase64(digest).replace(/=+$/, "");
}

/**
 * Verify a parsed certificate against raw public key bytes.
 * Returns { ok: true } or { ok: false, reason }.
 */
export async function verifyCertificate(cert, pubBytes) {
  if (!cert || typeof cert !== "object") return { ok: false, reason: "This is not a certificate." };
  if (cert.spec !== SPEC) return { ok: false, reason: `Unknown certificate format "${cert.spec}".` };
  const sig = cert.signature;
  if (!sig || sig.alg !== "Ed25519" || typeof sig.value !== "string") {
    return { ok: false, reason: "The certificate has no Ed25519 signature." };
  }
  const fp = await fingerprint(pubBytes);
  if (!cert.issuer || fp !== cert.issuer.key_fingerprint) {
    return { ok: false, reason: `The public key (${fp}) is not the key named on the certificate.` };
  }
  const unsigned = { ...cert };
  delete unsigned.signature;
  let data;
  try {
    data = new TextEncoder().encode(canonicalize(unsigned));
  } catch (e) {
    return { ok: false, reason: e.message };
  }
  let key;
  try {
    key = await crypto.subtle.importKey("raw", pubBytes, { name: "Ed25519" }, false, ["verify"]);
  } catch (e) {
    return { ok: false, reason: "This browser cannot check Ed25519 signatures. Use a current Chrome, Edge, Firefox or Safari." };
  }
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, base64ToBytes(sig.value), data);
  return valid
    ? { ok: true }
    : { ok: false, reason: "The signature does not match. The certificate was changed after it was signed, or it is forged." };
}
