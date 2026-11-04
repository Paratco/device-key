import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// A published package carries one prebuilt binary per platform; a local build leaves it under build/.
const candidates = [
  join(root, "prebuilds", `${process.platform}-${process.arch}`, "device_key.node"),
  join(root, "build", "Release", "device_key.node"),
  join(root, "build", "device_key.node")
];

let binding;

function native() {
  if (binding === undefined) {
    const path = candidates.find((candidate) => existsSync(candidate));

    if (path === undefined) {
      throw new Error(`device-key: no binary for ${process.platform}-${process.arch}`);
    }

    binding = require(path);
  }

  return binding;
}

// SubjectPublicKeyInfo prefix for an uncompressed P-256 point: id-ecPublicKey, prime256v1, BIT STRING of 66 bytes.
const P256_SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");

/** SPKI DER for an uncompressed P-256 point (0x04 || X || Y). */
export function spkiFromPoint(point) {
  if (point.length !== 65 || point[0] !== 0x04) {
    throw new TypeError("expected an uncompressed P-256 point (65 bytes, 0x04 || X || Y)");
  }

  return Buffer.concat([P256_SPKI_PREFIX, point]);
}

// One DER INTEGER for an unsigned big-endian value: leading zeros dropped, one 0x00 back when the top bit is set.
function derInteger(bytes) {
  let start = 0;

  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }

  const value = bytes.subarray(start);
  const body = (value[0] & 0x80) === 0 ? value : Buffer.concat([Buffer.of(0), value]);

  return Buffer.concat([Buffer.of(0x02, body.length), body]);
}

/** DER ECDSA-Sig-Value for a raw P-256 signature (r || s, 64 bytes). */
export function p1363ToDer(signature) {
  if (signature.length !== 64) {
    throw new TypeError("expected a raw P-256 signature (64 bytes, r || s)");
  }

  const r = derInteger(signature.subarray(0, 32));
  const s = derInteger(signature.subarray(32));

  // At most 2 * 35 bytes, so the length always fits the short form.
  return Buffer.concat([Buffer.of(0x30, r.length + s.length), r, s]);
}

/** Whether this machine can hold a device key (TPM 2.0 or Secure Enclave present and usable). */
export async function isAvailable() {
  return native().isAvailable();
}

/** Creates the named key in hardware. Fails if it already exists. */
export async function createKey(name) {
  await native().createKey(name);
}

/** The named key's public key, as SPKI DER. */
export async function publicKey(name) {
  return spkiFromPoint(await native().publicPoint(name));
}

/** Signs `data` with the named key: ECDSA P-256 over SHA-256, DER encoded. */
export async function sign(name, data) {
  const digest = createHash("sha256").update(data).digest();

  return p1363ToDer(await native().signDigest(name, digest));
}

/** Deletes the named key. Not an error when it does not exist. */
export async function deleteKey(name) {
  await native().deleteKey(name);
}
