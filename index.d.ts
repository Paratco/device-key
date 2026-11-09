/// <reference types="node" />

/**
 * Hardware-held P-256 device keys: TPM 2.0 on Windows and Linux, Secure Enclave on macOS. The private key never
 * leaves the hardware; names are 1-64 characters of `A-Z a-z 0-9 . _ -`.
 */

/** Whether this machine can hold a device key (TPM 2.0 or Secure Enclave present and usable). */
export function isAvailable(): Promise<boolean>;

/**
 * The `code` of a rejection callers act on: no key of that name (`publicKey`, `sign`), or one exists already
 * (`createKey`). Any other failure has no code.
 */
export type KeyErrorCode = "KEY_NOT_FOUND" | "KEY_EXISTS";

/** Creates the named key in hardware. Rejects with code `KEY_EXISTS` if it already exists. */
export function createKey(name: string): Promise<void>;

/** The named key's public key, as SPKI DER. Rejects with code `KEY_NOT_FOUND` if there is no such key. */
export function publicKey(name: string): Promise<Buffer>;

/** Signs `data` with the named key: ECDSA P-256 over SHA-256, DER encoded. Rejects with code `KEY_NOT_FOUND` if there is no such key. */
export function sign(name: string, data: Uint8Array): Promise<Buffer>;

/** Deletes the named key. Not an error when it does not exist. */
export function deleteKey(name: string): Promise<void>;

/** SPKI DER for an uncompressed P-256 point (0x04 || X || Y). */
export function spkiFromPoint(point: Uint8Array): Buffer;

/** DER ECDSA-Sig-Value for a raw P-256 signature (r || s, 64 bytes). */
export function p1363ToDer(signature: Uint8Array): Buffer;
