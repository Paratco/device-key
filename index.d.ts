/// <reference types="node" />

/**
 * Hardware-held P-256 device keys: TPM 2.0 on Windows and Linux, Secure Enclave on macOS. The private key never
 * leaves the hardware; names are 1-64 characters of `A-Z a-z 0-9 . _ -`.
 */

/** Whether this machine can hold a device key (TPM 2.0 or Secure Enclave present and usable). */
export function isAvailable(): Promise<boolean>;

/** Creates the named key in hardware. Rejects if it already exists. */
export function createKey(name: string): Promise<void>;

/** The named key's public key, as SPKI DER. */
export function publicKey(name: string): Promise<Buffer>;

/** Signs `data` with the named key: ECDSA P-256 over SHA-256, DER encoded. */
export function sign(name: string, data: Uint8Array): Promise<Buffer>;

/** Deletes the named key. Not an error when it does not exist. */
export function deleteKey(name: string): Promise<void>;

/** SPKI DER for an uncompressed P-256 point (0x04 || X || Y). */
export function spkiFromPoint(point: Uint8Array): Buffer;

/** DER ECDSA-Sig-Value for a raw P-256 signature (r || s, 64 bytes). */
export function p1363ToDer(signature: Uint8Array): Buffer;
