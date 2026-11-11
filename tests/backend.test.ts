import { createHash, createPublicKey, randomUUID, verify } from "node:crypto";
import { chmodSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "bun:test";
import * as deviceKey from "..";
import { p1363ToDer, spkiFromPoint } from "..";

interface NativeBinding {
  isAvailable(): Promise<boolean>;
  createKey(name: string): Promise<void>;
  publicPoint(name: string): Promise<Buffer>;
  signDigest(name: string, digest: Buffer): Promise<Buffer>;
  deleteKey(name: string): Promise<void>;
}

// The same API as the package, over a binary loaded by path.
function wrap(binding: NativeBinding): typeof deviceKey {
  return {
    ...deviceKey,
    isAvailable: async () => binding.isAvailable(),
    createKey: async (name) => binding.createKey(name),
    publicKey: async (name) => spkiFromPoint(await binding.publicPoint(name)),
    sign: async (name, data) => p1363ToDer(await binding.signDigest(name, createHash("sha256").update(data).digest())),
    deleteKey: async (name) => binding.deleteKey(name)
  };
}

// What to test: a test build CI points at (hosted runners have no TPM, so it uses a software key store through the same
// calls); otherwise the package itself, when this machine has the hardware; otherwise nothing.
const testBinary = process.env.DEVICE_KEY_TEST_BINARY;
const api = testBinary === undefined
  ? deviceKey
  : wrap(createRequire(import.meta.url)(testBinary) as NativeBinding);
const usable = await api.isAvailable();

// A test build that cannot hold a key would skip everything below and pass having tested nothing.
if (testBinary !== undefined && !usable) {
  throw new Error(`DEVICE_KEY_TEST_BINARY (${testBinary}) reports no usable key store`);
}

describe.skipIf(!usable)("key store", () => {
  it("creates a key that signs, verifiable with its public key", async () => {
    const name = `test-${randomUUID()}`;

    await api.createKey(name);

    try {
      const publicKey = createPublicKey({ key: await api.publicKey(name), format: "der", type: "spki" });
      const data = Buffer.from("login challenge");
      const signature = await api.sign(name, data);

      expect(publicKey.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
      expect(verify("sha256", data, publicKey, signature)).toBeTrue();
      expect(verify("sha256", Buffer.from("another challenge"), publicKey, signature)).toBeFalse();
    } finally {
      await api.deleteKey(name);
    }
  });

  it("refuses to replace an existing key, and forgets a deleted one", async () => {
    const name = `test-${randomUUID()}`;

    await api.createKey(name);

    try {
      await expect(api.createKey(name)).rejects.toMatchObject({ code: "KEY_EXISTS" });
    } finally {
      await api.deleteKey(name);
    }

    await expect(api.sign(name, Buffer.from("x"))).rejects.toMatchObject({ code: "KEY_NOT_FOUND" });
    await expect(api.publicKey(name)).rejects.toMatchObject({ code: "KEY_NOT_FOUND" });

    // Deleting a key that is not there is not an error.
    await api.deleteKey(name);
  });

  // Root reads any file, so the key could not be made unreadable.
  it.skipIf(process.platform !== "linux" || process.getuid?.() === 0)(
    "does not call a key it cannot read missing",
    async () => {
      const name = `test-${randomUUID()}`;
      const file = path.join(process.env.XDG_DATA_HOME ?? path.join(homedir(), ".local/share"), "paratco-device-key", `${name}.tpm`);

      await api.createKey(name);
      chmodSync(file, 0o000);

      try {
        await expect(api.publicKey(name)).rejects.toThrow("Permission denied");
        await expect(api.publicKey(name)).rejects.not.toHaveProperty("code");
      } finally {
        chmodSync(file, 0o600);
        await api.deleteKey(name);
      }
    }
  );
});
