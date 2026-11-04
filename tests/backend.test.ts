import { createHash, createPublicKey, randomUUID, verify } from "node:crypto";
import { createRequire } from "node:module";
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
      await expect(api.createKey(name)).rejects.toThrow("already exists");
    } finally {
      await api.deleteKey(name);
    }

    await expect(api.sign(name, Buffer.from("x"))).rejects.toThrow("no key");

    // Deleting a key that is not there is not an error.
    await api.deleteKey(name);
  });
});
