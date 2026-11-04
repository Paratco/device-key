import { createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { describe, expect, it } from "bun:test";
import { p1363ToDer, spkiFromPoint } from "..";

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });

describe("encoding", () => {
  it("wraps a raw point into SPKI that Node reads back as the same key", () => {
    const jwk = publicKey.export({ format: "jwk" });
    const point = Buffer.concat([Buffer.of(4), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]);

    const rebuilt = createPublicKey({ key: spkiFromPoint(point), format: "der", type: "spki" });

    expect(rebuilt.export({ format: "jwk" })).toEqual(jwk);
  });

  it("turns raw signatures into DER that verifies, across many random r and s", () => {
    // 500 signatures cover leading zero bytes and top bits set in r and s.
    for (let i = 0; i < 500; i++) {
      const data = randomBytes(32);
      const raw = sign("sha256", data, { key: privateKey, dsaEncoding: "ieee-p1363" });

      expect(verify("sha256", data, publicKey, p1363ToDer(raw))).toBeTrue();
    }
  });

  it("encodes the integer edge cases exactly", () => {
    // r: leading zeros then a top bit set (00 00 80 ...) keeps one 0x00; s: all zero but the last byte.
    const r = Buffer.concat([Buffer.of(0, 0, 0x80), Buffer.alloc(29, 1)]);
    const s = Buffer.concat([Buffer.alloc(31), Buffer.of(5)]);

    expect(p1363ToDer(Buffer.concat([r, s]))).toEqual(Buffer.concat([
      Buffer.of(0x30, 2 + 31 + 3, 0x02, 31, 0x00, 0x80), Buffer.alloc(29, 1),
      Buffer.of(0x02, 1, 5)
    ]));
  });

  it("refuses inputs of the wrong shape", () => {
    expect(() => p1363ToDer(Buffer.alloc(63))).toThrow(TypeError);
    expect(() => spkiFromPoint(Buffer.alloc(65))).toThrow(TypeError);
  });
});
