import { describe, expect, it } from "bun:test";
import { createKey, isAvailable, sign } from "..";

describe("native binding", () => {
  it("loads for this platform and answers availability", async () => {
    expect(typeof await isAvailable()).toBe("boolean");
  });

  it("checks arguments before touching the hardware", async () => {
    await expect(createKey("bad name!")).rejects.toThrow("name must be");
    await expect(createKey("")).rejects.toThrow("name must be");
  });

  it("rejects key operations when no key store is usable", async () => {
    if (await isAvailable()) {
      return;
    }

    await expect(sign("frs-test", Buffer.from("x"))).rejects.toThrow();
  });
});
