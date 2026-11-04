// Release step: one package per platform from prebuilds/<target>/device_key.node, and the main package pointed at them
// through exact-version optionalDependencies. Package managers install only the one matching os / cpu / libc, so an
// app never ships the other platforms' binaries. Run from the repo root after the prebuilds are laid out.
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const TARGETS = {
  "win32-x64": { os: "win32", cpu: "x64" },
  "win32-arm64": { os: "win32", cpu: "arm64" },
  "darwin-arm64": { os: "darwin", cpu: "arm64" },
  "darwin-x64": { os: "darwin", cpu: "x64" },

  // Built on Ubuntu: a musl system (Alpine) must skip it, not install a binary that fails to load.
  "linux-x64": { os: "linux", cpu: "x64", libc: "glibc" },
  "linux-arm64": { os: "linux", cpu: "arm64", libc: "glibc" }
};

const main = JSON.parse(readFileSync("package.json", "utf8"));
const optionalDependencies = {};

for (const [target, { os, cpu, libc }] of Object.entries(TARGETS)) {
  const name = `${main.name}-${target}`;
  const dir = `npm/${target}`;

  mkdirSync(dir, { recursive: true });

  // Throws when a target's binary is missing, which fails the release rather than publishing without it.
  copyFileSync(`prebuilds/${target}/device_key.node`, `${dir}/device_key.node`);
  copyFileSync("LICENSE", `${dir}/LICENSE`);

  writeFileSync(`${dir}/package.json`, `${JSON.stringify({
    name,
    version: main.version,
    description: `${main.name} binary for ${target}`,
    license: main.license,
    main: "device_key.node",
    files: ["device_key.node"],
    os: [os],
    cpu: [cpu],
    ...(libc === undefined ? {} : { libc: [libc] }),
    repository: main.repository,
    publishConfig: main.publishConfig
  }, null, 2)}\n`);

  optionalDependencies[name] = main.version;
}

writeFileSync("package.json", `${JSON.stringify({ ...main, optionalDependencies }, null, 2)}\n`);
console.log(Object.keys(optionalDependencies).join("\n"));
