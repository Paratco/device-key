# @paratco/device-key

Hardware-held device keys for Node and Electron. One P-256 ECDSA key per name, created inside the machine's security
hardware and never exported: TPM 2.0 on Windows and Linux, the Secure Enclave on macOS. The app gets the public key
and signatures, never the private key.

FRS uses it to log devices in: an admin approves a (user, device) pair, the device signs each login challenge with
its key, and the user's PIN is checked only after the signature (see Paratco/frs#534).

> **License:** MIT.
>
> **Status:** skeleton. The API, the encoding and the build/release pipeline are in place; the three hardware
> backends are not built yet and report the key store as unavailable.

## API

```ts
import { isAvailable, createKey, publicKey, sign, deleteKey } from "@paratco/device-key";

if (await isAvailable()) {
  await createKey("frs-device");                 // rejects if it already exists
  const spki = await publicKey("frs-device");    // SPKI DER, for the server
  const signature = await sign("frs-device", challenge); // ECDSA P-256 over SHA-256, DER
}
```

Every call returns a promise and runs off the JS thread: hardware operations can take hundreds of milliseconds.
Names are 1–64 characters of `A-Z a-z 0-9 . _ -`.

Signatures are DER on every platform, so a server verifies them with any standard library, e.g. Node's
`crypto.verify("sha256", data, spki, signature)`.

## Platforms

| OS | Hardware | Backend | Requirements |
|---|---|---|---|
| Windows 11 | TPM 2.0 | CNG `NCrypt`, *Microsoft Platform Crypto Provider*, machine key | Windows 11 requires TPM 2.0; VMs need a virtual TPM |
| Linux | TPM 2.0 | `tpm2-tss` ESAPI, key blob wrapped by the TPM | `libtss2-esys`; the process user in the `tss` group |
| macOS | Secure Enclave | Security.framework | Apple silicon or a T2 chip; the host app must be code-signed with a keychain access group, so it works inside a signed app, not from a bare `node` |

Prebuilt binaries for `win32-x64`, `win32-arm64`, `darwin-arm64`, `darwin-x64`, `linux-x64` (glibc) and `linux-arm64` (glibc), each
in its own package (`@paratco/device-key-<platform>-<arch>`), an optional dependency of the main package. The package
manager installs only the one for the machine, so an app ships only its own platform's binary. Node-API 10, so one
binary loads in Node, Bun and Electron without rebuilding.

## Security model

- The private key is created in, and used by, the hardware. Nothing in this package can read it.
- **The server cannot prove a key is hardware-held** without TPM / Secure Enclave key attestation, which this package
  does not do yet: a modified client could enroll a software key. In FRS the control is the admin's approval, after
  comparing the key fingerprint shown on the device.
- Release builds never fall back to a software key.
- Releases are built only by GitHub Actions from this repository. Every binary and the package tarball carry a build
  provenance attestation and are listed in `SHA256SUMS` on the release. Check one with
  `gh attestation verify device_key-win32-x64.node --repo Paratco/device-key`.
- Third-party code: the Node-API headers at build time, and `tpm2-tss` on Linux. No other native dependency.

## Build

Needs Bun 1.4.4, CMake 3.28+, and MSVC 2022 on Windows or Clang/GCC elsewhere.

```sh
bun install
bun run build      # build/Release/device_key.node (Windows) or build/device_key.node
bun test
```

## Tests and hardware

GitHub-hosted runners have no TPM and no Secure Enclave. CI builds every target and runs the tests that need no
hardware (encoding against Node's crypto, argument checks, the binding loading). Each backend's own CI test runs
against a stand-in: `swtpm` on Linux, the software key provider through the same NCrypt calls on Windows, a keychain
key on macOS. Before each release the hardware paths are tested on a real Windows 11 TPM, an Apple silicon Mac and
a Linux machine with a TPM.

## Releasing

Nobody types a version. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org): on every
push to `main`, semantic-release reads them since the last tag and decides whether a release is due and which version
(`feat` → minor, `fix` / `perf` → patch, `!` or a `BREAKING CHANGE:` footer → major). `package.json` keeps a
placeholder version. When a release is due, the release workflow builds all five targets,
makes one package per platform (`scripts/platform-packages.mjs`, which also writes the main package's
`optionalDependencies` at the exact version), attests the binaries and tarballs, publishes the platform packages and
then the main one to GitHub Packages and to npmjs (`scripts/publish.sh`; a version already published is skipped, so a
failed release can be re-run), and only then tags and creates a GitHub release with the notes, binaries, tarballs and
checksums, so a failed publish leaves no tag and the run can be repeated.

npmjs is published through **trusted publishing**: npm checks the workflow's GitHub OIDC identity, no token is stored,
and every version carries provenance. Each of the six packages has `Paratco/device-key`, `release.yml` as its trusted
publisher. The `NPM_TOKEN` secret exists only to create the packages on the very first release.
