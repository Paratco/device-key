#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// One P-256 signing key per name, held by the platform's hardware (TPM 2.0 or Secure Enclave) and never exported.
// Each OS implements these in its own backend_*.cpp. Every call may block on the hardware: the addon runs them off
// the JS thread.
namespace device_key {

    using Digest = std::array<uint8_t, 32>;

    // Whether this machine can hold a key at all (TPM present and usable, Secure Enclave present).
    bool Available();

    // Creates the key. Fails if a key with this name already exists: replacing it silently would orphan an enrollment.
    void CreateKey(const std::string &name);

    // The public key as an uncompressed point: 0x04 || X || Y, 65 bytes.
    std::vector<uint8_t> PublicPoint(const std::string &name);

    // ECDSA over a SHA-256 digest, as raw r || s, 64 bytes (the JS side encodes DER).
    std::vector<uint8_t> SignDigest(const std::string &name, const Digest &digest);

    // Deletes the key. Not an error when it does not exist.
    void DeleteKey(const std::string &name);

}
