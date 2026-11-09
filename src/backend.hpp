#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

// One P-256 signing key per name, held by the platform's hardware (TPM 2.0 or Secure Enclave) and never exported.
// Each OS implements these in its own backend_*.cpp. Every call may block on the hardware: the addon runs them off
// the JS thread.
namespace device_key {

    using Digest = std::array<uint8_t, 32>;

    // A failure callers act on: it reaches JS with a `code`, so they never match on the message.
    class KeyError : public std::runtime_error {
    public:
        KeyError(const char *code, const std::string &message) : std::runtime_error(message), code_(code) {}

        const char *Code() const { return code_; }

        static KeyError NotFound(const std::string &name) {
            return {"KEY_NOT_FOUND", "device-key: no key named \"" + name + "\""};
        }

        static KeyError Exists(const std::string &name) {
            return {"KEY_EXISTS", "device-key: a key named \"" + name + "\" already exists"};
        }

    private:
        const char *code_;
    };

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
