// CNG NCrypt with the Microsoft Platform Crypto Provider (TPM 2.0), machine key.
//
// Not built yet: tracked in Paratco/frs#534 (section 3a). Until then the backend reports itself unavailable and
// every key operation fails, so a caller can never mistake it for a working key store.

#include <stdexcept>

#include "backend.hpp"

namespace device_key {

    namespace {
        [[noreturn]] void NotBuilt() {
            throw std::runtime_error("device-key: the windows backend is not built yet");
        }
    }

    bool Available() { return false; }

    void CreateKey(const std::string &) { NotBuilt(); }

    std::vector<uint8_t> PublicPoint(const std::string &) { NotBuilt(); }

    std::vector<uint8_t> SignDigest(const std::string &, const Digest &) { NotBuilt(); }

    void DeleteKey(const std::string &) { NotBuilt(); }

}
