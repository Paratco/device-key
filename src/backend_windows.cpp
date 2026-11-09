// Windows: CNG NCrypt with the Microsoft Platform Crypto Provider, so the key is created and used inside the TPM 2.0
// and cannot be exported. Keys belong to the Windows account that creates them (no admin rights needed); a shared
// control-room PC with one Windows account is one device.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <cstdio>
#include <stdexcept>

#include "backend.hpp"

namespace device_key {

    namespace {

        // DEVICE_KEY_SOFTWARE_PROVIDER exists only for CI test builds (hosted runners have no TPM): the software key
        // storage provider through exactly the same calls. Release builds never define it.
#ifdef DEVICE_KEY_SOFTWARE_PROVIDER
        constexpr const wchar_t *kProvider = MS_KEY_STORAGE_PROVIDER;
#else
        constexpr const wchar_t *kProvider = MS_PLATFORM_CRYPTO_PROVIDER;
#endif

        // Prefixed so our keys never collide with another application's in the same key store.
        std::wstring ContainerName(const std::string &name) {
            // Names are checked to be plain ASCII before they get here (addon.cpp), so widening byte by byte is exact.
            return L"paratco-device-key." + std::wstring(name.begin(), name.end());
        }

        class Handle {
        public:
            Handle() = default;
            Handle(const Handle &) = delete;
            Handle &operator=(const Handle &) = delete;
            ~Handle() {
                if (handle_ != 0) NCryptFreeObject(handle_);
            }

            NCRYPT_HANDLE *Out() { return &handle_; }
            NCRYPT_HANDLE Get() const { return handle_; }

            // After NCryptDeleteKey succeeds the handle is already freed.
            void Forget() { handle_ = 0; }

        private:
            NCRYPT_HANDLE handle_ = 0;
        };

        void Check(const SECURITY_STATUS status, const char *call, const std::string &name) {
            if (status == ERROR_SUCCESS) return;
            if (status == NTE_BAD_KEYSET) throw KeyError::NotFound(name);
            if (status == NTE_EXISTS) throw KeyError::Exists(name);

            char code[16];
            std::snprintf(code, sizeof(code), "0x%08lX", static_cast<unsigned long>(status));
            throw std::runtime_error(std::string("device-key: ") + call + " failed (" + code + ")");
        }

        void OpenProvider(Handle &provider) {
            Check(NCryptOpenStorageProvider(reinterpret_cast<NCRYPT_PROV_HANDLE *>(provider.Out()), kProvider, 0),
                  "NCryptOpenStorageProvider", "");
        }

        void OpenKey(const Handle &provider, Handle &key, const std::string &name) {
            Check(NCryptOpenKey(provider.Get(), reinterpret_cast<NCRYPT_KEY_HANDLE *>(key.Out()),
                                ContainerName(name).c_str(), 0, NCRYPT_SILENT_FLAG),
                  "NCryptOpenKey", name);
        }

        void SetDword(const Handle &key, const wchar_t *property, DWORD value, const std::string &name) {
            Check(NCryptSetProperty(key.Get(), property, reinterpret_cast<PBYTE>(&value), sizeof(value),
                                    NCRYPT_PERSIST_FLAG | NCRYPT_SILENT_FLAG),
                  "NCryptSetProperty", name);
        }

    }

    bool Available() {
        Handle provider;
        if (NCryptOpenStorageProvider(reinterpret_cast<NCRYPT_PROV_HANDLE *>(provider.Out()), kProvider, 0)
            != ERROR_SUCCESS) {
            return false;
        }

        // A TPM 1.2, or a TPM without ECC, opens the provider but cannot hold a P-256 key.
        return NCryptIsAlgSupported(provider.Get(), BCRYPT_ECDSA_P256_ALGORITHM, 0) == ERROR_SUCCESS;
    }

    void CreateKey(const std::string &name) {
        Handle provider;
        OpenProvider(provider);

        // No NCRYPT_OVERWRITE_KEY_FLAG: an existing key with this name fails with NTE_EXISTS instead of being replaced.
        Handle key;
        Check(NCryptCreatePersistedKey(provider.Get(), reinterpret_cast<NCRYPT_KEY_HANDLE *>(key.Out()),
                                       BCRYPT_ECDSA_P256_ALGORITHM, ContainerName(name).c_str(), 0, 0),
              "NCryptCreatePersistedKey", name);

        // Explicit, not left to the provider's defaults: never exportable, signing only.
        SetDword(key, NCRYPT_EXPORT_POLICY_PROPERTY, 0, name);
        SetDword(key, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_SIGNING_FLAG, name);

        Check(NCryptFinalizeKey(key.Get(), NCRYPT_SILENT_FLAG), "NCryptFinalizeKey", name);
    }

    std::vector<uint8_t> PublicPoint(const std::string &name) {
        Handle provider;
        OpenProvider(provider);
        Handle key;
        OpenKey(provider, key, name);

        DWORD size = 0;
        Check(NCryptExportKey(key.Get(), 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &size, NCRYPT_SILENT_FLAG),
              "NCryptExportKey", name);
        std::vector<uint8_t> blob(size);
        Check(NCryptExportKey(key.Get(), 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), size, &size,
                              NCRYPT_SILENT_FLAG),
              "NCryptExportKey", name);

        // BCRYPT_ECCKEY_BLOB header, then X and Y, 32 bytes each for P-256.
        const auto *header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB *>(blob.data());
        if (size != sizeof(BCRYPT_ECCKEY_BLOB) + 64 || header->dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC
            || header->cbKey != 32) {
            throw std::runtime_error("device-key: unexpected public key blob");
        }

        std::vector<uint8_t> point{0x04};
        point.insert(point.end(), blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), blob.end());
        return point;
    }

    std::vector<uint8_t> SignDigest(const std::string &name, const Digest &digest) {
        Handle provider;
        OpenProvider(provider);
        Handle key;
        OpenKey(provider, key, name);

        // CNG returns the raw r || s; the JS side encodes it as DER.
        Digest input = digest;
        std::vector<uint8_t> signature(64);
        DWORD size = 0;
        Check(NCryptSignHash(key.Get(), nullptr, input.data(), static_cast<DWORD>(input.size()), signature.data(),
                             static_cast<DWORD>(signature.size()), &size, NCRYPT_SILENT_FLAG),
              "NCryptSignHash", name);
        if (size != 64) {
            throw std::runtime_error("device-key: unexpected signature length");
        }
        return signature;
    }

    void DeleteKey(const std::string &name) {
        Handle provider;
        OpenProvider(provider);

        Handle key;
        const auto status = NCryptOpenKey(provider.Get(), reinterpret_cast<NCRYPT_KEY_HANDLE *>(key.Out()),
                                          ContainerName(name).c_str(), 0, NCRYPT_SILENT_FLAG);
        if (status == NTE_BAD_KEYSET) return;
        Check(status, "NCryptOpenKey", name);

        // No NCRYPT_SILENT_FLAG here: the Platform Crypto Provider refuses it on delete (NTE_BAD_FLAGS).
        Check(NCryptDeleteKey(key.Get(), 0), "NCryptDeleteKey", name);
        key.Forget();
    }

}
