// Linux: tpm2-tss ESAPI. Each key is an ECC P-256 signing key, created inside the TPM 2.0 under the owner hierarchy's
// primary storage key and never exportable (fixedTPM). The TPM hands back the key wrapped by that primary key; the
// wrapped blob is kept in a file in the user's home, so keys belong to the Linux account that creates them, like on
// Windows. The blob is useless off this TPM. The primary key is derived again from the TPM's seed on every call
// (same template, same key), so nothing is left persistent in the TPM.
//
// Talks to /dev/tpmrm0 (the kernel's resource manager), which is owned by the tss group: the process user must be
// in it.

#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>

#include "backend.hpp"

namespace device_key {

    namespace {

        // DEVICE_KEY_SOFTWARE_PROVIDER exists only for CI test builds (hosted runners have no TPM): swtpm on
        // localhost:2321 through exactly the same calls. Release builds never define it, and name the device
        // explicitly: tpm2-tss's default TCTI list would fall back to a software TPM when there is no device.
#ifdef DEVICE_KEY_SOFTWARE_PROVIDER
        constexpr const char *kTcti = "swtpm";
#else
        constexpr const char *kTcti = "device:/dev/tpmrm0";
#endif

        void Check(const TSS2_RC rc, const char *call) {
            if (rc == TSS2_RC_SUCCESS) return;
            char code[16];
            std::snprintf(code, sizeof(code), "0x%08X", rc);
            throw std::runtime_error(std::string("device-key: ") + call + " failed (" + code + ")");
        }

        // One connection to the TPM, closed with everything loaded through it.
        class Tpm {
        public:
            Tpm() {
                Check(Tss2_TctiLdr_Initialize(kTcti, &tcti_), "Tss2_TctiLdr_Initialize");
                const auto rc = Esys_Initialize(&ctx_, tcti_, nullptr);
                if (rc != TSS2_RC_SUCCESS) {
                    Tss2_TctiLdr_Finalize(&tcti_);
                    Check(rc, "Esys_Initialize");
                }
            }
            Tpm(const Tpm &) = delete;
            Tpm &operator=(const Tpm &) = delete;
            ~Tpm() {
                for (const auto handle : loaded_) Esys_FlushContext(ctx_, handle);
                Esys_Finalize(&ctx_);
                Tss2_TctiLdr_Finalize(&tcti_);
            }

            ESYS_CONTEXT *Ctx() const { return ctx_; }

            // Transient objects are flushed when this connection closes.
            ESYS_TR Track(const ESYS_TR handle) {
                loaded_.push_back(handle);
                return handle;
            }

        private:
            TSS2_TCTI_CONTEXT *tcti_ = nullptr;
            ESYS_CONTEXT *ctx_ = nullptr;
            std::vector<ESYS_TR> loaded_;
        };

        // An ESAPI output, freed with Esys_Free.
        template <typename T> struct Out {
            T *ptr = nullptr;
            Out() = default;
            Out(const Out &) = delete;
            Out &operator=(const Out &) = delete;
            ~Out() { Esys_Free(ptr); }
        };

        // The TCG storage primary key template (ECC P-256, AES-128-CFB): the owner hierarchy always derives the same
        // key from it.
        ESYS_TR CreatePrimary(Tpm &tpm) {
            TPM2B_PUBLIC in{};
            auto &area = in.publicArea;
            area.type = TPM2_ALG_ECC;
            area.nameAlg = TPM2_ALG_SHA256;
            area.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN
                | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
            auto &ecc = area.parameters.eccDetail;
            ecc.symmetric.algorithm = TPM2_ALG_AES;
            ecc.symmetric.keyBits.aes = 128;
            ecc.symmetric.mode.aes = TPM2_ALG_CFB;
            ecc.scheme.scheme = TPM2_ALG_NULL;
            ecc.curveID = TPM2_ECC_NIST_P256;
            ecc.kdf.scheme = TPM2_ALG_NULL;
            area.unique.ecc.x.size = 32;
            area.unique.ecc.y.size = 32;

            const TPM2B_SENSITIVE_CREATE sensitive{};
            const TPM2B_DATA outside{};
            const TPML_PCR_SELECTION pcrs{};
            ESYS_TR primary = ESYS_TR_NONE;
            Check(Esys_CreatePrimary(tpm.Ctx(), ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                     &sensitive, &in, &outside, &pcrs, &primary, nullptr, nullptr, nullptr, nullptr),
                  "Esys_CreatePrimary");
            return tpm.Track(primary);
        }

        TPMS_ECC_PARMS SigningParms() {
            TPMS_ECC_PARMS ecc{};
            ecc.symmetric.algorithm = TPM2_ALG_NULL;
            ecc.scheme.scheme = TPM2_ALG_ECDSA;
            ecc.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
            ecc.curveID = TPM2_ECC_NIST_P256;
            ecc.kdf.scheme = TPM2_ALG_NULL;
            return ecc;
        }

        // ~/.local/share/paratco-device-key (or $XDG_DATA_HOME's), one file per key.
        std::filesystem::path KeyDir() {
            if (const char *xdg = std::getenv("XDG_DATA_HOME"); xdg != nullptr && xdg[0] == '/') {
                return std::filesystem::path(xdg) / "paratco-device-key";
            }
            std::filesystem::path home;
            if (const char *env = std::getenv("HOME"); env != nullptr && env[0] == '/') {
                home = env;
            } else {
                // getpwuid_r, not getpwuid: key operations run on parallel worker threads.
                passwd entry{};
                passwd *found = nullptr;
                std::vector<char> buffer(16384);
                if (getpwuid_r(getuid(), &entry, buffer.data(), buffer.size(), &found) != 0 || found == nullptr
                    || entry.pw_dir == nullptr || entry.pw_dir[0] != '/') {
                    throw std::runtime_error("device-key: no home directory for this user");
                }
                home = entry.pw_dir;
            }
            return home / ".local" / "share" / "paratco-device-key";
        }

        // fsync on a directory persists the names in it: a new or removed key file, a new subdirectory.
        void SyncDir(const std::filesystem::path &dir) {
            const int fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            const bool synced = fd >= 0 && fsync(fd) == 0;
            const int error = errno;
            if (fd >= 0) close(fd);
            if (!synced) throw std::runtime_error(std::string("device-key: cannot sync the key folder: ") + std::strerror(error));
        }

        // Missing folders are made 0700 whatever the umask (as the XDG spec asks), each synced into its parent so a
        // power cut cannot lose it together with the first key.
        void MakeDirs(const std::filesystem::path &dir) {
            if (std::filesystem::is_directory(dir)) return;
            MakeDirs(dir.parent_path());
            if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
                throw std::runtime_error(std::string("device-key: cannot create the key folder: ") + std::strerror(errno));
            }
            SyncDir(dir.parent_path());
        }

        // Names are checked to be plain (addon.cpp), so they are safe as file names.
        std::filesystem::path KeyFile(const std::string &name) { return KeyDir() / (name + ".tpm"); }

        struct Blob {
            TPM2B_PUBLIC pub{};
            TPM2B_PRIVATE priv{};
        };

        Blob ReadBlob(const std::string &name) {
            std::ifstream in(KeyFile(name), std::ios::binary);
            if (!in) throw KeyError::NotFound(name);
            const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(in), {}};

            Blob blob;
            size_t offset = 0;
            if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(bytes.data(), bytes.size(), &offset, &blob.pub) != TSS2_RC_SUCCESS
                || Tss2_MU_TPM2B_PRIVATE_Unmarshal(bytes.data(), bytes.size(), &offset, &blob.priv) != TSS2_RC_SUCCESS
                || offset != bytes.size()) {
                throw std::runtime_error("device-key: the key file for \"" + name + "\" is damaged");
            }
            return blob;
        }

        // Written to a temporary file, then hard-linked into place: link() fails if the name exists, so two creates
        // never both succeed and a crash never leaves a half-written key.
        void WriteBlob(const std::string &name, const std::vector<uint8_t> &bytes) {
            const auto dir = KeyDir();
            MakeDirs(dir);
            std::filesystem::permissions(dir, std::filesystem::perms::owner_all);

            auto tmp = (dir / ".tmp-XXXXXX").string();
            const int fd = mkstemp(tmp.data());
            if (fd < 0) throw std::runtime_error(std::string("device-key: cannot write a key file: ") + std::strerror(errno));
            const bool written = write(fd, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size())
                && fsync(fd) == 0;
            close(fd);

            const int linked = written ? link(tmp.c_str(), KeyFile(name).c_str()) : -1;
            const int error = errno;
            unlink(tmp.c_str());
            if (linked == 0) {
                // The key file's name, not only its content, must survive a power cut.
                SyncDir(dir);
                return;
            }
            if (written && error == EEXIST) throw KeyError::Exists(name);
            throw std::runtime_error(std::string("device-key: cannot write a key file: ") + std::strerror(error));
        }

        void PadTo32(const TPM2B_ECC_PARAMETER &value, std::vector<uint8_t> &out) {
            if (value.size > 32) throw std::runtime_error("device-key: unexpected P-256 value size");
            out.insert(out.end(), 32 - value.size, 0);
            out.insert(out.end(), value.buffer, value.buffer + value.size);
        }

    }

    bool Available() {
        try {
            Tpm tpm;
            // A TPM without ECC P-256 ECDSA answers the connection but cannot hold the key.
            TPMT_PUBLIC_PARMS parms{};
            parms.type = TPM2_ALG_ECC;
            parms.parameters.eccDetail = SigningParms();
            if (Esys_TestParms(tpm.Ctx(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &parms) != TSS2_RC_SUCCESS) {
                return false;
            }
            // An owner password, or a disabled owner hierarchy, refuses the primary key every operation needs.
            CreatePrimary(tpm);
            return true;
        } catch (const std::exception &) {
            // No TPM, no /dev/tpmrm0 access (not in tss), or no libtss2 TCTI: no key store.
            return false;
        }
    }

    void CreateKey(const std::string &name) {
        if (std::filesystem::exists(KeyFile(name))) {
            throw KeyError::Exists(name);
        }

        Tpm tpm;
        const auto primary = CreatePrimary(tpm);

        // Never exportable (fixedTPM, fixedParent), generated inside the TPM, signing only, ECDSA P-256 SHA-256.
        TPM2B_PUBLIC in{};
        auto &area = in.publicArea;
        area.type = TPM2_ALG_ECC;
        area.nameAlg = TPM2_ALG_SHA256;
        area.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN
            | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA | TPMA_OBJECT_SIGN_ENCRYPT;
        area.parameters.eccDetail = SigningParms();

        const TPM2B_SENSITIVE_CREATE sensitive{};
        const TPM2B_DATA outside{};
        const TPML_PCR_SELECTION pcrs{};
        Out<TPM2B_PRIVATE> priv;
        Out<TPM2B_PUBLIC> pub;
        Check(Esys_Create(tpm.Ctx(), primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &in, &outside,
                          &pcrs, &priv.ptr, &pub.ptr, nullptr, nullptr, nullptr),
              "Esys_Create");

        std::vector<uint8_t> bytes(sizeof(TPM2B_PUBLIC) + sizeof(TPM2B_PRIVATE));
        size_t offset = 0;
        Check(Tss2_MU_TPM2B_PUBLIC_Marshal(pub.ptr, bytes.data(), bytes.size(), &offset), "Tss2_MU_TPM2B_PUBLIC_Marshal");
        Check(Tss2_MU_TPM2B_PRIVATE_Marshal(priv.ptr, bytes.data(), bytes.size(), &offset), "Tss2_MU_TPM2B_PRIVATE_Marshal");
        bytes.resize(offset);
        WriteBlob(name, bytes);
    }

    std::vector<uint8_t> PublicPoint(const std::string &name) {
        // The public half is in the blob as the TPM returned it: no TPM call needed.
        const auto blob = ReadBlob(name);
        const auto &area = blob.pub.publicArea;
        if (area.type != TPM2_ALG_ECC || area.parameters.eccDetail.curveID != TPM2_ECC_NIST_P256) {
            throw std::runtime_error("device-key: unexpected public key blob");
        }

        std::vector<uint8_t> point{0x04};
        PadTo32(area.unique.ecc.x, point);
        PadTo32(area.unique.ecc.y, point);
        return point;
    }

    std::vector<uint8_t> SignDigest(const std::string &name, const Digest &digest) {
        const auto blob = ReadBlob(name);

        Tpm tpm;
        const auto primary = CreatePrimary(tpm);
        ESYS_TR key = ESYS_TR_NONE;
        Check(Esys_Load(tpm.Ctx(), primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &blob.priv, &blob.pub, &key),
              "Esys_Load");
        tpm.Track(key);

        TPM2B_DIGEST in{};
        in.size = digest.size();
        std::copy(digest.begin(), digest.end(), in.buffer);
        // The key's own scheme (ECDSA SHA-256). An unrestricted key needs no hash ticket: a NULL one.
        TPMT_SIG_SCHEME scheme{};
        scheme.scheme = TPM2_ALG_NULL;
        TPMT_TK_HASHCHECK ticket{};
        ticket.tag = TPM2_ST_HASHCHECK;
        ticket.hierarchy = TPM2_RH_NULL;

        Out<TPMT_SIGNATURE> signature;
        Check(Esys_Sign(tpm.Ctx(), key, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &in, &scheme, &ticket,
                        &signature.ptr),
              "Esys_Sign");
        if (signature.ptr->sigAlg != TPM2_ALG_ECDSA) throw std::runtime_error("device-key: unexpected signature");

        // r || s, 32 bytes each; the JS side encodes it as DER.
        std::vector<uint8_t> out;
        PadTo32(signature.ptr->signature.ecdsa.signatureR, out);
        PadTo32(signature.ptr->signature.ecdsa.signatureS, out);
        return out;
    }

    void DeleteKey(const std::string &name) {
        // Nothing persists in the TPM: without its wrapped blob the key can never be loaded again.
        std::error_code error;
        const bool removed = std::filesystem::remove(KeyFile(name), error);
        if (error) throw std::runtime_error("device-key: cannot delete \"" + name + "\": " + error.message());
        // So a deleted key cannot come back after a power cut.
        if (removed) SyncDir(KeyDir());
    }

}
