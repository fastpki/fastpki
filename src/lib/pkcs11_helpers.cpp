// PKCS#11 slot enumeration via dlopen/dlsym.
// Defines only the minimal PKCS#11 types needed — no system header dependency.

#include "pki/pkcs11_helpers.hpp"

#include <cctype>
#include <cerrno>
#include <cstring>
#include <map>
#include <mutex>
#include <vector>
#include <cstdio>
#include <dlfcn.h>
#include <fstream>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// Decoding an EC key's CKA_EC_PARAMS (a named-curve OID) into a curve name and a
// bit length. The OID table and the curve degrees are OpenSSL's; hand-rolling either
// would be a second copy of a table that already exists and already ships.
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>

namespace {

// ── Minimal PKCS#11 types (only what C_GetSlotList / C_GetTokenInfo need) ────
using CK_SLOT_ID  = unsigned long;
using CK_ULONG    = unsigned long;

struct CK_VERSION { unsigned char major; unsigned char minor; };

struct CK_TOKEN_INFO {
    char          label[32];
    char          manufacturer[32];
    char          model[16];
    char          serialNumber[16];
    CK_ULONG      flags;
    CK_ULONG      maxSessionCount;
    CK_ULONG      sessionCount;
    CK_ULONG      maxRwSessionCount;
    CK_ULONG      rwSessionCount;
    CK_ULONG      maxPinLen;
    CK_ULONG      minPinLen;
    CK_ULONG      totalPublicMemory;
    CK_ULONG      freePublicMemory;
    CK_ULONG      totalPrivateMemory;
    CK_ULONG      freePrivateMemory;
    CK_VERSION    hardwareVersion;
    CK_VERSION    firmwareVersion;
    char          utcTime[16];
};

// NOTE: CKF_TOKEN_PRESENT (0x1) is a **CK_SLOT_INFO** flag — on CK_TOKEN_INFO.flags
// bit 0x1 means CKF_RNG, so masking it here tested the wrong thing entirely (and was
// redundant: C_GetTokenInfo already fails with CKR_TOKEN_NOT_PRESENT for an empty
// slot). What we actually want is a token that has been INITIALIZED: SoftHSM always
// exposes a spare uninitialized slot, and listing it puts a blank, unusable entry in
// the console's HSM slot dropdown that then fails at CA-create time.
constexpr unsigned long CKF_TOKEN_INITIALIZED = 0x00000400;

// CK function pointer types (we only need a handful).
using t_C_Initialize    = int (*)(void*);

// The subset of CK_C_INITIALIZE_ARGS we need. A module may legitimately refuse
// C_Initialize(NULL) with CKR_CANT_LOCK when the caller is multi-threaded, so the
// locking flag has to be passed explicitly.
struct CkInitArgs {
    void* CreateMutex{nullptr};
    void* DestroyMutex{nullptr};
    void* LockMutex{nullptr};
    void* UnlockMutex{nullptr};
    unsigned long flags{0};
    void* pReserved{nullptr};
};
constexpr unsigned long CKF_OS_LOCKING_OK_ = 0x00000002UL;

// PKCS#11 §5.2: a module is only REQUIRED to export C_GetFunctionList. Everything else
// may exist solely as a pointer in the table it returns — and p11-kit-client.so is
// exactly such a module, which is why dlsym("C_GetSlotList") found nothing and the
// console concluded there was no HSM.
//
// CK_VERSION is two bytes followed by pointers, so the natural padding here matches the
// layout the module was compiled with.
//
// ⚠️ This struct is POSITIONAL — the ABI fixes the order and there is no name lookup.
// Every entry down to the one we want must be declared, in the exact PKCS#11 v2.40
// order, or the pointer we call is some other function. Count, do not guess. It runs to
// the END of the table (C_DeriveKey) because key replication needs C_GenerateKeyPair,
// C_WrapKey, C_UnwrapKey and C_DeriveKey, which are the last four entries but one.
struct CkFunctionList {
    unsigned char major, minor;
    void* C_Initialize;
    void* C_Finalize;
    void* C_GetInfo;
    void* C_GetFunctionList;
    void* C_GetSlotList;
    void* C_GetSlotInfo;
    void* C_GetTokenInfo;
    void* C_GetMechanismList;   // §5.2 order: immediately after C_GetTokenInfo
    void* C_GetMechanismInfo;
    void* C_InitToken;
    void* C_InitPIN;
    void* C_SetPIN;
    void* C_OpenSession;
    void* C_CloseSession;
    void* C_CloseAllSessions;
    void* C_GetSessionInfo;
    void* C_GetOperationState;
    void* C_SetOperationState;
    void* C_Login;
    void* C_Logout;
    void* C_CreateObject;
    void* C_CopyObject;
    void* C_DestroyObject;      // undo a mint whose certificate never signed
    void* C_GetObjectSize;
    void* C_GetAttributeValue;
    void* C_SetAttributeValue;
    void* C_FindObjectsInit;
    void* C_FindObjects;
    void* C_FindObjectsFinal;
    // From here to the end: the entries key replication needs, and every entry in between
    // because the table is positional. Names are the v2.40 spelling; the ones we never
    // call exist only to hold their slot.
    void* C_EncryptInit;
    void* C_Encrypt;
    void* C_EncryptUpdate;
    void* C_EncryptFinal;
    void* C_DecryptInit;
    void* C_Decrypt;
    void* C_DecryptUpdate;
    void* C_DecryptFinal;
    void* C_DigestInit;
    void* C_Digest;
    void* C_DigestUpdate;
    void* C_DigestKey;
    void* C_DigestFinal;
    void* C_SignInit;
    void* C_Sign;
    void* C_SignUpdate;
    void* C_SignFinal;
    void* C_SignRecoverInit;
    void* C_SignRecover;
    void* C_VerifyInit;
    void* C_Verify;
    void* C_VerifyUpdate;
    void* C_VerifyFinal;
    void* C_VerifyRecoverInit;
    void* C_VerifyRecover;
    void* C_DigestEncryptUpdate;
    void* C_DecryptDigestUpdate;
    void* C_SignEncryptUpdate;
    void* C_DecryptVerifyUpdate;
    void* C_GenerateKey;
    void* C_GenerateKeyPair;
    void* C_WrapKey;
    void* C_UnwrapKey;
    void* C_DeriveKey;
};
using t_C_GetFunctionList = int (*)(CkFunctionList**);
using t_C_GetSlotList   = int (*)(unsigned char, CK_SLOT_ID*, CK_ULONG*);
using t_C_GetTokenInfo  = int (*)(CK_SLOT_ID, CK_TOKEN_INFO*);
using t_C_GetMechanismList = int (*)(CK_SLOT_ID, unsigned long*, CK_ULONG*);
using t_C_Finalize      = int (*)(void*);

// ── the object-removal subset ───────────────────────────────────────────────
using CK_SESSION_HANDLE = unsigned long;
using CK_OBJECT_HANDLE  = unsigned long;

struct CK_ATTRIBUTE {
    CK_ULONG type;
    void*    pValue;
    CK_ULONG ulValueLen;
};

using t_C_OpenSession      = int (*)(CK_SLOT_ID, CK_ULONG, void*, void*, CK_SESSION_HANDLE*);
using t_C_CloseSession     = int (*)(CK_SESSION_HANDLE);
using t_C_Login            = int (*)(CK_SESSION_HANDLE, CK_ULONG, const unsigned char*, CK_ULONG);
using t_C_Logout           = int (*)(CK_SESSION_HANDLE);
using t_C_DestroyObject    = int (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
using t_C_FindObjectsInit  = int (*)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
using t_C_FindObjects      = int (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
using t_C_FindObjectsFinal = int (*)(CK_SESSION_HANDLE);
using t_C_GetAttributeValue = int (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);

constexpr CK_ULONG CKA_LABEL_       = 0x00000003UL;
constexpr CK_ULONG CKA_ID_          = 0x00000102UL;
// The attributes an operator needs to recognise an object they are looking at.
constexpr CK_ULONG CKA_CLASS_        = 0x00000000UL;
constexpr CK_ULONG CKA_KEY_TYPE_     = 0x00000100UL;
constexpr CK_ULONG CKA_MODULUS_BITS_ = 0x00000121UL;
// ⚠️ MEASURED against SoftHSM 2, not assumed: an EC key's curve IS in the token, as
// CKA_EC_PARAMS on the PUBLIC key object —
//     EC Params: 06:08:2a:86:48:ce:3d:03:01:07 ("prime256v1" OID 1.2.840.10045.3.1.7)
// — and the RSA modulus is on both objects. The console reported "size unknown" because
// this file asked for CKA_MODULUS_BITS and nothing else, and CKA_MODULUS_BITS is an RSA
// attribute that SoftHSM does not put on a private key at all. So the question raised on
// The obvious question — why not store curve or bit length in the DB as well — has a better answer than a
// column: we never asked. A DB column would also only describe keys WE
// minted, and would go stale against the token, which §3f is precisely about.
constexpr CK_ULONG CKA_MODULUS_      = 0x00000120UL;
constexpr CK_ULONG CKA_EC_PARAMS_    = 0x00000180UL;
constexpr CK_ULONG CKO_CERTIFICATE_  = 1UL;
constexpr CK_ULONG CKO_PUBLIC_KEY_   = 2UL;
constexpr CK_ULONG CKO_PRIVATE_KEY_  = 3UL;
constexpr CK_ULONG CKO_SECRET_KEY_   = 4UL;
// ⚠️ CKK (key type) and CKM (mechanism) are SEPARATE PKCS#11 number spaces, and the same
// value means different things in each. CKK_ML_DSA was set to 0x1C here — which is the
// value of CKM_ML_DSA_KEY_PAIR_GEN, and in CKK space is CKK_BATON. An ML-DSA key reports
// 0x4A, matched nothing, and the HSM keys page showed "-" for its type
// (ML keys were displayed with '-' in the type column).
// Values checked against p11-kit's pkcs11.h, not inferred.
constexpr CK_ULONG CKK_RSA_          = 0x00000000UL;
constexpr CK_ULONG CKK_EC_           = 0x00000003UL;
constexpr CK_ULONG CKK_AES_          = 0x0000001FUL;
constexpr CK_ULONG CKK_EC_EDWARDS_   = 0x00000040UL;
constexpr CK_ULONG CKK_EC_MONTGOMERY_= 0x00000041UL;
constexpr CK_ULONG CKK_ML_KEM_       = 0x00000049UL;
constexpr CK_ULONG CKK_ML_DSA_       = 0x0000004AUL;
constexpr CK_ULONG CKU_USER_        = 1UL;
constexpr CK_ULONG CKF_RW_SESSION_  = 0x00000002UL;
constexpr CK_ULONG CKF_SERIAL_SESSION_ = 0x00000004UL;
// Re-initialising a module the OpenSSL provider already opened is normal here, not an
// error: this process reaches the same module twice, by two different routes.
constexpr int CKR_CRYPTOKI_ALREADY_INITIALIZED_ = 0x00000191;
constexpr int CKR_USER_ALREADY_LOGGED_IN_       = 0x00000100;

// The keygen mechanisms we can map to an algorithm the CA form offers. Anything else a
// token advertises is real but not something we can ask for, so it is not listed.
// Values are from PKCS#11 (3.2 for the ML-DSA pair) rather than a header, because the
// module's own headers are not ours and these numbers are the wire format.
constexpr unsigned long CKM_RSA_PKCS_KEY_PAIR_GEN_ = 0x00000000UL;
constexpr unsigned long CKM_ML_DSA_KEY_PAIR_GEN_   = 0x0000001CUL;
constexpr unsigned long CKM_EC_KEY_PAIR_GEN_       = 0x00001040UL;

// ⚠️ The guard for that bug, and it needs no token to run. A key TYPE and the
// MECHANISM that generates it are different numbers in different PKCS#11 spaces; writing
// the mechanism into the key-type constant is what made every ML-DSA key display as "-".
// These two must never be equal again, and this fails the build rather than a test run.
static_assert(CKK_ML_DSA_ != CKM_ML_DSA_KEY_PAIR_GEN_,
              "CKK_ML_DSA is a KEY TYPE (0x4A); CKM_ML_DSA_KEY_PAIR_GEN is a MECHANISM "
              "(0x1C). If these are equal, a mechanism value has been pasted into the "
              "key-type table again and ML-DSA keys will show no type.");
static_assert(CKK_EC_ != CKM_EC_KEY_PAIR_GEN_, "same confusion, EC");
constexpr unsigned long CKM_EC_EDWARDS_KEY_PAIR_GEN_ = 0x00001055UL;

constexpr int CKR_OK = 0;

// ── key replication: attributes, mechanisms and the return codes worth naming ───────
constexpr CK_ULONG CKA_TOKEN_        = 0x00000001UL;
constexpr CK_ULONG CKA_PRIVATE_      = 0x00000002UL;
constexpr CK_ULONG CKA_SENSITIVE_    = 0x00000103UL;
constexpr CK_ULONG CKA_WRAP_         = 0x00000106UL;
constexpr CK_ULONG CKA_UNWRAP_       = 0x00000107UL;
constexpr CK_ULONG CKA_SIGN_         = 0x00000108UL;
constexpr CK_ULONG CKA_VERIFY_       = 0x0000010AUL;
constexpr CK_ULONG CKA_DERIVE_       = 0x0000010CUL;
constexpr CK_ULONG CKA_PUBLIC_EXPONENT_ = 0x00000122UL;
constexpr CK_ULONG CKA_VALUE_LEN_    = 0x00000161UL;
constexpr CK_ULONG CKA_EXTRACTABLE_  = 0x00000162UL;
constexpr CK_ULONG CKA_EC_POINT_     = 0x00000181UL;
constexpr CK_ULONG CKA_VALUE_        = 0x00000011UL;
constexpr CK_ULONG CKA_PARAMETER_SET_ = 0x0000061DUL;
constexpr CK_ULONG CKA_ALLOWED_MECHANISMS_ = 0x40000600UL;
constexpr CK_ULONG CKP_ML_DSA_44_    = 0x00000001UL;
constexpr CK_ULONG CKP_ML_DSA_65_    = 0x00000002UL;
constexpr CK_ULONG CKP_ML_DSA_87_    = 0x00000003UL;

// ⚠️ THE LIST THE PKCS#11 PROVIDER WRITES ON AN RSA-PSS KEY, measured in the shipped image
// (`pkcs11-tool --list-objects` on a key minted by `openssl genpkey -algorithm RSA-PSS`).
// An RSA-PSS key is CKK_RSA plus this restriction, and the provider reports a key loaded by
// URI as RSA-PSS because of it — so a replicable PSS key carries exactly the same list, or
// it loads as plain RSA and is signed with PKCS#1 v1.5, which the certificate forbids.
// Order: RSA-PKCS-PSS, SHA1, SHA256, SHA384, SHA512, SHA224, SHA3-256, SHA3-384, SHA3-512,
// SHA3-224 — each the *_RSA_PKCS_PSS mechanism.
constexpr CK_ULONG kRsaPssMechs[] = {0x0D, 0x0E, 0x43, 0x44, 0x45, 0x47, 0x63, 0x64, 0x65, 0x67};

constexpr unsigned long CKM_AES_KEY_WRAP_PAD_ = 0x0000210AUL;
constexpr unsigned long CKM_ECDH1_DERIVE_     = 0x00001050UL;
constexpr unsigned long CKD_NULL_             = 0x00000001UL;

// ⚠️ THESE THREE ARE THE ONLY FAILURES AN OPERATOR CAN ACT ON, so they are named rather
// than reported as a bare rc. All three mean the same thing in practice — this key was
// generated so that it can never leave its token — and the fix is not a retry.
constexpr int CKR_KEY_NOT_WRAPPABLE_   = 0x00000069;
constexpr int CKR_KEY_UNEXTRACTABLE_   = 0x0000006A;
constexpr int CKR_WRAPPING_KEY_HANDLE_INVALID_ = 0x00000113;

// The wrapped-key sizes we are willing to allocate for. An RSA-4096 PKCS#8 private key
// wraps to a little over 2.4 KB; the ceiling is generous rather than tight because the
// only cost of over-allocating is a page, and C_WrapKey's two-call form is asked for the
// exact length first anyway.
constexpr size_t kMaxWrappedKey = 65536;

using t_C_CreateObject    = int (*)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);
using t_C_GenerateKey     = int (*)(CK_SESSION_HANDLE, void*, CK_ATTRIBUTE*, CK_ULONG,
                                    CK_OBJECT_HANDLE*);
using t_C_GenerateKeyPair = int (*)(CK_SESSION_HANDLE, void*, CK_ATTRIBUTE*, CK_ULONG,
                                    CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*,
                                    CK_OBJECT_HANDLE*);
using t_C_WrapKey         = int (*)(CK_SESSION_HANDLE, void*, CK_OBJECT_HANDLE,
                                    CK_OBJECT_HANDLE, unsigned char*, CK_ULONG*);
using t_C_UnwrapKey       = int (*)(CK_SESSION_HANDLE, void*, CK_OBJECT_HANDLE,
                                    const unsigned char*, CK_ULONG, CK_ATTRIBUTE*, CK_ULONG,
                                    CK_OBJECT_HANDLE*);
using t_C_DeriveKey       = int (*)(CK_SESSION_HANDLE, void*, CK_OBJECT_HANDLE,
                                    CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*);

struct CK_MECHANISM {
    CK_ULONG mechanism;
    void*    pParameter;
    CK_ULONG ulParameterLen;
};

// ⚠️ THE PUBLIC POINT GOES IN pPublicData, NOT pSharedData. Both are pointer+length pairs
// in the same struct, and swapping them derives a key from nothing rather than failing —
// so both ends would "succeed" and produce different AES keys, and the only symptom would
// be an unwrap that reports corrupt data.
struct CK_ECDH1_DERIVE_PARAMS {
    CK_ULONG        kdf;
    CK_ULONG        ulSharedDataLen;
    unsigned char*  pSharedData;
    CK_ULONG        ulPublicDataLen;
    unsigned char*  pPublicData;
};

// ⚠️ ONE MODULE HANDLE PER PROCESS, OPENED ONCE AND NEVER CLOSED — because a fresh
// dlopen + C_Initialize on every call LEAKS, and the leak is fatal to the machine rather
// than to the call.
//
// With SoftHSM the module reached here is p11-kit-client.so, and C_Initialize is what
// connects to p11-kit-server; the server forks a p11-kit-remote per connection. The
// cleanup that would close it is C_Finalize, and this file may never call that: the
// OpenSSL pkcs11 provider holds the same module open in the same process, so finalising
// tears down the sessions this process signs with (see the comments at the two call
// sites). dlclose does not help either — the provider's reference keeps the library
// loaded and the connection open.
//
// So every caller that opened its own copy left a p11-kit-remote behind. Measured: the
// console's node report lists the token once a minute, and an otherwise idle server grew
// one process per minute — 126 of them in two hours, ~1.4 MB each, until the token server
// hit its process ceiling and every request that needed a session blocked for ever.
//
// Initialising once per process removes the growth without finalising anything: the
// handle and its connection live exactly as long as the provider's, and each call opens
// and closes only a SESSION, which is what sessions are for.
struct SharedModule { void* handle{nullptr}; CkFunctionList* fl{nullptr}; };
std::mutex shared_modules_mu;
std::map<std::string, SharedModule> shared_modules;

// Returns the module's function list, opening and initialising it on first use. nullptr on
// failure, with `err` set. Never closes anything.
CkFunctionList* shared_module(const std::filesystem::path& module, std::string& err) {
    const std::string key = module.string();
    std::lock_guard<std::mutex> lk(shared_modules_mu);
    auto it = shared_modules.find(key);
    if (it != shared_modules.end()) return it->second.fl;

    void* h = dlopen(key.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!h) { const char* e = dlerror(); err = std::string("dlopen: ") + (e ? e : "failed"); return nullptr; }

    CkFunctionList* fl = nullptr;
    auto gfl = reinterpret_cast<t_C_GetFunctionList>(dlsym(h, "C_GetFunctionList"));
    if (!gfl || gfl(&fl) != CKR_OK || !fl) {
        err = "the module offers no C_GetFunctionList";
        dlclose(h);            // nothing was initialised, so nothing is open to keep
        return nullptr;
    }
    if (auto init = reinterpret_cast<t_C_Initialize>(fl->C_Initialize)) {
        CkInitArgs args; args.flags = CKF_OS_LOCKING_OK_;
        const int rc = init(&args);
        // ALREADY_INITIALIZED is the ordinary answer when the OpenSSL provider got here
        // first, and it means the module is usable — not that anything went wrong.
        if (rc != CKR_OK && rc != CKR_CRYPTOKI_ALREADY_INITIALIZED_) {
            err = "C_Initialize failed (rc=" + std::to_string(rc) + ")";
            dlclose(h);
            return nullptr;
        }
    }
    shared_modules.emplace(key, SharedModule{h, fl});
    return fl;
}

// Trim trailing spaces from a fixed-length PKCS#11 char array.
std::string trim_label(const char* raw, size_t max) {
    std::string s(raw, strnlen(raw, max));
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

// Algorithm names come from a browser form on one side and from a C++ constant on the
// other, so `ML-DSA-44` and `ml-dsa-44` have to mean the same thing.
bool ieq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
    return true;
}

// RFC 7512 permits percent-encoding in attribute values, and a token label with a
// space in it is ordinary. Malformed escapes are left as written rather than dropped —
// the result is only ever compared against a label, so a wrong guess must not silently
// become a right one.
std::string pct_decode(const std::string& in) {
    std::string out; out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size() &&
            std::isxdigit((unsigned char)in[i+1]) && std::isxdigit((unsigned char)in[i+2])) {
            out += static_cast<char>(std::stoi(in.substr(i + 1, 2), nullptr, 16));
            i += 2;
        } else out += in[i];
    }
    return out;
}

} // namespace

namespace pki {

// One table, two callers: the slots API renders it as JSON for the console's dropdowns
// and the pre-flight below compares against it. A second copy of this mapping would be
// a second chance to disagree about what a token can do — and the two would disagree in
// the worst possible way, by offering an algorithm the pre-flight then refuses.
std::vector<std::string> pkcs11_slot_algorithms(const Pkcs11Slot& slot) {
    std::vector<std::string> out;
    for (unsigned long m : slot.keygen_mechanisms) {
        switch (m) {
            // One RSA keygen mechanism, two signature schemes over the same key.
            case CKM_RSA_PKCS_KEY_PAIR_GEN_:     out.push_back("rsa");
                                                 out.push_back("rsa-pss");   break;
            case CKM_EC_KEY_PAIR_GEN_:           out.push_back("ec");        break;
            // Both Edwards curves come from ONE mechanism — the curve is a keygen
            // argument (CKA_EC_PARAMS), exactly as the parameter set is for ML-DSA below.
            // Listing only ed25519 made pkcs11_keygen_refusal() reject "ed448" on every
            // token, so the console offering Ed448 produced a guaranteed 400 — the option
            // existed and could never be used. tests/hsm_helpers.sh mints ec:edwards448
            // through this very token and expects an ED448 key back.
            case CKM_EC_EDWARDS_KEY_PAIR_GEN_:   out.push_back("ed25519");
                                                 out.push_back("ed448");     break;
            // The parameter set is a keygen argument, not a separate mechanism.
            case CKM_ML_DSA_KEY_PAIR_GEN_:       out.push_back("ML-DSA-44");
                                                 out.push_back("ML-DSA-65");
                                                 out.push_back("ML-DSA-87"); break;
            default: break;
        }
    }
    return out;
}

std::string pkcs11_uri_attr(const std::string& uri, const std::string& name) {
    if (uri.rfind("pkcs11:", 0) != 0) return {};
    std::string path = uri.substr(7);
    const auto q = path.find('?');
    if (q != std::string::npos) path.resize(q);   // drop pin-source & co.
    const std::string want = name + "=";
    for (size_t pos = 0; pos <= path.size(); ) {
        const auto semi = path.find(';', pos);
        const std::string attr = path.substr(pos, semi == std::string::npos ? std::string::npos
                                                                            : semi - pos);
        if (attr.rfind(want, 0) == 0) return pct_decode(attr.substr(want.size()));
        if (semi == std::string::npos) break;
        pos = semi + 1;
    }
    return {};
}


std::string pkcs11_uri_redacted(const std::string& uri) {
    static const std::string needle = "pin-value=";
    auto at = uri.find(needle);
    if (at == std::string::npos) return uri;
    const size_t vstart = at + needle.size();
    const size_t vend = uri.find_first_of(";?&", vstart);   // RFC 7512 separators
    return uri.substr(0, vstart) + "(redacted)" +
           (vend == std::string::npos ? std::string() : uri.substr(vend));
}

std::string pkcs11_uri_token(const std::string& uri) { return pkcs11_uri_attr(uri, "token"); }

std::string pkcs11_resolve_pin(const std::string& uri,
                               const std::filesystem::path& pin_file) {
    // RFC 7512 puts pin-value / pin-source in the QUERY part, after '?', which is exactly
    // the part pkcs11_uri_attr drops. All three spellings are live in this repo: tests
    // write `?pin-value=1234`, the shipped configs use `pin-source`, and the deploy hands
    // services `PKCS11_PIN_FILE` so the PIN never sits in a config value.
    std::string q;
    if (uri.rfind("pkcs11:", 0) == 0) {
        const auto qm = uri.find('?');
        if (qm != std::string::npos) q = uri.substr(qm + 1);
    }
    std::string src;
    for (size_t pos = 0; !q.empty() && pos <= q.size(); ) {
        const auto amp = q.find('&', pos);
        const std::string a = q.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        if (a.rfind("pin-value=", 0) == 0) return pct_decode(a.substr(10));
        if (a.rfind("pin-source=", 0) == 0) src = pct_decode(a.substr(11));
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    const std::filesystem::path p = !src.empty() ? std::filesystem::path(src) : pin_file;
    if (p.empty()) return {};
    std::ifstream f(p);
    if (!f) return {};
    std::string pin;
    std::getline(f, pin);
    // A PIN file written by a shell heredoc carries the trailing newline; the token does
    // not want it as part of the PIN.
    while (!pin.empty() && (pin.back() == '\r' || pin.back() == '\n' || pin.back() == ' '))
        pin.pop_back();
    return pin;
}

std::string pkcs11_keygen_refusal(const Pkcs11Info& info, const std::string& key_uri,
                                  const std::string& algo) {
    if (algo.empty()) return {};
    const std::string token = pkcs11_uri_token(key_uri);
    if (token.empty()) return {};
    const Pkcs11Slot* slot = nullptr;
    for (const auto& s : info.slots)
        if (s.token_label == token) { slot = &s; break; }
    if (!slot) return {};
    const auto have = pkcs11_slot_algorithms(*slot);
    if (have.empty()) return {};
    for (const auto& a : have) if (ieq(a, algo)) return {};

    // Name the algorithm and list the alternatives. The failure this replaces was
    // CKR_TOKEN_NOT_PRESENT from deep inside the provider — a message about slots, for a
    // problem about algorithms, arriving only after a keypair had been minted.
    std::string list;
    for (const auto& a : have) { if (!list.empty()) list += ", "; list += a; }
    return "the token '" + token + "' does not generate " + algo + " keys; it offers " + list;
}

Pkcs11Info pkcs11_enumerate_slots(const std::filesystem::path& module) {
    Pkcs11Info info;
    info.module_path = module.string();
    if (module.empty()) return info;

    void* h = dlopen(module.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        const char* e = dlerror();
        info.error = std::string("cannot load the PKCS#11 module: ") + (e ? e : "dlopen failed");
        return info;
    }

    auto sym = [&](const char* name) -> void* { return dlsym(h, name); };
    auto getList = reinterpret_cast<t_C_GetSlotList>(sym("C_GetSlotList"));
    auto tokInfo = reinterpret_cast<t_C_GetTokenInfo>(sym("C_GetTokenInfo"));
    auto mechList = reinterpret_cast<t_C_GetMechanismList>(sym("C_GetMechanismList"));
    auto init    = reinterpret_cast<t_C_Initialize>(sym("C_Initialize"));

    // Direct symbols are the exception, not the rule. Prefer the function table whenever
    // the module offers one; keep any direct symbols only as the fallback.
    if (auto gfl = reinterpret_cast<t_C_GetFunctionList>(sym("C_GetFunctionList"))) {
        CkFunctionList* fl = nullptr;
        if (gfl(&fl) == CKR_OK && fl) {
            if (fl->C_GetSlotList)  getList = reinterpret_cast<t_C_GetSlotList>(fl->C_GetSlotList);
            if (fl->C_GetTokenInfo) tokInfo = reinterpret_cast<t_C_GetTokenInfo>(fl->C_GetTokenInfo);
            // p11-kit-client.so exports only C_GetFunctionList, so this pointer is the
            // only way to reach the proxy's mechanism list — dlsym alone finds nothing.
            if (fl->C_GetMechanismList)
                mechList = reinterpret_cast<t_C_GetMechanismList>(fl->C_GetMechanismList);
            if (fl->C_Initialize)   init    = reinterpret_cast<t_C_Initialize>(fl->C_Initialize);
        }
    }
    if (!getList || !tokInfo) {
        info.error = "the module offers neither C_GetFunctionList nor direct "
                     "C_GetSlotList/C_GetTokenInfo — not a PKCS#11 module?";
        dlclose(h); return info;
    }

    // Do NOT call C_Finalize — OpenSSL's pkcs11 provider already holds the
    // module open.  C_Finalize would tear it down, breaking all subsequent
    // PKCS#11 operations (key loading, signing) until the process restarts.
    //
    // Try C_GetSlotList first — works if OpenSSL (or a prior call) already
    // initialized the module.  If it fails, call C_Initialize to cold-start
    // the module, then retry.  Never call C_Finalize.

    CK_ULONG count = 0;
    if (getList(0, nullptr, &count) != CKR_OK || count == 0) {
        // Not initialised yet in this process. Ask WITH the OS-locking flag: fastpki-web
        // serves on many threads, and a module is within its rights to answer
        // CKR_CANT_LOCK to a bare C_Initialize(NULL). That refusal was being swallowed
        // into "no slots", so the console decided this deployment had no HSM.
        int rc = CKR_OK;
        if (init) {
            CkInitArgs args; args.flags = CKF_OS_LOCKING_OK_;
            rc = init(&args);
            if (rc != CKR_OK) rc = init(nullptr);   // older modules reject any args
        }
        if (!init || rc != CKR_OK) {
            info.error = "C_Initialize failed (rc=" + std::to_string(rc) + ")";
            dlclose(h); return info;
        }
        count = 0;
        if (getList(0, nullptr, &count) != CKR_OK) {
            info.error = "C_GetSlotList failed after C_Initialize";
            dlclose(h); return info;
        }
        if (count == 0) { dlclose(h); return info; }   // genuinely no slots
    }

    std::vector<CK_SLOT_ID> ids(count);
    if (getList(0, ids.data(), &count) != CKR_OK) {
        dlclose(h); return info;
    }

    for (CK_ULONG i = 0; i < count; ++i) {
        CK_TOKEN_INFO ti{};
        if (tokInfo(ids[i], &ti) == CKR_OK && (ti.flags & CKF_TOKEN_INITIALIZED)) {
            Pkcs11Slot s;
            s.id = ids[i];
            s.token_label = trim_label(ti.label, sizeof ti.label);
            // Which key types this slot will actually mint. Best-effort: a module
            // that won't answer leaves the list empty, and an empty list means "unknown",
            // never "supports nothing" — callers must not turn silence into a refusal.
            if (mechList) {
                CK_ULONG mcount = 0;
                if (mechList(ids[i], nullptr, &mcount) == CKR_OK && mcount > 0) {
                    std::vector<unsigned long> mechs(mcount);
                    if (mechList(ids[i], mechs.data(), &mcount) == CKR_OK) {
                        mechs.resize(mcount);
                        for (unsigned long m : mechs)
                            if (m == CKM_RSA_PKCS_KEY_PAIR_GEN_ || m == CKM_EC_KEY_PAIR_GEN_ ||
                                m == CKM_EC_EDWARDS_KEY_PAIR_GEN_ || m == CKM_ML_DSA_KEY_PAIR_GEN_)
                                s.keygen_mechanisms.push_back(m);
                    }
                }
            }
            info.slots.push_back(std::move(s));
        }
    }

    dlclose(h);
    return info;
}

// Delete the objects a pkcs11: URI names, so a keypair minted for a certificate
// that then failed to sign does not stay in the token forever.
//
// This is a compensating action, deliberately, rather than another pre-flight. The
// failure that motivated it — RSA-PSS CA creation — is refused by the OpenSSL
// pkcs11-provider while the token itself advertises `CKM_RSA_PKCS_PSS, sign, verify`,
// so no amount of asking the token in advance would have predicted it. Undoing a mint
// we can see failed assumes nothing about which operations a provider layer will accept.
Pkcs11DestroyResult pkcs11_destroy_key(const std::filesystem::path& module,
                                       const std::string& key_uri,
                                       const std::string& pin) {
    Pkcs11DestroyResult r;
    const std::string label = pkcs11_uri_attr(key_uri, "object");
    const std::string id    = pkcs11_uri_attr(key_uri, "id");
    const std::string token = pkcs11_uri_token(key_uri);
    if (label.empty() && id.empty()) {
        r.error = "the key URI names neither object= nor id=, so there is nothing to identify";
        return r;
    }
    if (module.empty()) { r.error = "no PKCS11_MODULE configured"; return r; }

    void* h = dlopen(module.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!h) { const char* e = dlerror(); r.error = std::string("dlopen: ") + (e ? e : "failed"); return r; }

    CkFunctionList* fl = nullptr;
    auto gfl = reinterpret_cast<t_C_GetFunctionList>(dlsym(h, "C_GetFunctionList"));
    if (!gfl || gfl(&fl) != CKR_OK || !fl) {
        r.error = "the module offers no C_GetFunctionList"; dlclose(h); return r;
    }
    auto init    = reinterpret_cast<t_C_Initialize>(fl->C_Initialize);
    auto getList = reinterpret_cast<t_C_GetSlotList>(fl->C_GetSlotList);
    auto tokInfo = reinterpret_cast<t_C_GetTokenInfo>(fl->C_GetTokenInfo);
    auto openS   = reinterpret_cast<t_C_OpenSession>(fl->C_OpenSession);
    auto closeS  = reinterpret_cast<t_C_CloseSession>(fl->C_CloseSession);
    auto login   = reinterpret_cast<t_C_Login>(fl->C_Login);
    auto destroy = reinterpret_cast<t_C_DestroyObject>(fl->C_DestroyObject);
    auto findI   = reinterpret_cast<t_C_FindObjectsInit>(fl->C_FindObjectsInit);
    auto find    = reinterpret_cast<t_C_FindObjects>(fl->C_FindObjects);
    auto findF   = reinterpret_cast<t_C_FindObjectsFinal>(fl->C_FindObjectsFinal);
    if (!getList || !tokInfo || !openS || !login || !destroy || !findI || !find || !findF) {
        r.error = "the module's function table is missing an object-removal entry";
        dlclose(h); return r;
    }

    if (init) {
        CkInitArgs args; args.flags = CKF_OS_LOCKING_OK_;
        const int rc = init(&args);
        if (rc != CKR_OK && rc != CKR_CRYPTOKI_ALREADY_INITIALIZED_) {
            r.error = "C_Initialize failed (rc=" + std::to_string(rc) + ")";
            dlclose(h); return r;
        }
    }

    // Find the slot the URI names. With no token= there is nothing to disambiguate, so
    // refuse rather than guess: deleting objects out of the wrong token would be far
    // worse than leaving one orphan behind.
    CK_ULONG count = 0;
    if (getList(1, nullptr, &count) != CKR_OK || count == 0) {
        r.error = "no slot holds a token"; dlclose(h); return r;
    }
    std::vector<CK_SLOT_ID> ids(count);
    if (getList(1, ids.data(), &count) != CKR_OK) {
        r.error = "C_GetSlotList failed"; dlclose(h); return r;
    }
    ids.resize(count);
    bool have_slot = false;
    CK_SLOT_ID slot = 0;
    for (CK_SLOT_ID s : ids) {
        CK_TOKEN_INFO ti{};
        if (tokInfo(s, &ti) != CKR_OK) continue;
        if (!(ti.flags & CKF_TOKEN_INITIALIZED)) continue;
        if (token.empty() || trim_label(ti.label, sizeof ti.label) == token) {
            slot = s; have_slot = true; break;
        }
    }
    if (!have_slot) {
        r.error = "no initialized token named '" + token + "'"; dlclose(h); return r;
    }

    CK_SESSION_HANDLE sess = 0;
    if (openS(slot, CKF_SERIAL_SESSION_ | CKF_RW_SESSION_, nullptr, nullptr, &sess) != CKR_OK) {
        r.error = "C_OpenSession failed (a read-write session is required to delete)";
        dlclose(h); return r;
    }
    // A private key object is only visible, let alone deletable, to a logged-in session.
    const int lrc = login(sess, CKU_USER_,
                          reinterpret_cast<const unsigned char*>(pin.data()),
                          static_cast<CK_ULONG>(pin.size()));
    if (lrc != CKR_OK && lrc != CKR_USER_ALREADY_LOGGED_IN_) {
        r.error = "C_Login failed (rc=" + std::to_string(lrc) + "); check the token PIN";
        if (closeS) closeS(sess);
        dlclose(h); return r;
    }

    // Match on whatever the URI gave us. Both attributes together is the precise case;
    // either alone is what the console's own generated URIs carry.
    std::vector<CK_ATTRIBUTE> tmpl;
    if (!label.empty())
        tmpl.push_back({CKA_LABEL_, const_cast<char*>(label.data()),
                        static_cast<CK_ULONG>(label.size())});
    if (!id.empty())
        tmpl.push_back({CKA_ID_, const_cast<char*>(id.data()),
                        static_cast<CK_ULONG>(id.size())});

    if (findI(sess, tmpl.data(), static_cast<CK_ULONG>(tmpl.size())) == CKR_OK) {
        // No CKA_CLASS in the template, so this returns the public AND private halves
        // (and any certificate object sharing the label) — all of which are the orphan.
        for (;;) {
            CK_OBJECT_HANDLE found[16];
            CK_ULONG n = 0;
            if (find(sess, found, 16, &n) != CKR_OK || n == 0) break;
            for (CK_ULONG i = 0; i < n; ++i)
                if (destroy(sess, found[i]) == CKR_OK) ++r.destroyed;
        }
        findF(sess);
    } else {
        r.error = "C_FindObjectsInit failed";
    }

    // ⚠️ C_Logout IS NOT CALLED, for the same reason C_Finalize is not — and the comment
    // below already had the argument, one call short of applying it. PKCS#11 login state
    // is per-token per-APPLICATION, not per-session (v2.40 §6.7.5: logging one session in
    // logs in every session this process holds on that token), so C_Logout would log out
    // the OpenSSL pkcs11 provider's sessions too — the ones this process signs with.
    // Closing our own session is the whole of the cleanup we owe: we never need the
    // process to be logged OUT, so the call had nothing to gain and a live signer to lose.
    if (closeS) closeS(sess);
    // C_Finalize is NOT called — the OpenSSL pkcs11 provider holds this module open in
    // the same process, and tearing it down breaks key loading and signing until restart.
    dlclose(h);
    return r;
}

// List what a token holds. Same dlopen/session/login shape as the removal above —
// deliberately, because the two answer halves of one question ("what is in there" and
// "take that out") and a second way of reaching the module is a second way to be wrong.
Pkcs11Objects pkcs11_list_objects(const std::filesystem::path& module,
                                  const std::string& token_label,
                                  const std::string& pin) {
    Pkcs11Objects out;
    out.token = token_label;
    if (module.empty()) { out.error = "no PKCS11_MODULE configured"; return out; }
    // ⚠️ Without a PIN the token answers with the PUBLIC objects only, and a list that
    // silently omits every private key is worse than no list: it is the exact question
    // the page exists to answer, answered wrongly and confidently.
    if (pin.empty()) {
        out.error = "no token PIN is available (PKCS11_PIN_FILE), and without one the "
                    "token would hide every private key — which is what this page is for";
        return out;
    }

    // The process-wide handle: opened and initialised on first use, never closed. A fresh
    // dlopen + C_Initialize here left a p11-kit-remote behind on every call, and this
    // function runs once a minute for the console's node report. See shared_module().
    CkFunctionList* fl = shared_module(module, out.error);
    if (!fl) return out;

    auto getList = reinterpret_cast<t_C_GetSlotList>(fl->C_GetSlotList);
    auto tokInfo = reinterpret_cast<t_C_GetTokenInfo>(fl->C_GetTokenInfo);
    auto openS   = reinterpret_cast<t_C_OpenSession>(fl->C_OpenSession);
    auto closeS  = reinterpret_cast<t_C_CloseSession>(fl->C_CloseSession);
    auto login   = reinterpret_cast<t_C_Login>(fl->C_Login);
    auto findI   = reinterpret_cast<t_C_FindObjectsInit>(fl->C_FindObjectsInit);
    auto find    = reinterpret_cast<t_C_FindObjects>(fl->C_FindObjects);
    auto findF   = reinterpret_cast<t_C_FindObjectsFinal>(fl->C_FindObjectsFinal);
    auto getAttr = reinterpret_cast<t_C_GetAttributeValue>(fl->C_GetAttributeValue);
    if (!getList || !tokInfo || !openS || !login || !findI || !find || !findF || !getAttr) {
        out.error = "the module's function table is missing an object-enumeration entry";
        return out;
    }

    // C_Initialize happened once, in shared_module(). Calling it again per listing is what
    // leaked a connection every time.

    CK_ULONG count = 0;
    if (getList(1, nullptr, &count) != CKR_OK || count == 0) {
        out.error = "no slot holds a token"; return out;
    }
    std::vector<CK_SLOT_ID> ids(count);
    if (getList(1, ids.data(), &count) != CKR_OK) {
        out.error = "C_GetSlotList failed"; return out;
    }
    ids.resize(count);
    bool have_slot = false;
    CK_SLOT_ID slot = 0;
    for (CK_SLOT_ID s : ids) {
        CK_TOKEN_INFO ti{};
        if (tokInfo(s, &ti) != CKR_OK) continue;
        if (!(ti.flags & CKF_TOKEN_INITIALIZED)) continue;
        const std::string lbl = trim_label(ti.label, sizeof ti.label);
        if (token_label.empty() || lbl == token_label) {
            slot = s; have_slot = true; out.token = lbl; break;
        }
    }
    if (!have_slot) {
        out.error = "no initialized token named '" + token_label + "'"; return out;
    }

    // Read-only: this page looks, it does not touch. A read-write session would be a
    // needless write lock on a token other services are using.
    CK_SESSION_HANDLE sess = 0;
    if (openS(slot, CKF_SERIAL_SESSION_, nullptr, nullptr, &sess) != CKR_OK) {
        out.error = "C_OpenSession failed"; return out;
    }
    const int lrc = login(sess, CKU_USER_,
                          reinterpret_cast<const unsigned char*>(pin.data()),
                          static_cast<CK_ULONG>(pin.size()));
    if (lrc != CKR_OK && lrc != CKR_USER_ALREADY_LOGGED_IN_) {
        out.error = "C_Login failed (rc=" + std::to_string(lrc) + "); check the token PIN";
        if (closeS) closeS(sess);
        return out;
    }

    // A byte string attribute, read in the two passes PKCS#11 requires: ask for the
    // length, then for the value. An attribute the object does not have comes back as a
    // failure, which is ordinary here — a certificate has no CKA_KEY_TYPE.
    auto attr_bytes = [&](CK_OBJECT_HANDLE obj, CK_ULONG type) -> std::string {
        CK_ATTRIBUTE a{type, nullptr, 0};
        if (getAttr(sess, obj, &a, 1) != CKR_OK || a.ulValueLen == 0 ||
            a.ulValueLen == static_cast<CK_ULONG>(-1))
            return {};
        std::string buf(a.ulValueLen, '\0');
        a.pValue = buf.data();
        if (getAttr(sess, obj, &a, 1) != CKR_OK) return {};
        buf.resize(a.ulValueLen);
        return buf;
    };
    auto attr_ulong = [&](CK_OBJECT_HANDLE obj, CK_ULONG type, CK_ULONG* v) -> bool {
        CK_ATTRIBUTE a{type, v, sizeof(CK_ULONG)};
        return getAttr(sess, obj, &a, 1) == CKR_OK;
    };

    // Empty template = every object this session can see. Which is the point: an orphan
    // is by definition an object nobody would have thought to ask for by name.
    if (findI(sess, nullptr, 0) == CKR_OK) {
        for (;;) {
            CK_OBJECT_HANDLE found[32];
            CK_ULONG n = 0;
            if (find(sess, found, 32, &n) != CKR_OK || n == 0) break;
            for (CK_ULONG i = 0; i < n; ++i) {
                Pkcs11Object o;
                o.label = attr_bytes(found[i], CKA_LABEL_);
                const std::string raw_id = attr_bytes(found[i], CKA_ID_);
                static const char* kHex = "0123456789abcdef";
                for (unsigned char c : raw_id) { o.id += kHex[c >> 4]; o.id += kHex[c & 0xF]; }
                CK_ULONG cls = 0, kt = 0, bits = 0;
                if (attr_ulong(found[i], CKA_CLASS_, &cls)) {
                    o.klass = cls == CKO_PRIVATE_KEY_ ? "private"
                            : cls == CKO_PUBLIC_KEY_  ? "public"
                            : cls == CKO_CERTIFICATE_ ? "certificate"
                            : cls == CKO_SECRET_KEY_  ? "secret" : "other";
                } else {
                    o.klass = "other";
                }
                if (o.klass == "private") {
                    // CK_BBOOL is one byte; read into one, never into a CK_ULONG.
                    unsigned char ext = 0;
                    CK_ATTRIBUTE a{CKA_EXTRACTABLE_, &ext, sizeof ext};
                    o.extractable = getAttr(sess, found[i], &a, 1) == CKR_OK && ext != 0;
                }
                if (attr_ulong(found[i], CKA_KEY_TYPE_, &kt)) {
                    // ⚠️ An unrecognised type reports its NUMBER, never an empty string.
                    // The empty fallback is what turned one wrong constant into a blank
                    // column with nothing to debug from: the page said "-" and could not
                    // say whether the object had no type, or a type we failed to name.
                    // A number is the one answer that stays useful when this list falls
                    // behind PKCS#11 again — which it will, as new algorithms land.
                    switch (kt) {
                        case CKK_RSA_:           o.key_type = "RSA";            break;
                        case CKK_EC_:            o.key_type = "EC";             break;
                        case CKK_AES_:           o.key_type = "AES";            break;
                        case CKK_EC_EDWARDS_:    o.key_type = "Ed25519";        break;
                        case CKK_EC_MONTGOMERY_: o.key_type = "X25519";         break;
                        case CKK_ML_KEM_:        o.key_type = "ML-KEM";         break;
                        case CKK_ML_DSA_:        o.key_type = "ML-DSA";         break;
                        default: {
                            char buf[32];
                            std::snprintf(buf, sizeof buf, "type 0x%lx",
                                          static_cast<unsigned long>(kt));
                            o.key_type = buf;
                            break;
                        }
                    }
                }
                if (attr_ulong(found[i], CKA_MODULUS_BITS_, &bits)) {
                    o.bits = bits;
                } else if (std::string m = attr_bytes(found[i], CKA_MODULUS_); !m.empty()) {
                    // The modulus itself is present where CKA_MODULUS_BITS is not.
                    // Its leading byte can be 0x00 (a positive-integer sign pad), which
                    // would report 2056 bits for a 2048-bit key.
                    size_t z = 0;
                    while (z < m.size() && static_cast<unsigned char>(m[z]) == 0) ++z;
                    o.bits = static_cast<unsigned long>((m.size() - z) * 8);
                }
                // EC keys carry their curve as a DER ECParameters — a named-curve
                // OID in every case we mint or adopt. Decode it to the NIST name the
                // console's picker actually uses ("P-256"), and take the bit length from
                // the curve's own degree rather than guessing it from the name.
                if (o.key_type == "EC") {
                    const std::string p = attr_bytes(found[i], CKA_EC_PARAMS_);
                    if (!p.empty()) {
                        const unsigned char* dp = reinterpret_cast<const unsigned char*>(p.data());
                        if (ASN1_OBJECT* obj = d2i_ASN1_OBJECT(nullptr, &dp,
                                                               static_cast<long>(p.size()))) {
                            const int nid = OBJ_obj2nid(obj);
                            ASN1_OBJECT_free(obj);
                            if (nid != NID_undef) {
                                if (const char* nist = EC_curve_nid2nist(nid)) o.curve = nist;
                                else if (const char* sn = OBJ_nid2sn(nid))     o.curve = sn;
                                if (EC_GROUP* g = EC_GROUP_new_by_curve_name(nid)) {
                                    o.bits = static_cast<unsigned long>(EC_GROUP_get_degree(g));
                                    EC_GROUP_free(g);
                                }
                            }
                        }
                    }
                }
                // ⚠️ CKK_EC_EDWARDS IS BOTH EdDSA CURVES, so the key type alone cannot say
                // Ed448 — every Ed448 key was listed as Ed25519. PKCS#11 3.x names the curve
                // in CKA_EC_PARAMS, as the OID (1.3.101.112 / .113) or as the printable
                // curve name; recorded here as a curve hint and resolved after the public
                // half's attributes are folded in below, because that is where SoftHSM
                // keeps them.
                if (o.key_type == "Ed25519") {
                    const std::string p = attr_bytes(found[i], CKA_EC_PARAMS_);
                    static const std::string oid448("\x06\x03\x2B\x65\x71", 5);
                    static const std::string oid25519("\x06\x03\x2B\x65\x70", 5);
                    if (p.find(oid448) != std::string::npos || p.find("edwards448") != std::string::npos)
                        o.curve = "edwards448";
                    else if (p.find(oid25519) != std::string::npos || p.find("edwards25519") != std::string::npos)
                        o.curve = "edwards25519";
                }
                out.objects.push_back(std::move(o));
            }
        }
        findF(sess);
        // ⚠️ THE HALF THAT MAKES THE ABOVE VISIBLE. A PKCS#11 keypair is TWO objects,
        // and the facts are split across them: SoftHSM puts CKA_EC_PARAMS and
        // CKA_MODULUS_BITS on the PUBLIC key, while every consumer here — the console's
        // "use existing key" picker, the HSM keys page — filters to `class == "private"`,
        // because that is the half a signing URI names. So reading the attributes without
        // this back-fill would have changed nothing anyone can see.
        //
        // Matched on (label, id): that pair is what makes two objects one keypair, and a
        // label alone would fuse two keys an operator happened to name the same.
        for (auto& priv : out.objects) {
            if (priv.klass != "private" || (priv.bits && !priv.curve.empty())) continue;
            for (const auto& pub : out.objects) {
                if (pub.klass != "public" || pub.label != priv.label || pub.id != priv.id)
                    continue;
                if (!priv.bits)         priv.bits  = pub.bits;
                if (priv.curve.empty()) priv.curve = pub.curve;
                break;
            }
        }
        // The Edwards curve hint from above, now that each private key carries its public
        // half's parameters: name the key by its curve, and do not show the hint as a curve.
        for (auto& obj : out.objects) {
            if (obj.key_type != "Ed25519") continue;
            if (obj.curve == "edwards448") obj.key_type = "Ed448";
            if (obj.curve == "edwards448" || obj.curve == "edwards25519") obj.curve.clear();
        }
    } else {
        out.error = "C_FindObjectsInit failed";
    }

    // C_Logout is NOT called either — see pkcs11_destroy_key. It matters more here:
    // moved this enumeration onto the CAs dashboard and both issue pickers, so an ordinary
    // console page load ran it while other threads may be signing with the same token.
    //
    // The session is the only thing this function owns, so closing it is the whole of the
    // cleanup. The module handle belongs to shared_module() and stays open for the life of
    // the process — dlclose here is what used to leave a p11-kit-remote behind on every
    // call, because the connection C_Initialize opened outlived the handle.
    if (closeS) closeS(sess);
    return out;
}

// ── key replication ────────────────────────────────────────────────────────────────
//
// The engine behind `fastpki-ca key replicate`. See include/pki/pkcs11_helpers.hpp for
// the design; what follows is the mechanism, and every step of it is measured by
// tests/wrapprobe.c in a container built from the shipped image — never on a host, whose
// stock SoftHSM and unpatched p11-kit cannot hold half the key types this handles.

namespace {

// A module opened, initialised, and a logged-in read/write session on one token.
//
// ⚠️ THE DESTRUCTOR FINALIZES AND CLOSES THE MODULE, which pkcs11_enumerate_slots()
// deliberately never does. That difference is the whole reason a replication run works:
// `p11-kit-client.so` reads P11_KIT_SERVER_ADDRESS at C_Initialize, and one run reaches
// the SOURCE node's token over the tunnel and then this node's own. Leave the module
// initialised between the two and the second phase silently keeps talking to the first
// token — succeeding, having replicated a key onto the node that already had it.
struct TokenSession {
    void*             h{nullptr};
    CkFunctionList*   fl{nullptr};
    CK_SESSION_HANDLE sess{0};
    bool              initialised{false};
    std::string       error;

    TokenSession() = default;
    TokenSession(const TokenSession&) = delete;
    TokenSession& operator=(const TokenSession&) = delete;
    // Movable, because open_token() returns one by value and a user-declared destructor
    // suppresses the implicit move. The moved-from object must own NOTHING, or the
    // destructor finalizes and dlcloses a module the live copy is still using.
    TokenSession(TokenSession&& o) noexcept
        : h(o.h), fl(o.fl), sess(o.sess), initialised(o.initialised),
          error(std::move(o.error)) {
        o.h = nullptr; o.fl = nullptr; o.sess = 0; o.initialised = false;
    }
    TokenSession& operator=(TokenSession&&) = delete;
    ~TokenSession() {
        if (h && fl) {
            if (sess) {
                if (auto c = reinterpret_cast<t_C_CloseSession>(fl->C_CloseSession)) c(sess);
            }
            if (initialised) {
                if (auto f = reinterpret_cast<t_C_Finalize>(fl->C_Finalize)) f(nullptr);
            }
        }
        if (h) dlclose(h);
    }
    bool ok() const { return error.empty(); }
};

// Every entry the replication paths call, checked once so a missing one is reported as
// "this module cannot do it" rather than as a crash on a null pointer.
bool have_replication_entries(const CkFunctionList* fl) {
    return fl->C_OpenSession && fl->C_CloseSession && fl->C_Login && fl->C_GetSlotList &&
           fl->C_GetTokenInfo && fl->C_FindObjectsInit && fl->C_FindObjects &&
           fl->C_FindObjectsFinal && fl->C_GetAttributeValue && fl->C_GenerateKeyPair &&
           fl->C_WrapKey && fl->C_UnwrapKey && fl->C_DeriveKey;
}

TokenSession open_token(const std::filesystem::path& module,
                        const std::string& token_label,
                        const std::string& pin) {
    TokenSession t;
    if (module.empty()) { t.error = "no PKCS11_MODULE configured"; return t; }
    if (pin.empty()) {
        t.error = "no token PIN available; a logged-in session is required to reach a "
                  "private key";
        return t;
    }
    t.h = dlopen(module.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!t.h) {
        const char* e = dlerror();
        t.error = std::string("cannot load the PKCS#11 module: ") + (e ? e : "dlopen failed");
        return t;
    }
    auto gfl = reinterpret_cast<t_C_GetFunctionList>(dlsym(t.h, "C_GetFunctionList"));
    if (!gfl || gfl(&t.fl) != CKR_OK || !t.fl) {
        t.error = "the module offers no C_GetFunctionList";
        return t;
    }
    if (!have_replication_entries(t.fl)) {
        t.error = "this PKCS#11 module does not offer the wrap/unwrap/derive group, so it "
                  "cannot replicate a key";
        return t;
    }
    if (auto init = reinterpret_cast<t_C_Initialize>(t.fl->C_Initialize)) {
        CkInitArgs args; args.flags = CKF_OS_LOCKING_OK_;
        int rc = init(&args);
        if (rc != CKR_OK && rc != CKR_CRYPTOKI_ALREADY_INITIALIZED_) rc = init(nullptr);
        if (rc != CKR_OK && rc != CKR_CRYPTOKI_ALREADY_INITIALIZED_) {
            t.error = "C_Initialize failed (rc=" + std::to_string(rc) + ")";
            return t;
        }
        t.initialised = (rc == CKR_OK);
    }
    auto getList = reinterpret_cast<t_C_GetSlotList>(t.fl->C_GetSlotList);
    auto tokInfo = reinterpret_cast<t_C_GetTokenInfo>(t.fl->C_GetTokenInfo);
    CK_ULONG count = 0;
    if (getList(1, nullptr, &count) != CKR_OK || count == 0) {
        t.error = "no slot holds an initialized token"; return t;
    }
    std::vector<CK_SLOT_ID> ids(count);
    if (getList(1, ids.data(), &count) != CKR_OK) {
        t.error = "C_GetSlotList failed"; return t;
    }
    ids.resize(count);
    bool have = false; CK_SLOT_ID slot = 0;
    for (CK_SLOT_ID s : ids) {
        CK_TOKEN_INFO ti{};
        if (tokInfo(s, &ti) != CKR_OK) continue;
        if (!(ti.flags & CKF_TOKEN_INITIALIZED)) continue;
        if (token_label.empty() || trim_label(ti.label, sizeof ti.label) == token_label) {
            slot = s; have = true; break;
        }
    }
    if (!have) {
        t.error = "no initialized token named '" + token_label + "' is reachable";
        return t;
    }
    auto openS = reinterpret_cast<t_C_OpenSession>(t.fl->C_OpenSession);
    if (openS(slot, CKF_SERIAL_SESSION_ | CKF_RW_SESSION_, nullptr, nullptr, &t.sess) != CKR_OK) {
        t.error = "C_OpenSession failed (a read-write session is required)";
        t.sess = 0; return t;
    }
    auto login = reinterpret_cast<t_C_Login>(t.fl->C_Login);
    const int lrc = login(t.sess, CKU_USER_,
                          reinterpret_cast<const unsigned char*>(pin.data()),
                          static_cast<CK_ULONG>(pin.size()));
    if (lrc != CKR_OK && lrc != CKR_USER_ALREADY_LOGGED_IN_) {
        // ⚠️ NAME THE TOKEN. This same call authenticates to a LOCAL token and, across the
        // P11_TLS tunnel, to a PEER's — with different PINs. "check the token PIN" left an
        // operator holding two of them and no way to tell which one had been refused.
        t.error = "C_Login to token '" + (token_label.empty() ? std::string("(any)")
                                                              : token_label) +
                  "' failed (rc=" + std::to_string(lrc) + ")" +
                  (lrc == 0xa0 ? ": the PIN is wrong for THIS token"
                   : lrc == 0xa4 ? ": the token has locked this PIN out"
                                 : "");
        return t;
    }
    return t;
}

// The first object of `klass` carrying `label` (and `id`, when given). Zero when none.
CK_OBJECT_HANDLE find_object(const TokenSession& t, CK_ULONG klass,
                             const std::string& label, const std::string& id) {
    auto findI = reinterpret_cast<t_C_FindObjectsInit>(t.fl->C_FindObjectsInit);
    auto find  = reinterpret_cast<t_C_FindObjects>(t.fl->C_FindObjects);
    auto findF = reinterpret_cast<t_C_FindObjectsFinal>(t.fl->C_FindObjectsFinal);
    std::vector<CK_ATTRIBUTE> tmpl;
    tmpl.push_back({CKA_CLASS_, &klass, sizeof klass});
    if (!label.empty())
        tmpl.push_back({CKA_LABEL_, const_cast<char*>(label.data()),
                        static_cast<CK_ULONG>(label.size())});
    if (!id.empty())
        tmpl.push_back({CKA_ID_, const_cast<char*>(id.data()),
                        static_cast<CK_ULONG>(id.size())});
    if (findI(t.sess, tmpl.data(), static_cast<CK_ULONG>(tmpl.size())) != CKR_OK) return 0;
    CK_OBJECT_HANDLE h = 0; CK_ULONG n = 0;
    find(t.sess, &h, 1, &n);
    findF(t.sess);
    return n ? h : 0;
}

// One attribute's bytes. Empty when the token will not say.
std::vector<unsigned char> attr_bytes(const TokenSession& t, CK_OBJECT_HANDLE obj,
                                      CK_ULONG type) {
    auto get = reinterpret_cast<t_C_GetAttributeValue>(t.fl->C_GetAttributeValue);
    CK_ATTRIBUTE a{type, nullptr, 0};
    if (get(t.sess, obj, &a, 1) != CKR_OK || a.ulValueLen == 0 ||
        a.ulValueLen == static_cast<CK_ULONG>(-1))
        return {};
    std::vector<unsigned char> v(a.ulValueLen);
    a.pValue = v.data();
    if (get(t.sess, obj, &a, 1) != CKR_OK) return {};
    v.resize(a.ulValueLen);
    return v;
}

// ⚠️ CKA_EC_POINT COMES BACK DER-WRAPPED AND CKM_ECDH1_DERIVE WANTS THE RAW POINT.
// SoftHSM returns the point inside an OCTET STRING; handing that straight to the
// mechanism derives from the wrong bytes at one end only, so the two sides produce
// DIFFERENT AES keys and the failure surfaces as a corrupt unwrap rather than as
// anything naming the point. Measured in tests/wrapprobe.c, which does exactly this.
std::vector<unsigned char> ec_point_raw(const std::vector<unsigned char>& v) {
    if (v.size() > 2 && v[0] == 0x04 && v[1] == v.size() - 2)
        return std::vector<unsigned char>(v.begin() + 2, v.end());
    return v;
}

// prime256v1 as a DER-encoded named-curve OID — what CKA_EC_PARAMS takes.
const unsigned char kP256Oid[] = {0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
// The other curves a CA key may use, as the same DER-encoded OIDs.
const unsigned char kP384Oid[]    = {0x06,0x05,0x2B,0x81,0x04,0x00,0x22};
const unsigned char kP521Oid[]    = {0x06,0x05,0x2B,0x81,0x04,0x00,0x23};
const unsigned char kEd25519Oid[] = {0x06,0x03,0x2B,0x65,0x70};
const unsigned char kEd448Oid[]   = {0x06,0x03,0x2B,0x65,0x71};

// A DER length, short or long form. An EC point for P-521 is 133 bytes, past the 127 a
// single length byte can say, so writing the short form produced a malformed CKA_EC_POINT.
void der_push_len(std::vector<unsigned char>& out, size_t n) {
    if (n < 0x80) { out.push_back(static_cast<unsigned char>(n)); return; }
    unsigned char tmp[sizeof(size_t)];
    int k = 0;
    while (n) { tmp[k++] = static_cast<unsigned char>(n & 0xFF); n >>= 8; }
    out.push_back(static_cast<unsigned char>(0x80 | k));
    while (k) out.push_back(tmp[--k]);
}

// Derive the shared AES-256 key from `priv` and the peer's public point. A SESSION
// object: it exists for this operation and vanishes with the session, so nothing has to
// remember to delete it and no failure path can leave a usable wrapping key behind.
CK_OBJECT_HANDLE derive_shared_aes(const TokenSession& t, CK_OBJECT_HANDLE priv,
                                   const std::vector<unsigned char>& peer_point, int& rc) {
    std::vector<unsigned char> raw = ec_point_raw(peer_point);
    CK_ECDH1_DERIVE_PARAMS p{CKD_NULL_, 0, nullptr,
                             static_cast<CK_ULONG>(raw.size()), raw.data()};
    CK_MECHANISM m{CKM_ECDH1_DERIVE_, &p, sizeof p};
    CK_ULONG klass = CKO_SECRET_KEY_, ktype = CKK_AES_, len = 32;
    unsigned char yes = 1, no = 0;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS_, &klass, sizeof klass}, {CKA_KEY_TYPE_, &ktype, sizeof ktype},
        {CKA_TOKEN_, &no, sizeof no},       {CKA_VALUE_LEN_, &len, sizeof len},
        {CKA_WRAP_, &yes, sizeof yes},      {CKA_UNWRAP_, &yes, sizeof yes},
        {CKA_SENSITIVE_, &yes, sizeof yes},
    };
    CK_OBJECT_HANDLE k = 0;
    auto derive = reinterpret_cast<t_C_DeriveKey>(t.fl->C_DeriveKey);
    rc = derive(t.sess, &m, priv, tmpl, 7, &k);
    return rc == CKR_OK ? k : 0;
}

std::string ck_err(const char* what, int rc) {
    return std::string(what) + " failed (CKR 0x" + [rc] {
        char b[16]; std::snprintf(b, sizeof b, "%x", static_cast<unsigned>(rc)); return std::string(b);
    }() + ")";
}

} // namespace

Pkcs11Kek pkcs11_kek_public(const std::filesystem::path& module,
                            const std::string& token_label,
                            const std::string& pin,
                            const std::string& kek_label) {
    Pkcs11Kek r;
    TokenSession t = open_token(module, token_label, pin);
    if (!t.ok()) { r.error = t.error; return r; }

    CK_OBJECT_HANDLE pub = find_object(t, CKO_PUBLIC_KEY_, kek_label, "");
    if (!pub) {
        // First use on this node. The private half is SENSITIVE and NOT extractable: it
        // decrypts every key replicated to this node, so it must never itself be
        // replicable — and CKA_EXTRACTABLE cannot be granted later, which is exactly the
        // property being relied on.
        CK_ULONG cls_pub = CKO_PUBLIC_KEY_, cls_prv = CKO_PRIVATE_KEY_, kt = CKK_EC_;
        unsigned char yes = 1, no = 0;
        CK_ATTRIBUTE pubt[] = {
            {CKA_CLASS_, &cls_pub, sizeof cls_pub}, {CKA_KEY_TYPE_, &kt, sizeof kt},
            {CKA_TOKEN_, &yes, sizeof yes},
            {CKA_EC_PARAMS_, const_cast<unsigned char*>(kP256Oid), sizeof kP256Oid},
            {CKA_LABEL_, const_cast<char*>(kek_label.data()),
             static_cast<CK_ULONG>(kek_label.size())},
        };
        CK_ATTRIBUTE prvt[] = {
            {CKA_CLASS_, &cls_prv, sizeof cls_prv}, {CKA_KEY_TYPE_, &kt, sizeof kt},
            {CKA_TOKEN_, &yes, sizeof yes},   {CKA_PRIVATE_, &yes, sizeof yes},
            {CKA_DERIVE_, &yes, sizeof yes},  {CKA_SENSITIVE_, &yes, sizeof yes},
            {CKA_EXTRACTABLE_, &no, sizeof no},
            {CKA_LABEL_, const_cast<char*>(kek_label.data()),
             static_cast<CK_ULONG>(kek_label.size())},
        };
        CK_MECHANISM m{CKM_EC_KEY_PAIR_GEN_, nullptr, 0};
        CK_OBJECT_HANDLE prv = 0;
        auto gen = reinterpret_cast<t_C_GenerateKeyPair>(t.fl->C_GenerateKeyPair);
        const int rc = gen(t.sess, &m, pubt, 5, prvt, 8, &pub, &prv);
        if (rc != CKR_OK) {
            r.error = ck_err("generating this node's key-encryption keypair", rc) +
                      "; the token must support EC P-256 key generation";
            return r;
        }
    }
    r.ec_point = attr_bytes(t, pub, CKA_EC_POINT_);
    if (r.ec_point.empty())
        r.error = "the key-encryption public point could not be read back from the token";
    return r;
}

Pkcs11Wrapped pkcs11_wrap_for_peer(const std::filesystem::path& module,
                                   const std::string& key_uri,
                                   const std::string& pin,
                                   const std::vector<unsigned char>& kek_ec_point) {
    Pkcs11Wrapped r;
    const std::string label = pkcs11_uri_attr(key_uri, "object");
    const std::string id    = pkcs11_uri_attr(key_uri, "id");
    const std::string token = pkcs11_uri_token(key_uri);
    if (label.empty() && id.empty()) {
        r.error = "the key URI names neither object= nor id=, so there is nothing to wrap";
        return r;
    }
    if (kek_ec_point.empty()) {
        r.error = "no destination key-encryption point was supplied";
        return r;
    }
    TokenSession t = open_token(module, token, pin);
    if (!t.ok()) { r.error = t.error; return r; }

    CK_OBJECT_HANDLE ca = find_object(t, CKO_PRIVATE_KEY_, label, id);
    if (!ca) {
        r.error = "no private key matching " + pkcs11_uri_redacted(key_uri) +
                  " is in that token";
        return r;
    }
    // The destination's C_UnwrapKey template has to name the key type, and only this side
    // can see it. Reported rather than assumed: unwrapping an EC key as CKK_RSA produces a
    // handle that fails at the first signature, long after the transfer looked successful.
    const std::vector<unsigned char> kt = attr_bytes(t, ca, CKA_KEY_TYPE_);
    CK_ULONG ktv = static_cast<CK_ULONG>(-1);
    if (kt.size() >= sizeof(CK_ULONG)) std::memcpy(&ktv, kt.data(), sizeof ktv);
    r.key_type = (ktv == CKK_EC_)         ? "EC"
               : (ktv == CKK_RSA_)        ? "RSA"
               : (ktv == CKK_EC_EDWARDS_) ? "EdDSA"
               : (ktv == CKK_ML_DSA_)     ? "ML-DSA" : "";
    if (r.key_type.empty()) {
        r.error = "this key is not RSA, EC, EdDSA or ML-DSA, so FastPKI cannot replicate it";
        return r;
    }
    // ⚠️ THE MECHANISM RESTRICTION TRAVELS WITH THE KEY, because the wrapped PKCS#8 blob does
    // not carry it. An RSA-PSS key is CKK_RSA plus CKA_ALLOWED_MECHANISMS; unwrapped without the
    // list, the copy is an unrestricted RSA key that loads as "RSA", signs PKCS#1 v1.5, and so
    // produces signatures its own rsassaPss certificate forbids.
    r.allowed_mechanisms = attr_bytes(t, ca, CKA_ALLOWED_MECHANISMS_);
    if (r.key_type == "RSA" && !r.allowed_mechanisms.empty()) r.key_type = "RSA-PSS";

    // An EPHEMERAL keypair, per transfer, as session objects. A fresh one each time means
    // one recovered blob cannot be replayed against a later transfer, and nothing survives
    // the session to be cleaned up.
    CK_ULONG cls_pub = CKO_PUBLIC_KEY_, cls_prv = CKO_PRIVATE_KEY_, ktec = CKK_EC_;
    unsigned char yes = 1, no = 0;
    CK_ATTRIBUTE pubt[] = {
        {CKA_CLASS_, &cls_pub, sizeof cls_pub}, {CKA_KEY_TYPE_, &ktec, sizeof ktec},
        {CKA_TOKEN_, &no, sizeof no},
        {CKA_EC_PARAMS_, const_cast<unsigned char*>(kP256Oid), sizeof kP256Oid},
    };
    CK_ATTRIBUTE prvt[] = {
        {CKA_CLASS_, &cls_prv, sizeof cls_prv}, {CKA_KEY_TYPE_, &ktec, sizeof ktec},
        {CKA_TOKEN_, &no, sizeof no},           {CKA_DERIVE_, &yes, sizeof yes},
        {CKA_SENSITIVE_, &yes, sizeof yes},
    };
    CK_MECHANISM gm{CKM_EC_KEY_PAIR_GEN_, nullptr, 0};
    CK_OBJECT_HANDLE eph_pub = 0, eph_prv = 0;
    auto gen = reinterpret_cast<t_C_GenerateKeyPair>(t.fl->C_GenerateKeyPair);
    int rc = gen(t.sess, &gm, pubt, 4, prvt, 5, &eph_pub, &eph_prv);
    if (rc != CKR_OK) {
        r.error = ck_err("generating the transfer's ephemeral keypair", rc);
        return r;
    }
    CK_OBJECT_HANDLE aes = derive_shared_aes(t, eph_prv, kek_ec_point, rc);
    if (!aes) {
        r.error = ck_err("deriving the transfer key (CKM_ECDH1_DERIVE)", rc) +
                  "; the destination's public point may not be a P-256 point";
        return r;
    }

    CK_MECHANISM wm{CKM_AES_KEY_WRAP_PAD_, nullptr, 0};
    auto wrap = reinterpret_cast<t_C_WrapKey>(t.fl->C_WrapKey);
    CK_ULONG need = 0;
    rc = wrap(t.sess, &wm, aes, ca, nullptr, &need);
    if (rc == CKR_OK && (need == 0 || need > kMaxWrappedKey)) {
        r.error = "the token reported an implausible wrapped-key length (" +
                  std::to_string(need) + " bytes)";
        return r;
    }
    if (rc == CKR_OK) {
        r.blob.resize(need);
        rc = wrap(t.sess, &wm, aes, ca, r.blob.data(), &need);
        if (rc == CKR_OK) r.blob.resize(need);
    }
    if (rc != CKR_OK) {
        r.blob.clear();
        // ⚠️ THE ONE FAILURE WITH A DIFFERENT ANSWER. CKA_EXTRACTABLE is fixed at key
        // generation and PKCS#11 forbids granting it afterwards, so this CA can never be
        // replicated and no retry will change that. Saying so is the difference between an
        // operator re-creating the CA and an operator debugging a mechanism.
        if (rc == CKR_KEY_UNEXTRACTABLE_ || rc == CKR_KEY_NOT_WRAPPABLE_) {
            r.permanent = true;
            r.error = "this CA's key was generated non-extractable, so it can never leave "
                      "its token. CKA_EXTRACTABLE is set when a key is created and PKCS#11 "
                      "does not allow granting it later — a CA that must be replicated has "
                      "to be created with `fastpki-ca create --replicable`.";
        } else if (rc == CKR_WRAPPING_KEY_HANDLE_INVALID_) {
            r.error = "the token refused the derived transfer key for wrapping (CKR 0x113); "
                      "it does not support CKM_AES_KEY_WRAP_PAD over a derived AES key";
        } else {
            r.error = ck_err("wrapping the CA private key (CKM_AES_KEY_WRAP_PAD)", rc);
        }
        return r;
    }

    r.ephemeral_pub = attr_bytes(t, eph_pub, CKA_EC_POINT_);
    if (r.ephemeral_pub.empty()) {
        r.blob.clear();
        r.error = "the transfer's ephemeral public point could not be read back";
    }
    return r;
}

namespace {

// Write the public half beside a just-unwrapped private key, rebuilt from the CA
// certificate. Best-effort by design: the private key is already in the token and usable
// for signing, so failing here must not undo a transfer that succeeded — the caller's
// verification is what decides whether the result is good.
void create_public_half(const TokenSession& t, const std::vector<unsigned char>& spki_der,
                        const std::string& label, const std::string& id) {
    if (spki_der.empty()) return;
    if (find_object(t, CKO_PUBLIC_KEY_, label, id)) return;   // already there

    const unsigned char* p = spki_der.data();
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>
        pk(d2i_PUBKEY(nullptr, &p, static_cast<long>(spki_der.size())), &EVP_PKEY_free);
    if (!pk) return;

    CK_ULONG cls = CKO_PUBLIC_KEY_, kt = 0, pset = 0;
    unsigned char yes = 1;
    std::vector<CK_ATTRIBUTE> tmpl;
    std::vector<unsigned char> a, b;   // must outlive the C_CreateObject call

    // The raw public key of an EdDSA or ML-DSA certificate key, which is all its SPKI holds.
    auto raw_public = [&](std::vector<unsigned char>& out) {
        size_t len = 0;
        if (!EVP_PKEY_get_raw_public_key(pk.get(), nullptr, &len) || len == 0) return false;
        out.resize(len);
        if (!EVP_PKEY_get_raw_public_key(pk.get(), out.data(), &len)) return false;
        out.resize(len);
        return true;
    };

    const int base = EVP_PKEY_get_base_id(pk.get());
    if (base == EVP_PKEY_ED25519 || base == EVP_PKEY_ED448) {
        // CKA_EC_PARAMS is the curve OID, as the key was generated with; CKA_EC_POINT is the
        // raw key in an OCTET STRING, the shape SoftHSM stores for a key it generated.
        kt = CKK_EC_EDWARDS_;
        if (base == EVP_PKEY_ED25519) a.assign(kEd25519Oid, kEd25519Oid + sizeof kEd25519Oid);
        else                          a.assign(kEd448Oid, kEd448Oid + sizeof kEd448Oid);
        std::vector<unsigned char> raw;
        if (!raw_public(raw)) return;
        b.push_back(0x04);
        der_push_len(b, raw.size());
        b.insert(b.end(), raw.begin(), raw.end());
        tmpl.push_back({CKA_EC_PARAMS_, a.data(), static_cast<CK_ULONG>(a.size())});
        tmpl.push_back({CKA_EC_POINT_,  b.data(), static_cast<CK_ULONG>(b.size())});
    } else if (EVP_PKEY_is_a(pk.get(), "ML-DSA-44") || EVP_PKEY_is_a(pk.get(), "ML-DSA-65") ||
               EVP_PKEY_is_a(pk.get(), "ML-DSA-87")) {
        kt = CKK_ML_DSA_;
        pset = EVP_PKEY_is_a(pk.get(), "ML-DSA-44") ? CKP_ML_DSA_44_
             : EVP_PKEY_is_a(pk.get(), "ML-DSA-65") ? CKP_ML_DSA_65_ : CKP_ML_DSA_87_;
        if (!raw_public(a)) return;
        tmpl.push_back({CKA_PARAMETER_SET_, &pset, sizeof pset});
        tmpl.push_back({CKA_VALUE_, a.data(), static_cast<CK_ULONG>(a.size())});
    } else if (base == EVP_PKEY_EC) {
        kt = CKK_EC_;
        char gname[80] = {0};
        size_t glen = 0;
        if (!EVP_PKEY_get_utf8_string_param(pk.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                            gname, sizeof gname, &glen))
            return;
        const int nid = OBJ_txt2nid(gname);
        if (nid == NID_undef) return;
        // CKA_EC_PARAMS is the DER-encoded named-curve OID.
        ASN1_OBJECT* obj = OBJ_nid2obj(nid);
        unsigned char* der = nullptr;
        const int dlen = i2d_ASN1_OBJECT(obj, &der);
        if (dlen <= 0 || !der) return;
        a.assign(der, der + dlen);
        OPENSSL_free(der);
        // CKA_EC_POINT is that point wrapped in an ASN.1 OCTET STRING — the same shape the
        // token hands back, and the reason ec_point_raw() exists to undo it.
        size_t plen = 0;
        if (!EVP_PKEY_get_octet_string_param(pk.get(), OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                             nullptr, 0, &plen) || plen == 0 || plen > 255)
            return;
        std::vector<unsigned char> raw(plen);
        if (!EVP_PKEY_get_octet_string_param(pk.get(), OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                             raw.data(), raw.size(), &plen))
            return;
        raw.resize(plen);
        b.reserve(plen + 3);
        b.push_back(0x04);
        der_push_len(b, plen);     // P-521's 133-byte point needs the long form
        b.insert(b.end(), raw.begin(), raw.end());
        tmpl.push_back({CKA_EC_PARAMS_, a.data(), static_cast<CK_ULONG>(a.size())});
        tmpl.push_back({CKA_EC_POINT_,  b.data(), static_cast<CK_ULONG>(b.size())});
    } else if (base == EVP_PKEY_RSA || base == EVP_PKEY_RSA_PSS) {
        kt = CKK_RSA_;
        std::unique_ptr<BIGNUM, decltype(&BN_free)> n(nullptr, &BN_free), e(nullptr, &BN_free);
        BIGNUM* nb = nullptr; BIGNUM* eb = nullptr;
        if (!EVP_PKEY_get_bn_param(pk.get(), OSSL_PKEY_PARAM_RSA_N, &nb) ||
            !EVP_PKEY_get_bn_param(pk.get(), OSSL_PKEY_PARAM_RSA_E, &eb)) {
            BN_free(nb); BN_free(eb); return;
        }
        n.reset(nb); e.reset(eb);
        a.resize(static_cast<size_t>(BN_num_bytes(n.get())));
        b.resize(static_cast<size_t>(BN_num_bytes(e.get())));
        BN_bn2bin(n.get(), a.data());
        BN_bn2bin(e.get(), b.data());
        tmpl.push_back({CKA_MODULUS_,         a.data(), static_cast<CK_ULONG>(a.size())});
        tmpl.push_back({CKA_PUBLIC_EXPONENT_, b.data(), static_cast<CK_ULONG>(b.size())});
    } else {
        return;
    }

    tmpl.push_back({CKA_CLASS_, &cls, sizeof cls});
    tmpl.push_back({CKA_KEY_TYPE_, &kt, sizeof kt});
    tmpl.push_back({CKA_TOKEN_, &yes, sizeof yes});
    tmpl.push_back({CKA_VERIFY_, &yes, sizeof yes});
    tmpl.push_back({CKA_LABEL_, const_cast<char*>(label.data()),
                    static_cast<CK_ULONG>(label.size())});
    if (!id.empty())
        tmpl.push_back({CKA_ID_, const_cast<char*>(id.data()),
                        static_cast<CK_ULONG>(id.size())});

    if (auto create = reinterpret_cast<t_C_CreateObject>(t.fl->C_CreateObject)) {
        CK_OBJECT_HANDLE out = 0;
        create(t.sess, tmpl.data(), static_cast<CK_ULONG>(tmpl.size()), &out);
    }
}

} // namespace

std::string pkcs11_unwrap_into(const std::filesystem::path& module,
                               const std::string& token_label,
                               const std::string& pin,
                               const std::string& kek_label,
                               const Pkcs11Wrapped& w,
                               const std::string& dest_label,
                               const std::string& dest_id,
                               const std::vector<unsigned char>& spki_der) {
    if (w.blob.empty() || w.ephemeral_pub.empty())
        return "nothing to unwrap: the source produced no wrapped key";
    if (dest_label.empty())
        return "no destination object label, so the key would be unfindable once written";
    const CK_ULONG unwrap_kt = (w.key_type == "EC")                          ? CKK_EC_
                             : (w.key_type == "RSA" || w.key_type == "RSA-PSS") ? CKK_RSA_
                             : (w.key_type == "EdDSA")                       ? CKK_EC_EDWARDS_
                             : (w.key_type == "ML-DSA")                      ? CKK_ML_DSA_
                             : static_cast<CK_ULONG>(-1);
    if (unwrap_kt == static_cast<CK_ULONG>(-1))
        return "the source did not report a key type this can unwrap ('" + w.key_type + "')";

    TokenSession t = open_token(module, token_label, pin);
    if (!t.ok()) return t.error;

    CK_OBJECT_HANDLE kek = find_object(t, CKO_PRIVATE_KEY_, kek_label, "");
    if (!kek)
        return "this node has no key-encryption key '" + kek_label + "' in its token; the "
               "destination must publish its public point before a source can wrap for it";

    int rc = 0;
    CK_OBJECT_HANDLE aes = derive_shared_aes(t, kek, w.ephemeral_pub, rc);
    if (!aes)
        return ck_err("deriving the transfer key (CKM_ECDH1_DERIVE)", rc) +
               "; this node's key-encryption key does not match the one the source wrapped for";

    // ⚠️ EXTRACTABLE AT THE DESTINATION TOO. A replicated key that could not itself be
    // replicated onward would make the SECOND node a single point of failure the moment
    // the first was lost — the exact failure this mechanism exists to remove.
    CK_ULONG cls = CKO_PRIVATE_KEY_;
    CK_ULONG kt  = unwrap_kt;
    unsigned char yes = 1;
    std::vector<CK_ATTRIBUTE> tmpl = {
        {CKA_CLASS_, &cls, sizeof cls},       {CKA_KEY_TYPE_, &kt, sizeof kt},
        {CKA_TOKEN_, &yes, sizeof yes},       {CKA_PRIVATE_, &yes, sizeof yes},
        {CKA_SIGN_, &yes, sizeof yes},        {CKA_SENSITIVE_, &yes, sizeof yes},
        {CKA_EXTRACTABLE_, &yes, sizeof yes},
        {CKA_LABEL_, const_cast<char*>(dest_label.data()),
         static_cast<CK_ULONG>(dest_label.size())},
    };

    // ⚠️ CKA_ID ALWAYS, DERIVED FROM THE LABEL WHEN THE SOURCE URI NAMES NONE. This is the
    // same trap the generator hits from the other side: the provider associates a private
    // key with its public half BY CKA_ID, so a key unwrapped without one can sign — and
    // nothing else. Every comparison against the certificate then fails, including the
    // `expect` check load_signing_key() makes for a CA with more than one key URL, and the
    // symptom is "the key that arrived does NOT match" about a key that is provably correct.
    const std::string kid = dest_id.empty() ? dest_label : dest_id;
    tmpl.push_back({CKA_ID_, const_cast<char*>(kid.data()),
                    static_cast<CK_ULONG>(kid.size())});
    // The source's mechanism restriction, verbatim — see pkcs11_wrap_for_peer().
    if (!w.allowed_mechanisms.empty())
        tmpl.push_back({CKA_ALLOWED_MECHANISMS_,
                        const_cast<unsigned char*>(w.allowed_mechanisms.data()),
                        static_cast<CK_ULONG>(w.allowed_mechanisms.size())});

    CK_MECHANISM wm{CKM_AES_KEY_WRAP_PAD_, nullptr, 0};
    CK_OBJECT_HANDLE out = 0;
    auto unwrap = reinterpret_cast<t_C_UnwrapKey>(t.fl->C_UnwrapKey);
    rc = unwrap(t.sess, &wm, aes, w.blob.data(), static_cast<CK_ULONG>(w.blob.size()),
                tmpl.data(), static_cast<CK_ULONG>(tmpl.size()), &out);
    if (rc != CKR_OK || !out)
        return ck_err("unwrapping the CA private key into this token", rc);
    create_public_half(t, spki_der, dest_label, kid);
    return {};
}

// ── the transient tunnel a replication run reaches the source token through ─────────

// The last few lines a failed tunnel child wrote, so the caller can say WHY stunnel would
// not start instead of only that it did not. Kept small: this goes into an error message.
static std::string tail_lines(const std::filesystem::path& p, size_t want) {
    std::ifstream f(p);
    if (!f) return {};
    std::vector<std::string> all;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        all.push_back(line);
        if (all.size() > want) all.erase(all.begin());
    }
    std::string out;
    for (auto& l : all) { if (!out.empty()) out += "; "; out += l; }
    return out;
}

P11Tunnel::~P11Tunnel() { stop(); }

std::string P11Tunnel::start(const std::string& host_port,
                             const std::filesystem::path& tls_dir,
                             const std::filesystem::path& module,
                             const std::filesystem::path& pin_file,
                             const std::string& token) {
    if (host_port.empty()) return "no peer address to dial";
    const std::filesystem::path cert = tls_dir / "client.crt";
    const std::filesystem::path capath = tls_dir / "servers";
    std::error_code ec;
    if (!std::filesystem::exists(cert, ec))
        return cert.string() + " is missing: this node has no client certificate to "
               "identify itself with. It is generated by certgen under P11_TLS=on.";
    // ⚠️ AN EMPTY TRUST DIRECTORY IS A HARD STOP, not a warning. Dialling out with nothing
    // to verify against would hand the token PIN — which C_Login carries — to whatever
    // answered on that address, which is the one failure this whole transport prevents.
    if (!std::filesystem::is_directory(capath, ec) ||
        std::filesystem::is_empty(capath, ec))
        return capath.string() + " is empty: no peer token host can be verified. The "
               "serving node publishes its certificate at startup; check that this node's "
               "database has replicated from it.";

    char tmpl[] = "/tmp/fastpki-p11XXXXXX";
    const char* d = ::mkdtemp(tmpl);
    if (!d) return "could not create a working directory for the tunnel";
    dir_ = d;
    const std::string sock = dir_ + "/peer.sock";
    const std::string conf = dir_ + "/stunnel.conf";
    const std::string ossl = dir_ + "/openssl.cnf";
    const std::string logp = dir_ + "/stunnel.log";

    {
        std::ofstream f(conf);
        // No checkHost/checkIP, for the same reason every other end of this transport
        // omits them: addresses are dynamic across the deployment shapes, so the identity
        // is the pinned certificate rather than where it answers from.
        f << "foreground = yes\npid =\n\n[p11]\nclient = yes\n"
          << "accept = " << sock << "\n"
          << "connect = " << host_port << "\n"
          << "cert = " << cert.string() << "\n"
          << "key = pkcs11:token=" << token
          << ";object=p11-client;type=private?pin-source=" << pin_file.string() << "\n"
          << "CApath = " << capath.string() << "\n"
          << "verifyPeer = yes\nverifyChain = yes\n";
    }
    {
        // stunnel is a stock binary reading the stock openssl.cnf, which activates no
        // provider — and its own key is a token object. Scoped to the child.
        std::ofstream f(ossl);
        f << "openssl_conf = c\n[c]\nproviders = p\n[p]\ndefault = d\npkcs11 = k\n"
          << "[d]\nactivate = 1\n[k]\n"
          << "module = " << (std::getenv("OSSL_MODULES_DIR")
                                 ? std::getenv("OSSL_MODULES_DIR")
                                 : "/usr/lib/ossl-modules") << "/pkcs11.so\n"
          << "pkcs11-module-path = " << module.string() << "\n"
          << "activate = 1\n";
    }

    // ⚠️ THE CHILD KEEPS THIS NODE'S OWN TOKEN ADDRESS. stunnel resolves `p11-client` from
    // the LOCAL token; if it inherited an address already pointed at the peer it would try
    // to open its own key through the tunnel it is being started to create.
    const char* local = ::getenv("P11_KIT_SERVER_ADDRESS");
    const std::string local_addr = local ? local : "";

    const int pid = ::fork();
    if (pid < 0) { stop(); return "fork failed while starting the tunnel"; }
    if (pid == 0) {
        ::setenv("OPENSSL_CONF", ossl.c_str(), 1);
        if (!local_addr.empty()) ::setenv("P11_KIT_SERVER_ADDRESS", local_addr.c_str(), 1);
        // ⚠️ CAPTURED, NOT DISCARDED. These went to /dev/null so they would not interleave
        // with the CLI's output, which also meant a tunnel that refused to start said
        // nothing anywhere. A file keeps both properties: the caller quotes the tail into
        // its error, and stop() removes it with the rest of the working directory.
        const int lf = ::open(logp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (lf >= 0) { ::dup2(lf, 1); ::dup2(lf, 2); ::close(lf); }
        ::execlp("stunnel", "stunnel", conf.c_str(), static_cast<char*>(nullptr));
        ::_exit(127);
    }
    pid_ = pid;

    // Wait for the near end to exist. A child that died (a bad certificate, no stunnel on
    // PATH) is reaped here rather than leaving the caller to time out on a socket that is
    // never coming.
    for (int i = 0; i < 100; ++i) {
        struct stat st{};
        if (::stat(sock.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
            address_ = "unix:path=" + sock;
            return {};
        }
        int status = 0;
        if (::waitpid(pid_, &status, WNOHANG) == pid_) {
            pid_ = -1;
            const std::string why = tail_lines(logp, 4);
            stop();
            return "the tunnel to " + host_port + " exited immediately; stunnel is either "
                   "not installed, or the peer refused this node's client certificate" +
                   (why.empty() ? std::string() : " — stunnel said: " + why);
        }
        ::usleep(100000);
    }
    const std::string why = tail_lines(logp, 4);
    stop();
    return "the tunnel to " + host_port + " did not come up within 10s" +
           (why.empty() ? std::string() : " — stunnel said: " + why);
}

void P11Tunnel::stop() {
    if (pid_ > 0) {
        ::kill(pid_, SIGTERM);
        // ⚠️ BOUNDED, AND THAT IS THE WHOLE POINT. A blocking waitpid() here hangs the
        // caller on a child that does not die — and because `key replicate` prints the
        // transfer's own error only after stop() returns, the hang SWALLOWED the message
        // saying what had actually gone wrong. The command then sat silent with nothing to
        // distinguish a stuck tunnel from a stuck token. Escalate instead of waiting.
        bool reaped = false;
        for (int i = 0; i < 50 && !reaped; ++i) {
            int status = 0;
            const pid_t r = ::waitpid(pid_, &status, WNOHANG);
            if (r == pid_) reaped = true;
            else if (r < 0 && errno != EINTR) reaped = true;  // already gone
            else ::usleep(100000);
        }
        if (!reaped) {
            ::kill(pid_, SIGKILL);
            int status = 0;
            ::waitpid(pid_, &status, 0);
        }
        pid_ = -1;
    }
    if (!dir_.empty()) {
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
        dir_.clear();
    }
    address_.clear();
}

// How to mint a replicable key of one algorithm through PKCS#11 directly: its key type,
// its keygen mechanism, and the one attribute that selects the variant (curve OID, ML-DSA
// parameter set, or modulus size). `error` is set, and nothing else is, when FastPKI does
// not mint that algorithm.
//
// ⚠️ EVERY CA KEY TYPE THE CONSOLE OFFERS, not a subset. This once took only RSA and EC P-256,
// because the probe it rested on had been written on a host whose unpatched SoftHSM and
// p11-kit could not hold Ed25519, ML-DSA or a PSS-restricted key. tests/wrapprobe.c, run in
// a container built from the shipped image, wraps, unwraps and signs with each of these.
struct ReplicableSpec {
    CK_ULONG             key_type{0};
    CK_ULONG             gen_mech{0};
    const unsigned char* ec_params{nullptr};
    CK_ULONG             ec_params_len{0};
    CK_ULONG             parameter_set{0};
    bool                 rsa{false};
    bool                 pss{false};
    std::string          error{};
};

static ReplicableSpec replicable_spec(const std::string& algo, const std::string& curve) {
    auto lower = [](std::string s) {
        for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    };
    const std::string a = lower(algo), cv = lower(curve);
    ReplicableSpec sp;
    if (a.empty() || a == "rsa" || a == "rsa-pss") {
        sp.key_type = CKK_RSA_; sp.gen_mech = CKM_RSA_PKCS_KEY_PAIR_GEN_;
        sp.rsa = true; sp.pss = (a == "rsa-pss");
    } else if (a == "ec" || a == "ecdsa" || a == "p256") {
        sp.key_type = CKK_EC_; sp.gen_mech = CKM_EC_KEY_PAIR_GEN_;
        if (cv.empty() || cv == "p-256" || cv == "prime256v1") {
            sp.ec_params = kP256Oid; sp.ec_params_len = sizeof kP256Oid;
        } else if (cv == "p-384" || cv == "secp384r1") {
            sp.ec_params = kP384Oid; sp.ec_params_len = sizeof kP384Oid;
        } else if (cv == "p-521" || cv == "secp521r1") {
            sp.ec_params = kP521Oid; sp.ec_params_len = sizeof kP521Oid;
        } else {
            sp.error = "a replicable EC key must use P-256, P-384 or P-521; '" + curve +
                       "' is not a curve FastPKI generates";
        }
    } else if (a == "ed25519" || a == "ed448") {
        sp.key_type = CKK_EC_EDWARDS_; sp.gen_mech = CKM_EC_EDWARDS_KEY_PAIR_GEN_;
        sp.ec_params     = (a == "ed25519") ? kEd25519Oid : kEd448Oid;
        sp.ec_params_len = (a == "ed25519") ? sizeof kEd25519Oid : sizeof kEd448Oid;
    } else if (a == "ml-dsa-44" || a == "ml-dsa-65" || a == "ml-dsa-87") {
        sp.key_type = CKK_ML_DSA_; sp.gen_mech = CKM_ML_DSA_KEY_PAIR_GEN_;
        sp.parameter_set = (a == "ml-dsa-44") ? CKP_ML_DSA_44_
                         : (a == "ml-dsa-65") ? CKP_ML_DSA_65_ : CKP_ML_DSA_87_;
    } else {
        sp.error = "a replicable key must be RSA, RSA-PSS, EC, Ed25519, Ed448 or ML-DSA; '" +
                   algo + "' is not an algorithm FastPKI generates";
    }
    return sp;
}

std::string pkcs11_replicable_refusal(const std::string& algo, const std::string& curve) {
    return replicable_spec(algo, curve).error;
}

std::string pkcs11_generate_replicable_keypair(const std::filesystem::path& module,
                                               const std::string& key_uri,
                                               const std::string& pin,
                                               const std::string& algo,
                                               const std::string& curve,
                                               unsigned long bits) {
    const std::string label = pkcs11_uri_attr(key_uri, "object");
    const std::string id    = pkcs11_uri_attr(key_uri, "id");
    const std::string token = pkcs11_uri_token(key_uri);
    if (label.empty())
        return "the key URI names no object=, so the new key would be unfindable";
    const ReplicableSpec sp = replicable_spec(algo, curve);
    if (!sp.error.empty()) return sp.error;

    TokenSession t = open_token(module, token, pin);
    if (!t.ok()) return t.error;
    if (find_object(t, CKO_PRIVATE_KEY_, label, id))
        return "the token already holds a private key labelled '" + label + "'";

    CK_ULONG cls_pub = CKO_PUBLIC_KEY_, cls_prv = CKO_PRIVATE_KEY_;
    CK_ULONG kt = sp.key_type;
    CK_ULONG modbits = bits ? bits : 4096;
    CK_ULONG pset = sp.parameter_set;
    unsigned char yes = 1;
    unsigned char e[] = {0x01, 0x00, 0x01};        // 65537
    std::vector<CK_ATTRIBUTE> pubt = {
        {CKA_CLASS_, &cls_pub, sizeof cls_pub}, {CKA_KEY_TYPE_, &kt, sizeof kt},
        {CKA_TOKEN_, &yes, sizeof yes},         {CKA_VERIFY_, &yes, sizeof yes},
        {CKA_LABEL_, const_cast<char*>(label.data()),
         static_cast<CK_ULONG>(label.size())},
    };
    if (sp.rsa) {
        pubt.push_back({CKA_MODULUS_BITS_, &modbits, sizeof modbits});
        pubt.push_back({CKA_PUBLIC_EXPONENT_, e, sizeof e});
    } else if (sp.ec_params) {
        pubt.push_back({CKA_EC_PARAMS_, const_cast<unsigned char*>(sp.ec_params),
                        sp.ec_params_len});
    } else if (sp.parameter_set) {
        pubt.push_back({CKA_PARAMETER_SET_, &pset, sizeof pset});
    }
    // ⚠️ CKA_EXTRACTABLE IS THE WHOLE POINT OF THIS FUNCTION, and the one attribute the
    // OpenSSL pkcs11 provider gives no way to set. CKA_SENSITIVE stays true beside it:
    // together they mean "may leave the token, but only ever wrapped".
    std::vector<CK_ATTRIBUTE> prvt = {
        {CKA_CLASS_, &cls_prv, sizeof cls_prv},  {CKA_KEY_TYPE_, &kt, sizeof kt},
        {CKA_TOKEN_, &yes, sizeof yes},          {CKA_PRIVATE_, &yes, sizeof yes},
        {CKA_SIGN_, &yes, sizeof yes},           {CKA_SENSITIVE_, &yes, sizeof yes},
        {CKA_EXTRACTABLE_, &yes, sizeof yes},
        {CKA_LABEL_, const_cast<char*>(label.data()),
         static_cast<CK_ULONG>(label.size())},
    };
    if (sp.pss)
        prvt.push_back({CKA_ALLOWED_MECHANISMS_, const_cast<CK_ULONG*>(kRsaPssMechs),
                        sizeof kRsaPssMechs});
    // ⚠️ CKA_ID ON BOTH HALVES, ALWAYS — DERIVED FROM THE LABEL WHEN THE URI NAMES NONE.
    // Without it the OpenSSL pkcs11 provider cannot associate the private key with its
    // public half: it fails with `p11prov_obj_find_associated: No CKA_ID in source object`,
    // and the EVP_PKEY that comes back carries no public key at all — so the very next step,
    // X509_set_pubkey() on the CA certificate, dies with "asn1 encoding routines::too
    // small". The provider's own keygen invents a random id for exactly this reason; minting
    // through PKCS#11 directly means doing it here.
    //
    // The label's own bytes, so the id is deterministic: a re-created key under the same
    // label gets the same id, and nothing has to store the mapping.
    const std::string kid = id.empty() ? label : id;
    pubt.push_back({CKA_ID_, const_cast<char*>(kid.data()),
                    static_cast<CK_ULONG>(kid.size())});
    prvt.push_back({CKA_ID_, const_cast<char*>(kid.data()),
                    static_cast<CK_ULONG>(kid.size())});

    CK_MECHANISM m{sp.gen_mech, nullptr, 0};
    CK_OBJECT_HANDLE pub = 0, prv = 0;
    auto gen = reinterpret_cast<t_C_GenerateKeyPair>(t.fl->C_GenerateKeyPair);
    const int rc = gen(t.sess, &m, pubt.data(), static_cast<CK_ULONG>(pubt.size()),
                       prvt.data(), static_cast<CK_ULONG>(prvt.size()), &pub, &prv);
    if (rc != CKR_OK)
        return ck_err(("generating a replicable " + algo + " keypair in the token").c_str(), rc);
    return {};
}

} // namespace pki
