// ACME device attestation for Apple devices — see include/pki/device_attest.hpp.
#include "pki/device_attest.hpp"
#include "pki/error.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string_view>

namespace pki::attest {

const char kAppleEnterpriseAttestationRoot[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICJDCCAamgAwIBAgIUQsDCuyxyfFxeq/bxpm8frF15hzcwCgYIKoZIzj0EAwMw\n"
    "UTEtMCsGA1UEAwwkQXBwbGUgRW50ZXJwcmlzZSBBdHRlc3RhdGlvbiBSb290IENB\n"
    "MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMjAyMTYxOTAx\n"
    "MjRaFw00NzAyMjAwMDAwMDBaMFExLTArBgNVBAMMJEFwcGxlIEVudGVycHJpc2Ug\n"
    "QXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UE\n"
    "BhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT6Jigq+Ps9Q4CoT8t8q+UnOe2p\n"
    "oT9nRaUfGhBTbgvqSGXPjVkbYlIWYO+1zPk2Sz9hQ5ozzmLrPmTBgEWRcHjA2/y7\n"
    "7GEicps9wn2tj+G89l3INNDKETdxSPPIZpPj8VmjQjBAMA8GA1UdEwEB/wQFMAMB\n"
    "Af8wHQYDVR0OBBYEFPNqTQGd8muBpV5du+UIbVbi+d66MA4GA1UdDwEB/wQEAwIB\n"
    "BjAKBggqhkjOPQQDAwNpADBmAjEA1xpWmTLSpr1VH4f8Ypk8f3jMUKYz4QPG8mL5\n"
    "8m9sX/b2+eXpTv2pH4RZgJjucnbcAjEA4ZSB6S45FlPuS/u4pTnzoz632rA+xW/T\n"
    "ZwFEh9bhKjJ+5VQ9/Do1os0u3LEkgN/r\n"
    "-----END CERTIFICATE-----\n";

namespace {

// ---- a CBOR reader for exactly what an attestation object needs -------------------------
//
// RFC 8949, definite lengths only. The object is small (two or three certificates), so the
// reader is bounded rather than general: nesting stops at kMaxDepth and every length is
// checked against what is left of the input BEFORE it is used, so a length field claiming
// 2^64 bytes is a clean error, never an allocation or an out-of-bounds read.
constexpr int kMaxDepth = 8;

struct Cbor {
    const unsigned char* p;
    const unsigned char* end;

    [[noreturn]] static void bad(const char* why) {
        throw Error(1, std::string("attestation object: ") + why);
    }
    unsigned char byte() {
        if (p >= end) bad("truncated");
        return *p++;
    }
    // Reads an item head: returns the major type and sets `arg`.
    int head(uint64_t& arg) {
        const unsigned char b = byte();
        const int major = b >> 5;
        const int info = b & 0x1f;
        if (info < 24) { arg = static_cast<uint64_t>(info); return major; }
        int n = 0;
        switch (info) {
            case 24: n = 1; break;
            case 25: n = 2; break;
            case 26: n = 4; break;
            case 27: n = 8; break;
            case 31: bad("indefinite lengths are not accepted");
            default: bad("reserved additional-information value");
        }
        arg = 0;
        for (int i = 0; i < n; ++i) arg = (arg << 8) | byte();
        return major;
    }
    size_t left() const { return static_cast<size_t>(end - p); }
    std::string_view take(uint64_t n) {
        if (n > left()) bad("length runs past the end");
        std::string_view v(reinterpret_cast<const char*>(p), static_cast<size_t>(n));
        p += n;
        return v;
    }
    // Skips one complete item of any type.
    void skip(int depth) {
        if (depth > kMaxDepth) bad("nested too deeply");
        uint64_t arg = 0;
        const int major = head(arg);
        switch (major) {
            case 0: case 1: return;                      // integers
            case 2: case 3: (void)take(arg); return;     // byte / text string
            case 4:                                      // array
                if (arg > left()) bad("array count runs past the end");
                for (uint64_t i = 0; i < arg; ++i) skip(depth + 1);
                return;
            case 5:                                      // map
                if (arg > left() / 2) bad("map count runs past the end");
                for (uint64_t i = 0; i < arg; ++i) { skip(depth + 1); skip(depth + 1); }
                return;
            case 6: skip(depth + 1); return;             // tag: skip the tagged item
            default:                                     // 7: simple values and floats
                return;                                  // head() already consumed their bytes
        }
    }
    std::string text() {
        uint64_t n = 0;
        if (head(n) != 3) bad("expected a text string");
        return std::string(take(n));
    }
    std::vector<unsigned char> bytes() {
        uint64_t n = 0;
        if (head(n) != 2) bad("expected a byte string");
        const std::string_view v = take(n);
        return std::vector<unsigned char>(v.begin(), v.end());
    }
    uint64_t map_count() {
        uint64_t n = 0;
        if (head(n) != 5) bad("expected a map");
        if (n > left() / 2) bad("map count runs past the end");
        return n;
    }
    uint64_t array_count() {
        uint64_t n = 0;
        if (head(n) != 4) bad("expected an array");
        if (n > left()) bad("array count runs past the end");
        return n;
    }
    // Reads a map key when it is a text string; otherwise skips the key and returns "".
    // Keys of other types are legal CBOR and are simply not ones this reader looks for.
    std::string key() {
        if (p >= end) bad("truncated");
        if ((*p >> 5) == 3) return text();
        skip(1);
        return {};
    }
};

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

X509Ptr der_to_x509(const std::vector<unsigned char>& der) {
    const unsigned char* q = der.data();
    X509* x = d2i_X509(nullptr, &q, static_cast<long>(der.size()));
    if (!x || q != der.data() + der.size()) {
        if (x) X509_free(x);
        throw Error(1, "attestation certificate is not a single DER certificate");
    }
    return X509Ptr(x, X509_free);
}

// An Apple attestation extension's value. step-ca compares the raw extnValue bytes, and
// Apple's documentation does not say whether the value is wrapped; accept the raw bytes,
// and also a single DER OCTET STRING or UTF8String that spans the whole value, which
// carries the same content.
std::string ext_value(X509* x, const char* oid) {
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> obj(OBJ_txt2obj(oid, 1),
                                                                 ASN1_OBJECT_free);
    if (!obj) return {};
    const int idx = X509_get_ext_by_OBJ(x, obj.get(), -1);
    if (idx < 0) return {};
    X509_EXTENSION* ext = X509_get_ext(x, idx);
    ASN1_OCTET_STRING* os = ext ? X509_EXTENSION_get_data(ext) : nullptr;
    if (!os) return {};
    const auto* d = ASN1_STRING_get0_data(os);
    const size_t n = static_cast<size_t>(ASN1_STRING_length(os));
    std::string v(reinterpret_cast<const char*>(d), n);
    if (n >= 2 && (d[0] == 0x04 || d[0] == 0x0c) && d[1] < 0x80 &&
        static_cast<size_t>(d[1]) + 2 == n)
        return v.substr(2);
    return v;
}

// An attested integer (the SIP status): a DER INTEGER, the digits as text, or one raw byte.
// Apple does not document which, and all three carry the same number. -1 when absent or
// unreadable, which a posture check treats as "not attested".
int ext_int(X509* x, const char* oid) {
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> obj(OBJ_txt2obj(oid, 1),
                                                                 ASN1_OBJECT_free);
    if (!obj) return -1;
    const int idx = X509_get_ext_by_OBJ(x, obj.get(), -1);
    if (idx < 0) return -1;
    ASN1_OCTET_STRING* os = X509_EXTENSION_get_data(X509_get_ext(x, idx));
    if (!os) return -1;
    const auto* d = ASN1_STRING_get0_data(os);
    const int n = ASN1_STRING_length(os);
    if (n >= 3 && d[0] == 0x02 && d[1] == n - 2 && n - 2 <= 4) {   // DER INTEGER, small
        int v = 0;
        for (int i = 2; i < n; ++i) v = (v << 8) | d[i];
        return v;
    }
    if (n >= 1 && n <= 9) {
        bool digits = true;
        for (int i = 0; i < n; ++i) if (d[i] < '0' || d[i] > '9') { digits = false; break; }
        if (digits) return std::atoi(std::string(reinterpret_cast<const char*>(d), n).c_str());
    }
    if (n == 1) return d[0];
    return -1;
}

} // namespace

int compare_versions(const std::string& a, const std::string& b) {
    auto parts = [](const std::string& s) {
        std::vector<long> v;
        long cur = 0;
        bool any = false;
        for (char ch : s + ".") {
            if (ch >= '0' && ch <= '9') { cur = cur * 10 + (ch - '0'); any = true; if (cur > 1000000) cur = 1000000; }
            else if (ch == '.') { v.push_back(any ? cur : 0); cur = 0; any = false; }
            else break;   // "17.2 (21C62)" and the like: the number is the part before
        }
        while (!v.empty() && v.back() == 0) v.pop_back();
        return v;
    };
    const auto x = parts(a), y = parts(b);
    for (size_t i = 0; i < std::max(x.size(), y.size()); ++i) {
        const long p = i < x.size() ? x[i] : 0, q = i < y.size() ? y[i] : 0;
        if (p != q) return p < q ? -1 : 1;
    }
    return 0;
}

AttestationObject parse_attestation_object(const unsigned char* data, size_t len) {
    Cbor c{data, data + len};
    AttestationObject out;
    bool have_fmt = false, have_stmt = false;
    const uint64_t n = c.map_count();
    for (uint64_t i = 0; i < n; ++i) {
        const std::string k = c.key();
        if (k == "fmt") {
            out.fmt = c.text();
            have_fmt = true;
        } else if (k == "attStmt") {
            const uint64_t m = c.map_count();
            for (uint64_t j = 0; j < m; ++j) {
                if (c.key() == "x5c") {
                    const uint64_t certs = c.array_count();
                    if (certs == 0 || certs > 8) Cbor::bad("x5c must hold 1 to 8 certificates");
                    for (uint64_t q = 0; q < certs; ++q) out.x5c.push_back(c.bytes());
                } else {
                    c.skip(2);
                }
            }
            have_stmt = true;
        } else {
            c.skip(1);
        }
    }
    if (c.p != c.end) Cbor::bad("trailing bytes after the object");
    if (!have_fmt) Cbor::bad("no fmt");
    if (!have_stmt || out.x5c.empty()) Cbor::bad("no attStmt.x5c");
    return out;
}

AppleDevice verify_apple(const AttestationObject& obj, const std::string& token,
                         const std::string& extra_roots_pem) {
    if (obj.fmt != "apple")
        throw Error(1, "attestation format '" + obj.fmt + "' is not supported; only 'apple' is");
    if (obj.x5c.empty()) throw Error(1, "attestation carries no certificate");

    X509Ptr leaf = der_to_x509(obj.x5c[0]);
    std::unique_ptr<STACK_OF(X509), void (*)(STACK_OF(X509)*)> chain(
        sk_X509_new_null(), [](STACK_OF(X509)* s) { sk_X509_pop_free(s, X509_free); });
    if (!chain) throw Error(2, "out of memory");
    for (size_t i = 1; i < obj.x5c.size(); ++i) {
        X509Ptr c = der_to_x509(obj.x5c[i]);
        if (!sk_X509_push(chain.get(), c.get())) throw Error(2, "out of memory");
        c.release();
    }

    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(X509_STORE_new(),
                                                                  X509_STORE_free);
    if (!store) throw Error(2, "X509_STORE_new failed");
    auto add_pem = [&](const std::string& pem) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
        int added = 0;
        while (X509* x = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) {
            X509_STORE_add_cert(store.get(), x);
            X509_free(x);
            ++added;
        }
        return added;
    };
    add_pem(kAppleEnterpriseAttestationRoot);
    if (!extra_roots_pem.empty() && add_pem(extra_roots_pem) == 0)
        throw Error(2, "ACME_ATTESTATION_ROOTS holds no readable certificate");

    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx(X509_STORE_CTX_new(),
                                                                         X509_STORE_CTX_free);
    if (!ctx || !X509_STORE_CTX_init(ctx.get(), store.get(), leaf.get(), chain.get()))
        throw Error(2, "X509_STORE_CTX_init failed");
    if (X509_verify_cert(ctx.get()) != 1)
        throw Error(1, std::string("the attestation does not chain to a trusted attestation "
                                   "root: ") +
                           X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get())));

    // The freshness code binds the attestation to THIS challenge. Required, not optional:
    // without it an attestation captured once could be replayed for every later order.
    unsigned char want[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(token.data()), token.size(), want);
    const std::string fresh = ext_value(leaf.get(), "1.2.840.113635.100.8.11.1");
    if (fresh.size() != sizeof want || std::memcmp(fresh.data(), want, sizeof want) != 0)
        throw Error(1, "the attestation's freshness code does not match this challenge's token");

    AppleDevice d;
    d.serial = ext_value(leaf.get(), "1.2.840.113635.100.8.9.1");
    d.udid   = ext_value(leaf.get(), "1.2.840.113635.100.8.9.2");
    d.os_version = ext_value(leaf.get(), "1.2.840.113635.100.8.10.1");
    d.sip        = ext_int(leaf.get(), "1.2.840.113635.100.8.13.1");
    if (d.serial.empty())
        throw Error(1, "the attestation names no serial number (a User Enrollment device "
                       "does not attest one)");
    for (const char ch : d.serial)
        if (static_cast<unsigned char>(ch) < 0x21 || static_cast<unsigned char>(ch) > 0x7e)
            throw Error(1, "the attested serial number is not printable text");

    EVP_PKEY* pk = X509_get0_pubkey(leaf.get());
    const int n = pk ? i2d_PUBKEY(pk, nullptr) : -1;
    if (n <= 0) throw Error(1, "the attested key cannot be read");
    d.leaf_spki_der.resize(static_cast<size_t>(n));
    unsigned char* w = d.leaf_spki_der.data();
    i2d_PUBKEY(pk, &w);
    return d;
}

} // namespace pki::attest
