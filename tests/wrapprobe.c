/* Does this PKCS#11 token let us replicate a CA key?
 *
 * The multi-URL CA-key HA design transfers a CA private key between tokens by
 * envelope encryption: wrap the private key under an ephemeral AES key, wrap that AES key
 * under the destination node's public KEK, and unwrap both inside the destination token so
 * plaintext key material never exists outside one. Every part of that rests on one
 * question the mechanism list cannot answer: will the token actually C_WrapKey a PRIVATE
 * key, and does what comes back out the other side still sign?
 *
 * Advertising CKM_AES_KEY_WRAP_PAD in C_GetMechanismList is not the same claim. A module
 * may list a mechanism and still refuse it for an asymmetric object.
 *
 * So this proves the whole round trip: generate, wrap, unwrap, then sign with the
 * UNWRAPPED handle and verify against the ORIGINAL public key. That last step is the
 * assertion — a wrap that returns bytes proves nothing if the key that comes back is not
 * the same key.
 *
 * No PKCS#11 headers: the types are declared here, the way src/lib/pkcs11_helpers.cpp
 * does, so the probe builds anywhere the module does.
 *
 * NOT WIRED INTO run_all.sh. It answers a question about the PLATFORM, not about FastPKI,
 * so it earns its place by being re-runnable after a SoftHSM or p11-kit bump rather than on
 * every commit.
 *
 * ⚠️ RUN IT ONLY IN A CONTAINER BUILT FROM THE SHIPPED IMAGE, never on a host. The answer is
 * a property of the patched SoftHSM and p11-kit the image carries; a stock SoftHSM or an
 * unpatched p11-kit lacks Ed25519, ML-DSA and the PSS restriction outright, so a host run
 * measures a platform FastPKI does not ship. The image has no compiler, so add one on top:
 *
 *   printf 'FROM fastpki:local\nUSER root\nRUN apk add --no-cache gcc musl-dev\n
 *           COPY tests/wrapprobe.c /probe/wrapprobe.c\n
 *           RUN cc -o /probe/wrapprobe /probe/wrapprobe.c\n' > /tmp/Dockerfile.probe
 *   docker build -f /tmp/Dockerfile.probe -t fastpki-wrapprobe .
 *   docker run --rm fastpki-wrapprobe sh -c '
 *     mkdir -p /tmp/tok && printf "directories.tokendir = /tmp/tok\n" > /tmp/s.conf &&
 *     export SOFTHSM2_CONF=/tmp/s.conf &&
 *     softhsm2-util --init-token --free --label probe --so-pin 1234 --pin 1234 &&
 *     /probe/wrapprobe <the image'"'"'s libsofthsm2.so> 1234'
 *
 * Run it a second time through `p11-kit server` and p11-kit-client.so, which is the path
 * the product takes, because the RPC relay drops mechanisms it cannot serialise.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE;

typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_ULONG hashAlg, mgf, source; void *pSourceData; CK_ULONG ulSourceDataLen; }
        CK_RSA_PKCS_OAEP_PARAMS;
typedef struct { CK_ULONG kdf; CK_ULONG ulSharedDataLen; CK_BYTE *pSharedData;
                 CK_ULONG ulPublicDataLen; CK_BYTE *pPublicData; } CK_ECDH1_DERIVE_PARAMS;

/* CK_FUNCTION_LIST in its standard order. Entries we never call stay void*; the ones we
 * do are cast at the call site, which is what keeps this header-free. */
struct CKFL {
    CK_BYTE ver[2];
    void *Initialize, *Finalize, *GetInfo, *GetFunctionList, *GetSlotList, *GetSlotInfo,
         *GetTokenInfo, *GetMechanismList, *GetMechanismInfo, *InitToken, *InitPIN, *SetPIN,
         *OpenSession, *CloseSession, *CloseAllSessions, *GetSessionInfo, *GetOperationState,
         *SetOperationState, *Login, *Logout, *CreateObject, *CopyObject, *DestroyObject,
         *GetObjectSize, *GetAttributeValue, *SetAttributeValue, *FindObjectsInit,
         *FindObjects, *FindObjectsFinal, *EncryptInit, *Encrypt, *EncryptUpdate,
         *EncryptFinal, *DecryptInit, *Decrypt, *DecryptUpdate, *DecryptFinal, *DigestInit,
         *Digest, *DigestUpdate, *DigestKey, *DigestFinal, *SignInit, *Sign, *SignUpdate,
         *SignFinal, *SignRecoverInit, *SignRecover, *VerifyInit, *Verify, *VerifyUpdate,
         *VerifyFinal, *VerifyRecoverInit, *VerifyRecover, *DigestEncryptUpdate,
         *DecryptDigestUpdate, *SignEncryptUpdate, *DecryptVerifyUpdate, *GenerateKey,
         *GenerateKeyPair, *WrapKey, *UnwrapKey, *DeriveKey;
};

#define CKA_CLASS 0x0000UL
#define CKA_TOKEN 0x0001UL
#define CKA_LABEL 0x0003UL
#define CKA_KEY_TYPE 0x0100UL
#define CKA_SENSITIVE 0x0103UL
#define CKA_WRAP 0x0106UL
#define CKA_UNWRAP 0x0107UL
#define CKA_SIGN 0x0108UL
#define CKA_VERIFY 0x010AUL
#define CKA_MODULUS_BITS 0x0121UL
#define CKA_PUBLIC_EXPONENT 0x0122UL
#define CKA_VALUE_LEN 0x0161UL
#define CKA_EXTRACTABLE 0x0162UL
#define CKA_DERIVE 0x010CUL
#define CKA_EC_PARAMS 0x0180UL
#define CKA_EC_POINT 0x0181UL

#define CKO_PUBLIC_KEY 0x0002UL
#define CKO_PRIVATE_KEY 0x0003UL
#define CKO_SECRET_KEY 0x0004UL
#define CKK_RSA 0x0000UL
#define CKK_AES 0x001FUL

#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x0000UL
#define CKM_RSA_PKCS_OAEP 0x0009UL
#define CKM_SHA256_RSA_PKCS 0x0040UL
#define CKM_SHA256 0x0250UL
#define CKM_SHA_1 0x0220UL
#define CKM_AES_KEY_GEN 0x1080UL
#define CKM_AES_KEY_WRAP_PAD 0x210AUL
#define CKM_EC_KEY_PAIR_GEN 0x1040UL
#define CKM_ECDH1_DERIVE 0x1050UL
#define CKD_NULL 0x0001UL
#define CKK_EC 0x0003UL

#define CKF_RW_SESSION 0x0002UL
#define CKF_SERIAL_SESSION 0x0004UL
#define CKU_USER 1UL

/* The other CA key types the console offers. Values are PKCS#11 3.0/3.2 wire numbers. */
#define CKK_EC_EDWARDS 0x0040UL
#define CKK_ML_DSA 0x004AUL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN 0x1055UL
#define CKM_ML_DSA_KEY_PAIR_GEN 0x001CUL
#define CKM_ECDSA 0x1041UL
#define CKM_EDDSA 0x1057UL
#define CKM_ML_DSA 0x001DUL
#define CKM_RSA_PKCS_PSS 0x000DUL
#define CKM_SHA256_RSA_PKCS_PSS 0x0043UL
#define CKM_SHA384_RSA_PKCS_PSS 0x0044UL
#define CKM_SHA512_RSA_PKCS_PSS 0x0045UL
#define CKG_MGF1_SHA256 0x0002UL
#define CKA_PARAMETER_SET 0x061DUL
#define CKA_ALLOWED_MECHANISMS 0x40000600UL
#define CKP_ML_DSA_65 0x0002UL

typedef struct { CK_ULONG hashAlg, mgf, sLen; } CK_RSA_PKCS_PSS_PARAMS;

static int fails = 0;
static void ok(const char *what, int cond, unsigned long rv) {
    if (cond) { printf("  [PASS] %s\n", what); }
    else { printf("  [FAIL] %s (CKR 0x%lx)\n", what, rv); fails++; }
}

/* One CA key type through the whole replication round trip: generate SENSITIVE and
 * EXTRACTABLE, wrap under the AES KEK, unwrap as a new object, sign with the COPY and verify
 * with the ORIGINAL public key. Each stage reports on its own, so "the probe's template is
 * wrong" (keygen fails) is never read as "the token will not wrap this" (wrap fails).
 *
 * ⚠️ RUN THIS ONLY IN A CONTAINER BUILT FROM THE SHIPPED IMAGE. A stock SoftHSM or an
 * unpatched p11-kit does not have Ed25519, ML-DSA or the PSS mechanism restriction at all,
 * and a probe that can only see RSA and P-256 is how "replicable keys are RSA or P-256 only"
 * became a rule nobody had measured. */
struct keycase {
    const char *name;
    CK_ULONG keytype, genmech, signmech;
    const CK_BYTE *ecparams; CK_ULONG ecparams_len;   /* EC / EdDSA curve, or NULL */
    CK_ULONG paramset;                                 /* ML-DSA parameter set, or 0 */
    CK_ULONG modbits;                                  /* RSA, or 0 */
    int pss;                                           /* RSA-PSS: restrict + PSS params */
};

static void round_trip(struct CKFL *f, CK_SESSION_HANDLE s, CK_OBJECT_HANDLE hAes,
                       const struct keycase *k) {
    char what[160];
    unsigned long rv;
    CK_BYTE t = 1;
    CK_ULONG cls_pub = CKO_PUBLIC_KEY, cls_prv = CKO_PRIVATE_KEY, kt = k->keytype;
    CK_ULONG ps = k->paramset, mb = k->modbits;
    CK_BYTE e[] = { 1, 0, 1 };
    CK_ULONG allowed[] = { CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS,
                           CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS };
    CK_ATTRIBUTE pub[8], prv[10], unw[10];
    CK_ULONG np = 0, nv = 0, nu = 0;

    printf("  -- %s --\n", k->name);
    pub[np++] = (CK_ATTRIBUTE){ CKA_CLASS, &cls_pub, sizeof cls_pub };
    pub[np++] = (CK_ATTRIBUTE){ CKA_KEY_TYPE, &kt, sizeof kt };
    pub[np++] = (CK_ATTRIBUTE){ CKA_TOKEN, &t, sizeof t };
    pub[np++] = (CK_ATTRIBUTE){ CKA_VERIFY, &t, sizeof t };
    if (k->ecparams) pub[np++] = (CK_ATTRIBUTE){ CKA_EC_PARAMS, (void *)k->ecparams, k->ecparams_len };
    if (k->paramset) pub[np++] = (CK_ATTRIBUTE){ CKA_PARAMETER_SET, &ps, sizeof ps };
    if (k->modbits) {
        pub[np++] = (CK_ATTRIBUTE){ CKA_MODULUS_BITS, &mb, sizeof mb };
        pub[np++] = (CK_ATTRIBUTE){ CKA_PUBLIC_EXPONENT, e, sizeof e };
    }
    CK_ATTRIBUTE common[] = {
        { CKA_CLASS, &cls_prv, sizeof cls_prv }, { CKA_KEY_TYPE, &kt, sizeof kt },
        { CKA_TOKEN, &t, sizeof t }, { CKA_SIGN, &t, sizeof t },
        { CKA_SENSITIVE, &t, sizeof t }, { CKA_EXTRACTABLE, &t, sizeof t },
    };
    for (CK_ULONG i = 0; i < 6; i++) { prv[nv++] = common[i]; unw[nu++] = common[i]; }
    if (k->pss) {
        prv[nv++] = (CK_ATTRIBUTE){ CKA_ALLOWED_MECHANISMS, allowed, sizeof allowed };
        unw[nu++] = (CK_ATTRIBUTE){ CKA_ALLOWED_MECHANISMS, allowed, sizeof allowed };
    }

    CK_MECHANISM mg = { k->genmech, NULL, 0 };
    CK_OBJECT_HANDLE hPub = 0, hPrv = 0;
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG,
                   CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *))
          f->GenerateKeyPair)(s, &mg, pub, np, prv, nv, &hPub, &hPrv);
    snprintf(what, sizeof what, "%s: a SENSITIVE, EXTRACTABLE key is generated", k->name);
    ok(what, rv == 0, rv);
    if (rv != 0) return;

    CK_BYTE blob[16384]; CK_ULONG blen = sizeof blob;
    CK_MECHANISM mw = { CKM_AES_KEY_WRAP_PAD, NULL, 0 };
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE,
                   CK_BYTE *, CK_ULONG *))f->WrapKey)(s, &mw, hAes, hPrv, blob, &blen);
    snprintf(what, sizeof what, "%s: the PRIVATE key wraps (CKM_AES_KEY_WRAP_PAD)", k->name);
    ok(what, rv == 0, rv);
    if (rv != 0) return;
    printf("         wrapped blob: %lu bytes\n", blen);

    CK_OBJECT_HANDLE hCopy = 0;
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_BYTE *, CK_ULONG,
                   CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *))f->UnwrapKey)(
             s, &mw, hAes, blob, blen, unw, nu, &hCopy);
    snprintf(what, sizeof what, "%s: and unwraps into the token", k->name);
    ok(what, rv == 0, rv);
    if (rv != 0) return;

    /* ECDSA signs a digest; the others sign the message. 48 bytes suits every EC curve. */
    CK_BYTE msg[48];
    for (int i = 0; i < 48; i++) msg[i] = (CK_BYTE)(0x5a ^ i);
    CK_ULONG mlen = (k->signmech == CKM_ECDSA) ? 48 : sizeof msg;
    CK_RSA_PKCS_PSS_PARAMS pp = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_MECHANISM ms = { k->signmech, k->pss ? &pp : NULL, k->pss ? sizeof pp : 0 };
    CK_BYTE sig[8192]; CK_ULONG siglen = sizeof sig;
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE))f->SignInit)(s, &ms, hCopy);
    if (rv == 0)
        rv = ((int (*)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *))f->Sign)(
                 s, msg, mlen, sig, &siglen);
    snprintf(what, sizeof what, "%s: the COPY signs", k->name);
    ok(what, rv == 0, rv);
    if (rv != 0) return;
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE))f->VerifyInit)(s, &ms, hPub);
    if (rv == 0)
        rv = ((int (*)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG))f->Verify)(
                 s, msg, mlen, sig, siglen);
    snprintf(what, sizeof what, "%s: and the ORIGINAL public key verifies it", k->name);
    ok(what, rv == 0, rv);

    CK_BYTE ex = 0;
    CK_ATTRIBUTE ga[] = { { CKA_EXTRACTABLE, &ex, sizeof ex } };
    rv = ((int (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *, CK_ULONG))
          f->GetAttributeValue)(s, hCopy, ga, 1);
    snprintf(what, sizeof what, "%s: the copy is extractable in turn", k->name);
    ok(what, rv == 0 && ex == 1, rv);

    if (k->pss) {
        /* ⚠️ THE RESTRICTION MUST TRAVEL. A PSS key is CKK_RSA plus CKA_ALLOWED_MECHANISMS, and
         * the wrapped PKCS#8 blob carries only the key. A copy that accepts PKCS#1 v1.5 is a
         * different key policy under the same certificate. */
        CK_MECHANISM m15 = { CKM_SHA256_RSA_PKCS, NULL, 0 };
        rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE))f->SignInit)(s, &m15, hCopy);
        if (rv == 0) {   /* finish the operation so the session is usable again */
            CK_BYTE sb[1024]; CK_ULONG sl = sizeof sb;
            ((int (*)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *))f->Sign)(
                s, msg, sizeof msg, sb, &sl);
        }
        snprintf(what, sizeof what, "%s: the copy still REFUSES PKCS#1 v1.5", k->name);
        ok(what, rv != 0, rv);
    }
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <module.so> <pin>\n", argv[0]); return 2; }
    const char *pin = argv[2];

    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    int (*getfl)(struct CKFL **) = (int (*)(struct CKFL **))dlsym(h, "C_GetFunctionList");
    if (!getfl) { fprintf(stderr, "no C_GetFunctionList\n"); return 2; }
    struct CKFL *f = NULL;
    if (getfl(&f) != 0 || !f) { fprintf(stderr, "C_GetFunctionList failed\n"); return 2; }

    unsigned long rv;
    rv = ((int (*)(void *))f->Initialize)(NULL);
    if (rv != 0) { fprintf(stderr, "C_Initialize: 0x%lx\n", rv); return 2; }

    CK_SLOT_ID slots[16]; CK_ULONG n = 16;
    rv = ((int (*)(CK_BYTE, CK_SLOT_ID *, CK_ULONG *))f->GetSlotList)(1, slots, &n);
    if (rv != 0 || n == 0) { fprintf(stderr, "no token present (0x%lx)\n", rv); return 2; }

    CK_SESSION_HANDLE s;
    rv = ((int (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))f->OpenSession)(
             slots[0], CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &s);
    if (rv != 0) { fprintf(stderr, "C_OpenSession: 0x%lx\n", rv); return 2; }
    rv = ((int (*)(CK_SESSION_HANDLE, CK_ULONG, const CK_BYTE *, CK_ULONG))f->Login)(
             s, CKU_USER, (const CK_BYTE *)pin, (CK_ULONG)strlen(pin));
    if (rv != 0) { fprintf(stderr, "C_Login: 0x%lx\n", rv); return 2; }

    /* ⚠️ CK_BBOOL IS ONE BYTE. Declaring these CK_ULONG makes every boolean attribute
     * 8 bytes wide and the module rejects the template with CKR_ATTRIBUTE_VALUE_INVALID —
     * which reads exactly like "this token will not create such a key" and is not. */
    CK_BYTE t = 1, ff = 0;
    CK_ULONG bits = 2048, aeslen = 32;
    CK_ULONG cls_pub = CKO_PUBLIC_KEY, cls_prv = CKO_PRIVATE_KEY, cls_sec = CKO_SECRET_KEY;
    CK_ULONG kt_rsa = CKK_RSA, kt_aes = CKK_AES;
    CK_BYTE e[] = { 1, 0, 1 };

    /* A CA-shaped key: SENSITIVE so plaintext can never be read out, EXTRACTABLE so it may
     * be WRAPPED. PKCS#11 keeps those two separate on purpose, and that pair is the whole
     * basis of the design — a key created without it can never be replicated, which is why
     * this has to be decided at CA creation and not at failover. */
    CK_ATTRIBUTE pub[] = {
        { CKA_CLASS, &cls_pub, sizeof cls_pub }, { CKA_KEY_TYPE, &kt_rsa, sizeof kt_rsa },
        { CKA_TOKEN, &t, sizeof t }, { CKA_VERIFY, &t, sizeof t },
        { CKA_MODULUS_BITS, &bits, sizeof bits }, { CKA_PUBLIC_EXPONENT, e, sizeof e },
        { CKA_LABEL, (void *)"probe-ca", 8 },
    };
    CK_ATTRIBUTE prv[] = {
        { CKA_CLASS, &cls_prv, sizeof cls_prv }, { CKA_KEY_TYPE, &kt_rsa, sizeof kt_rsa },
        { CKA_TOKEN, &t, sizeof t }, { CKA_SIGN, &t, sizeof t },
        { CKA_SENSITIVE, &t, sizeof t }, { CKA_EXTRACTABLE, &t, sizeof t },
        { CKA_LABEL, (void *)"probe-ca", 8 },
    };
    CK_MECHANISM mkp = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE hPub = 0, hPrv = 0;
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG,
                   CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *))
          f->GenerateKeyPair)(s, &mkp, pub, 7, prv, 7, &hPub, &hPrv);
    ok("a CA key can be created SENSITIVE and EXTRACTABLE", rv == 0, rv);
    if (rv != 0) goto done;

    /* The ephemeral AES key that wraps it. */
    CK_ATTRIBUTE sec[] = {
        { CKA_CLASS, &cls_sec, sizeof cls_sec }, { CKA_KEY_TYPE, &kt_aes, sizeof kt_aes },
        { CKA_TOKEN, &t, sizeof t }, { CKA_VALUE_LEN, &aeslen, sizeof aeslen },
        { CKA_WRAP, &t, sizeof t }, { CKA_UNWRAP, &t, sizeof t },
        { CKA_SENSITIVE, &t, sizeof t }, { CKA_EXTRACTABLE, &t, sizeof t },
        { CKA_LABEL, (void *)"probe-kek", 9 },
    };
    CK_MECHANISM mag = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE hAes = 0;
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG,
                   CK_OBJECT_HANDLE *))f->GenerateKey)(s, &mag, sec, 9, &hAes);
    ok("an AES-256 KEK can be created with wrap/unwrap", rv == 0, rv);
    if (rv != 0) goto done;

    /* THE question: wrap a PRIVATE key under the AES KEK. */
    CK_BYTE blob[8192]; CK_ULONG blen = sizeof blob;
    CK_MECHANISM mw = { CKM_AES_KEY_WRAP_PAD, NULL, 0 };
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE,
                   CK_BYTE *, CK_ULONG *))f->WrapKey)(s, &mw, hAes, hPrv, blob, &blen);
    ok("the CA PRIVATE key can be wrapped (CKM_AES_KEY_WRAP_PAD)", rv == 0, rv);
    if (rv == 0) printf("         wrapped blob: %lu bytes\n", blen);
    if (rv != 0) goto oaep;

    /* Unwrap it back as a fresh, signing-capable private key — what the peer node does. */
    CK_ATTRIBUTE unw[] = {
        { CKA_CLASS, &cls_prv, sizeof cls_prv }, { CKA_KEY_TYPE, &kt_rsa, sizeof kt_rsa },
        { CKA_TOKEN, &t, sizeof t }, { CKA_SIGN, &t, sizeof t },
        { CKA_SENSITIVE, &t, sizeof t }, { CKA_EXTRACTABLE, &t, sizeof t },
        { CKA_LABEL, (void *)"probe-ca2", 9 },
    };
    CK_OBJECT_HANDLE hPrv2 = 0;
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_BYTE *, CK_ULONG,
                   CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *))f->UnwrapKey)(
             s, &mw, hAes, blob, blen, unw, 7, &hPrv2);
    ok("  and unwrapped again into the token", rv == 0, rv);
    if (rv != 0) goto oaep;

    /* ⚠️ THE ACTUAL ASSERTION. Bytes coming back from C_WrapKey prove nothing; what matters
     * is that the unwrapped handle is the SAME key. Sign with the copy, verify with the
     * ORIGINAL public key — if that holds, replication preserves the CA identity. */
    CK_BYTE msg[] = "fastpki wrap round trip";
    CK_BYTE sig[1024]; CK_ULONG siglen = sizeof sig;
    CK_MECHANISM ms = { CKM_SHA256_RSA_PKCS, NULL, 0 };
    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE))f->SignInit)(s, &ms, hPrv2);
    if (rv == 0)
        rv = ((int (*)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *))f->Sign)(
                 s, msg, sizeof msg - 1, sig, &siglen);
    ok("  the unwrapped key signs", rv == 0, rv);
    if (rv == 0) {
        rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE))f->VerifyInit)(s, &ms, hPub);
        if (rv == 0)
            rv = ((int (*)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG))f->Verify)(
                     s, msg, sizeof msg - 1, sig, siglen);
        ok("  and the ORIGINAL public key verifies it — same key, replicated", rv == 0, rv);
    }

    /* Every other CA key type, through the same round trip. */
    {
        static const CK_BYTE p384[]   = { 0x06,0x05,0x2B,0x81,0x04,0x00,0x22 };
        static const CK_BYTE p521[]   = { 0x06,0x05,0x2B,0x81,0x04,0x00,0x23 };
        static const CK_BYTE ed25519[] = { 0x06,0x03,0x2B,0x65,0x70 };
        static const CK_BYTE ed448[]   = { 0x06,0x03,0x2B,0x65,0x71 };
        const struct keycase cases[] = {
            { "EC P-384",  CKK_EC, CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, p384, sizeof p384, 0, 0, 0 },
            { "EC P-521",  CKK_EC, CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, p521, sizeof p521, 0, 0, 0 },
            { "Ed25519",   CKK_EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA,
                           ed25519, sizeof ed25519, 0, 0, 0 },
            { "Ed448",     CKK_EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA,
                           ed448, sizeof ed448, 0, 0, 0 },
            { "ML-DSA-65", CKK_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA,
                           NULL, 0, CKP_ML_DSA_65, 0, 0 },
            { "RSA-PSS",   CKK_RSA, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_SHA256_RSA_PKCS_PSS,
                           NULL, 0, 0, 2048, 1 },
        };
        for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++)
            round_trip(f, s, hAes, &cases[i]);
    }

oaep:
    /* The other half of the envelope: the AES KEK travels wrapped under the destination
     * node's public key, so no shared secret has to be provisioned anywhere. */
    {
        /* ⚠️ WHICH OAEP HASH THE TOKEN ACCEPTS IS NOT A DETAIL. SoftHSM rejects a
         * parameter block it does not like with CKR_ARGUMENTS_BAD, which is
         * indistinguishable from "we called it wrong" — so try SHA-256 and fall back to
         * SHA-1, and REPORT which one the token actually took. The answer constrains the
         * design: if only SHA-1 is available for OAEP, that is a fact the KEK distribution
         * has to be built around rather than discovered later. */
        CK_ULONG hashes[2] = { CKM_SHA256, CKM_SHA_1 };
        CK_ULONG mgfs[2]   = { 0x0002UL,   0x0001UL };
        const char *names[2] = { "SHA-256", "SHA-1" };
        CK_BYTE kb[1024]; CK_ULONG kl = sizeof kb;
        int which = -1;
        CK_MECHANISM mo = { CKM_RSA_PKCS_OAEP, NULL, 0 };
        /* ⚠️ OUTER SCOPE, deliberately. The parameter block must outlive the wrap: the
         * unwrap below reuses `mo`, and a params struct declared inside the branch that
         * chose it leaves mo.pParameter dangling. That read as "the token cannot unwrap"
         * on one platform and worked on another, which is the worst way to be wrong. */
        CK_RSA_PKCS_OAEP_PARAMS opUse = { 0, 0, 1UL, NULL, 0 };
        for (int i = 0; i < 2; i++) {
            CK_RSA_PKCS_OAEP_PARAMS op = { hashes[i], mgfs[i], 1UL, NULL, 0 };
            mo.pParameter = &op; mo.ulParameterLen = sizeof op;
            kl = sizeof kb;
            rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE,
                           CK_OBJECT_HANDLE, CK_BYTE *, CK_ULONG *))f->WrapKey)(
                     s, &mo, hPub, hAes, kb, &kl);
            if (rv == 0) { which = i; break; }
            printf("         OAEP/%s refused (CKR 0x%lx)\n", names[i], rv);
        }
        ok("the KEK can be wrapped to a peer's public key (RSA-OAEP)", which >= 0, rv);
        if (which >= 0) {
            printf("         accepted OAEP hash: %s\n", names[which]);
            opUse.hashAlg = hashes[which]; opUse.mgf = mgfs[which];
            mo.pParameter = &opUse; mo.ulParameterLen = sizeof opUse;
        }
        if (which >= 0) {
            CK_ATTRIBUTE ua[] = {
                { CKA_CLASS, &cls_sec, sizeof cls_sec }, { CKA_KEY_TYPE, &kt_aes, sizeof kt_aes },
                { CKA_TOKEN, &ff, sizeof ff }, { CKA_WRAP, &t, sizeof t },
                { CKA_UNWRAP, &t, sizeof t },
            };
            CK_OBJECT_HANDLE hAes2 = 0;
            rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_BYTE *,
                           CK_ULONG, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *))f->UnwrapKey)(
                     s, &mo, hPrv, kb, kl, ua, 5, &hAes2);
            ok("  and unwrapped by that node's private half", rv == 0, rv);
        }
    }

    /* ── The OAEP-free alternative: static-static ECDH ──────────────────────────────
     *
     * If two nodes each hold an EC keypair, each can derive the SAME AES key from its own
     * private half and the other's public point — so the KEK is never transmitted at all,
     * in any form. That sidesteps the OAEP hash question entirely, which matters because a
     * stock SoftHSM accepts OAEP only with SHA-1.
     *
     * ⚠️ The two derived keys are SENSITIVE, so they cannot be read out and compared. The
     * proof that they are equal is functional: wrap the CA key under A's key and unwrap it
     * with B's. If the derivation disagreed, the unwrap fails. */
    {
        CK_ULONG kt_ec = CKK_EC;
        /* prime256v1 as a DER-encoded named-curve OID. */
        CK_BYTE p256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
        CK_MECHANISM mec = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
        CK_OBJECT_HANDLE aPub = 0, aPrv = 0, bPub = 0, bPrv = 0;
        int made = 1;

        for (int node = 0; node < 2; node++) {
            CK_ATTRIBUTE ep[] = {
                { CKA_CLASS, &cls_pub, sizeof cls_pub }, { CKA_KEY_TYPE, &kt_ec, sizeof kt_ec },
                { CKA_TOKEN, &t, sizeof t }, { CKA_EC_PARAMS, p256, sizeof p256 },
            };
            CK_ATTRIBUTE ev[] = {
                { CKA_CLASS, &cls_prv, sizeof cls_prv }, { CKA_KEY_TYPE, &kt_ec, sizeof kt_ec },
                { CKA_TOKEN, &t, sizeof t }, { CKA_DERIVE, &t, sizeof t },
                { CKA_SENSITIVE, &t, sizeof t },
            };
            CK_OBJECT_HANDLE pk = 0, sk = 0;
            rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG,
                           CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *))
                  f->GenerateKeyPair)(s, &mec, ep, 4, ev, 5, &pk, &sk);
            if (rv != 0) { made = 0; break; }
            if (node == 0) { aPub = pk; aPrv = sk; } else { bPub = pk; bPrv = sk; }
        }
        ok("two EC KEK pairs can be created (one per node)", made, rv);

        if (made) {
            /* Read each public point. SoftHSM returns CKA_EC_POINT DER-wrapped in an OCTET
             * STRING; CKM_ECDH1_DERIVE wants the raw point, so try raw first and fall back
             * to the wrapped form rather than guessing which this build hands back. */
            CK_BYTE ptA[256], ptB[256];
            CK_ATTRIBUTE ga[] = { { CKA_EC_POINT, ptA, sizeof ptA } };
            CK_ATTRIBUTE gb[] = { { CKA_EC_POINT, ptB, sizeof ptB } };
            unsigned long rA = ((int (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *,
                                         CK_ULONG))f->GetAttributeValue)(s, aPub, ga, 1);
            unsigned long rB = ((int (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *,
                                         CK_ULONG))f->GetAttributeValue)(s, bPub, gb, 1);
            ok("  their public points can be read back", rA == 0 && rB == 0, rA ? rA : rB);

            if (rA == 0 && rB == 0) {
                CK_BYTE *rawA = ptA, *rawB = ptB;
                CK_ULONG lenA = ga[0].ulValueLen, lenB = gb[0].ulValueLen;
                if (lenA > 2 && ptA[0] == 0x04 && ptA[1] == lenA - 2) { rawA += 2; lenA -= 2; }
                if (lenB > 2 && ptB[0] == 0x04 && ptB[1] == lenB - 2) { rawB += 2; lenB -= 2; }
                printf("         EC point: %lu bytes after unwrapping the OCTET STRING\n", lenA);

                CK_ULONG derlen = 32;
                CK_ATTRIBUTE dk[] = {
                    { CKA_CLASS, &cls_sec, sizeof cls_sec },
                    { CKA_KEY_TYPE, &kt_aes, sizeof kt_aes },
                    { CKA_TOKEN, &ff, sizeof ff }, { CKA_VALUE_LEN, &derlen, sizeof derlen },
                    { CKA_WRAP, &t, sizeof t }, { CKA_UNWRAP, &t, sizeof t },
                    { CKA_SENSITIVE, &t, sizeof t },
                };
                CK_ECDH1_DERIVE_PARAMS pa = { CKD_NULL, 0, NULL, lenB, rawB };
                CK_ECDH1_DERIVE_PARAMS pb = { CKD_NULL, 0, NULL, lenA, rawA };
                CK_MECHANISM ma = { CKM_ECDH1_DERIVE, &pa, sizeof pa };
                CK_MECHANISM mb = { CKM_ECDH1_DERIVE, &pb, sizeof pb };
                CK_OBJECT_HANDLE kA = 0, kB = 0;

                /* A derives from ITS private half and B's public point, and vice versa. */
                unsigned long dA = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE,
                                             CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *))
                                    f->DeriveKey)(s, &ma, aPrv, dk, 7, &kA);
                unsigned long dB = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE,
                                             CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *))
                                    f->DeriveKey)(s, &mb, bPrv, dk, 7, &kB);
                ok("  each node derives an AES-256 KEK (CKM_ECDH1_DERIVE, CKD_NULL)",
                   dA == 0 && dB == 0, dA ? dA : dB);

                if (dA == 0 && dB == 0) {
                    /* THE assertion: wrap with A's, unwrap with B's. */
                    CK_BYTE eb[8192]; CK_ULONG el = sizeof eb;
                    CK_MECHANISM mw2 = { CKM_AES_KEY_WRAP_PAD, NULL, 0 };
                    rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE,
                                   CK_OBJECT_HANDLE, CK_BYTE *, CK_ULONG *))f->WrapKey)(
                             s, &mw2, kA, hPrv, eb, &el);
                    ok("  the CA key wraps under the derived KEK", rv == 0, rv);
                    if (rv == 0) {
                        CK_ATTRIBUTE u2[] = {
                            { CKA_CLASS, &cls_prv, sizeof cls_prv },
                            { CKA_KEY_TYPE, &kt_rsa, sizeof kt_rsa },
                            { CKA_TOKEN, &ff, sizeof ff }, { CKA_SIGN, &t, sizeof t },
                            { CKA_SENSITIVE, &t, sizeof t }, { CKA_EXTRACTABLE, &t, sizeof t },
                        };
                        CK_OBJECT_HANDLE hPrv3 = 0;
                        rv = ((int (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE,
                                       CK_BYTE *, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG,
                                       CK_OBJECT_HANDLE *))f->UnwrapKey)(
                                 s, &mw2, kB, eb, el, u2, 6, &hPrv3);
                        ok("  and unwraps under the OTHER node's — the two derivations agree",
                           rv == 0, rv);
                    }
                }
            }
        }
    }

done:
    ((int (*)(void *))f->Finalize)(NULL);
    printf("\n=== WRAP PROBE: %s ===\n", fails ? "UNSUPPORTED" : "SUPPORTED");
    return fails ? 1 : 0;
}
