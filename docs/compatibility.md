# Interoperability: what can verify what FastPKI issues

The console offers every algorithm OpenSSL 3.5 supports, including a post-quantum key for
a root CA. Not every relying party can check a signature made by one.

This page records the constraints that are known, so the decision is made before a CA
exists rather than after a client rejects it. **The CA key algorithm is the one choice that
is expensive to reverse**: changing it means re-keying the CA and re-issuing everything
below it.

## Contents

1. [The short version](#1-the-short-version)
2. [Measured: what verifies what](#2-measured-what-verifies-what)
3. [Microsoft Windows](#3-microsoft-windows)
4. [Constraints inside FastPKI itself](#4-constraints-inside-fastpki-itself)
5. [Testing a relying party before you commit](#5-testing-a-relying-party-before-you-commit)

---

## 1. The short version

| CA key | verified against | use it when | avoid it when |
|---|---|---|---|
| **EC** (P-256/384/521) | every stack tested, Windows included | the default — smallest certificates, and nothing tested rejects it | you must support a client older than roughly 2010 |
| **RSA** (3072+) | every stack tested, Windows included | maximum reach, including old appliances | certificate size or signing throughput matters |
| **Ed25519 / Ed448** | OpenSSL and GnuTLS only — **not Windows, not libpq** | a closed estate with no Windows and no PostgreSQL in the trust path | either of those is in scope (§3, §4.1) |
| **ML-DSA-44/65/87** | OpenSSL 3.5+ only | testing post-quantum readiness between endpoints you control | anything general-purpose — the installed base does not verify it yet |

Three results from that table:

**Ed25519 and Ed448 fail on Windows exactly as post-quantum keys do.** Both complete
handshakes on OpenSSL and GnuTLS, including against curl on OpenSSL 3.0. Windows Server
2022 rejects a CA using either with the same `NTE_BAD_ALGID` it gives ML-DSA. Combined
with the PostgreSQL failure, an Ed25519 CA has two hard holes, not one.

**The constraint is the CA's key, not the certificate's key.** Windows validated a chain
whose *leaf* carried an Ed25519 or ML-DSA public key without complaint, because an EC CA had
signed it. What it cannot do is verify a signature *made by* one of those keys. So the
algorithm that decides compatibility is the one on the issuer, all the way up the chain.

**Mixing does not rescue you.** Issuing RSA leaves from an ML-DSA root does not make the
chain verifiable: the sub CA and leaf certificates carry the *root's* ML-DSA signature, and
a client that cannot verify that algorithm cannot build the path. The only case where a
trust anchor's own algorithm stops mattering is when the client is given the sub CA
directly as the anchor, so nothing it verifies was signed by the root.

---

## 2. Measured: what verifies what

A self-signed CA and a `localhost` leaf were generated for each algorithm; the leaf was
served over TLS 1.3 by `openssl s_server` and fetched by each client with the CA as its
only trust anchor. §5.1 has the full method and the client versions.

| CA + leaf key | OpenSSL 3.5.8 (shipped image) | OpenSSL 3.6.3 | Python 3.13 (OpenSSL 3.6) | curl 8.9 (OpenSSL 3.0.16) | GnuTLS 3.8.10 | libpq 16.14 | Windows Server 2022 |
|---|---|---|---|---|---|---|---|
| **RSA-3072** | ok | ok | ok | ok | ok | ok | ok |
| **RSA-PSS** | ok | ok | ok | ok | ok | ok | ok |
| **EC P-256** | ok | ok | ok | ok | ok | ok | ok |
| **Ed25519** | ok | ok | ok | ok | ok | **fails** | **fails** |
| **Ed448** | ok | ok | ok | ok | ok | **fails** | **fails** |
| **ML-DSA-44/65/87** | ok | ok | ok | **fails** | **fails** | **fails** | **fails** |

Not tested, and not assumed: Java/JDK, Go, browsers, macOS/iOS Secure Transport, Android,
and network appliances. Treat every one of them as unknown until measured.

### 2.1 ML-DSA is not excluded by the TLS standard — it is excluded by deployment

RFC 8446 does not mention ML-DSA; it was published in 2018 and FIPS 204 in 2024. TLS 1.3
needs no revision to carry a new signature algorithm — `signature_algorithms` is an
extensible IANA registry, ML-DSA code points have been allocated, and OpenSSL implements
them from 3.5. Measured inside the shipped image:

```
Peer signature type: mldsa65
Negotiated TLS1.3 group: X25519MLKEM768
Verify return code: 0 (ok)
```

That is a complete TLS 1.3 handshake authenticated by ML-DSA. The barrier is the installed
base, not the protocol, so it moves as clients update. An ML-DSA CA is testable now between
endpoints you control.

### 2.2 The two failure modes look nothing alike

**An ML-DSA leaf** fails in the handshake. The client never offered `mldsa*` in its
`signature_algorithms`, so the server cannot authenticate and the connection dies with an
alert:

```
TLSv1.3 (IN), TLS alert, handshake failure (552)
OpenSSL/3.0.16: error:0A000410:SSL routines::sslv3 alert handshake failure
```

**An ML-DSA CA** fails in path validation instead, and GnuTLS reports it as
`Public key signature verification has failed` — which reads like a corrupt certificate
rather than an unsupported algorithm. Neither message names ML-DSA, which is the main reason
this is hard to diagnose from the client side.

### 2.3 Mixing algorithms does not rescue the chain — measured

Issuing an **RSA leaf from an ML-DSA root** was tested directly. The leaf's public key is
`rsaEncryption` and its signature algorithm is `ML-DSA-65`, because the CA key signs it. curl,
GnuTLS and Windows all still fail on it — Windows with the same `NTE_BAD_ALGID` — while
OpenSSL 3.6 verifies it.

The only arrangement that removes the root's algorithm from the question is giving the client
the **sub CA** as its trust anchor, so nothing it verifies was signed by the root.

### 2.4 Certificate size

ML-DSA certificates are large enough to matter for constrained clients, UDP-based transports
and anything with a handshake size limit. Leaf certificates, PEM bytes, same subject and
extensions throughout:

| Ed25519 | EC P-256 | Ed448 | RSA-3072 | RSA-PSS | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|---|---|---|---|
| 566 | 648 | 664 | 1,529 | 1,675 | 5,527 | 7,594 | 10,247 |

An ML-DSA-87 chain is roughly sixteen times an EC one, before the handshake signature itself.

---

## 3. Microsoft Windows

Measured on **Windows Server 2022 Standard**, via `certutil` against a trust anchor imported
into the machine Root store.

| CA key | imports into Root store | `certutil -dump` | chain validates |
|---|---|---|---|
| RSA-3072, RSA-PSS, EC P-256 | yes | ok | ok |
| Ed25519, Ed448 | **yes** | `NTE_BAD_ALGID` | **no** |
| ML-DSA-44/65/87 | **yes** | `NTE_BAD_ALGID` | **no** |

### 3.1 The import succeeds, and that is the trap

An Ed25519, Ed448 or ML-DSA root **imports without error and is listed in the store**. All
eight test anchors appeared under `Cert:\LocalMachine\Root` afterwards, with their correct
subjects and signature-algorithm OIDs, and .NET's `X509Certificate2` parsed every one of
them.

What fails is any operation that must *verify a signature made by that key*:

```
CertUtil: -verify command FAILED: 0x80090008 (-2146893816 NTE_BAD_ALGID)
Cannot decode object: Invalid algorithm specified.
```

So the certificate is neither malformed nor rejected at the door. CryptoAPI simply has no
provider for the algorithm, and every chain built through that anchor fails. Seeing the
root listed in `certmgr.msc` is therefore not evidence that the trust works.

### 3.2 Ed25519 is not the safe middle ground

Ed25519 and Ed448 fail on Windows with the same error as ML-DSA. If Windows clients are in
scope, the choice is EC or RSA.

### 3.3 What the subject key may be is a separate question

A leaf carrying an **Ed25519 or ML-DSA public key** validated cleanly when an EC CA had
signed it — `certutil` parsed it and built the chain, reporting only
`CRYPT_E_NO_REVOCATION_CHECK`, which is the expected complaint for a test CA that publishes
no CRL or OCSP. Windows can therefore hold and verify a certificate whose subject key it
does not otherwise support; what it cannot do is check a signature that key's algorithm
produced.

Whether Windows will *negotiate TLS* with such a leaf, or generate such a key for
autoenrolment, are further questions that were not tested here. For enrolment purposes the
binding constraint is the CA, because it applies to the whole estate at once.

### 3.4 Post-quantum on later Windows

Microsoft's post-quantum support arrives in the Windows Server 2025 generation and later
servicing updates. **Confirm it against your own build before committing a CA to it** — the
support has been arriving across servicing updates rather than in one release, so a version
number alone is not a safe answer. §5 gives the test.

For Windows autoenrolment (MS-XCEP/WSTEP) all of this applies to the whole chain the client
must trust, not only the certificate it enrols for. A client that cannot verify the CA fails
with a policy or trust error rather than an algorithm one, which makes it easy to
misdiagnose.

---

## 4. Constraints inside FastPKI itself

These are not third-party limitations — they are places where FastPKI's own components
refuse an algorithm, and each one refuses up front rather than failing later.

### 4.1 PostgreSQL certificates must come from an EC or RSA CA

Ed25519, Ed448 and ML-DSA are one-shot signature schemes that name no separate digest. RFC
5929 `tls-server-end-point` channel binding must hash the server certificate using the
digest its signature algorithm names; libpq looks that up, gets `NID_undef`, and refuses
**before authentication**:

```
psql: error: connection to server failed: could not find digest for NID UNDEF
```

What the measurement shows, and what the message hides:

- **The server is fine.** PostgreSQL loads and serves all six certificate types without
  complaint. Nothing in its log indicates a problem — the failure is entirely in the client.
- **It is channel binding specifically.** Adding `channel_binding=disable` to the conninfo
  makes all three connect. **Do not leave it there.** Channel binding is what binds the
  SCRAM exchange to the TLS session; use it to confirm the diagnosis, then change the CA
  key. FastPKI's conninfo does not set the parameter, so it gets the default and hits this.
- **Established connections keep working**, so a node can look healthy while refusing every
  new connection — including its own services and mesh replication.

The signing CA's key decides the leaf's signature algorithm, so a node whose sub CA holds an
Ed448 or ML-DSA key cannot produce a usable database certificate at all. `fastpki-ca pg-tls`
and the console both refuse this rather than writing a certificate nothing can connect to.
Re-issue the database certificate from an EC or RSA CA, as
[`postgres.md`](postgres.md) §2.1 shows.

⚠️ **FastPKI requires PostgreSQL 17** ([`postgres.md`](postgres.md)), and the shipped image
and the native install both carry the 17 client. The libpq column of §2 was measured
against libpq 16.14 and has not been re-measured against 17 — re-measure before relying on
it, as §5.1 says of every cell.

### 4.2 A SCEP RA key must be RSA

The SCEP RA key decrypts the `PKIOperation` envelope, which needs RSA key transport.
`fastpki-scep` refuses to serve with a non-RSA RA key and says so, and the console refuses to
issue one. **RSA-PSS does not qualify** — OpenSSL rejects the operation at context
initialisation, so a client cannot even build the envelope to send.

This constrains the RA credential only. The CA behind it, and the certificates it issues,
are unaffected.

### 4.3 OpenSSL version floors

| feature | needs |
|---|---|
| everything else | OpenSSL 3.0 |
| `fastpki-cmp` | OpenSSL 3.2 (CRMF APIs) |
| ML-DSA | OpenSSL 3.5 |
| `-crl_check_all` satisfied by `-crl_download` alone | OpenSSL 3.6 |

These apply to clients too. An EST or CMP client on OpenSSL 3.0 cannot verify an ML-DSA
chain regardless of what the server sends.

### 4.4 Full-chain CRL checking needs the CRLs staged, not downloaded

Below OpenSSL 3.6, `-crl_check_all` demands a CRL for **every** certificate in the chain,
including the root. A root carries no CRL distribution point — a trust anchor has no issuer
to point at, and nothing revokes it — so `-crl_download` has no URL to fetch for it and
verification stops at the root's depth with:

```
verify error:num=3:unable to get certificate CRL
```

`-crl_download` also *replaces* the local CRL store rather than adding to it, so supplying
the root's CRL locally alongside it does not help either.

Stage the CRLs in a hashed directory and drop `-crl_download`. Every CRL required is named
inside the chain itself: the leaf's distribution point gives the issuing CA's CRL, and the
issuing CA's gives the root's — which also covers the root. Read each distribution point
out of the certificate above it, fetch that URL, then file the CRL under its own issuer
hash as `<hash>.r0`:

```bash
mkdir -p crls

# Once per CRL in the chain. <crl-url> is the CRL distribution point printed by
#   openssl x509 -in <cert> -noout -text | grep -A2 'CRL Distribution'
curl -fsS -o downloaded.crl "<crl-url>"
openssl crl -in downloaded.crl -inform DER -out "crls/$(openssl crl -in downloaded.crl \
    -inform DER -noout -hash).r0"
```

Then pass the directory as `-CApath`:

```bash
openssl s_client -CAfile root-ca.crt -CApath crls -servername "$PKI_DNS" \
    -x509_strict -crl_check_all -connect "$PKI_DNS:8090"
```

This verifies identically on 3.5 and 3.6, and keeps CRLs out of the `-CAfile`, which carries
trust anchors only. `demo/demo.txt` has a `stage_crls` helper that builds the directory, and
`demo/pki-demo.sh` does the same in `crl_capath`.

Checking only the leaf — `-crl_check -crl_download` — works on every version and needs no
staging, but does not confirm that the CAs above it are unrevoked.

### 4.5 Creating the key needs the shipped image

Ed25519, Ed448 and ML-DSA CA keys are generated **inside** the PKCS#11 token, and the stock
packaged SoftHSM and p11-kit drop those mechanisms. The container image builds all three
components from patched sources, which is why those algorithms appear in the New CA dropdown
there and may be missing on a native install. deployment.md covers this for host installs.

---

## 5. Testing a relying party before you commit

Create the CA you are considering, then verify a certificate from it on the client that
matters — before issuing anything real. A throwaway CA costs nothing and can be deleted.

The tests below use four files, so produce them first: `root.crt` and `sub_ca.crt` are the
CA certificates, downloaded from the console's **CAs** page; `leaf.crt` and `leaf.key` are
an ordinary certificate issued by that CA and its key — take them from **Inventory →
Request** with the key generated in the browser, which hands you both. Where a command
below says `ca.crt`, give it the certificate of whichever CA signed `leaf.crt`.

**Any OpenSSL client**, which also tells you the algorithm names in play:

```bash
openssl x509 -in ca.crt -noout -text | grep -m1 'Signature Algorithm'
openssl verify -CAfile root.crt -untrusted sub_ca.crt leaf.crt
```

`openssl verify` reads only the **first** certificate in a file, so intermediates must be
passed with `-untrusted` — a chain that fails without it is not necessarily a bad chain.

**Windows**, on the client that will actually enrol:

```
certutil -addstore -f Root root.crt      # succeeds even for an algorithm Windows cannot use
certutil -dump root.crt                  # THIS is the test that answers the question
certutil -verify -urlfetch leaf.crt
```

**Do not read `-addstore` as the answer.** It succeeds for every algorithm, and the anchor
then appears in `certmgr.msc` looking healthy. `certutil -dump` on the root is the honest
test: `NTE_BAD_ALGID` (0x80090008) means CryptoAPI has no provider for that signature
algorithm and no chain through this anchor will ever validate. `-verify` fails the same way.
A `CRYPT_E_NO_REVOCATION_CHECK` complaint, by contrast, is only about a missing CRL/OCSP and
says nothing about the algorithm.

**PostgreSQL**, which is worth testing explicitly because it fails before authentication and
established connections keep working:

```bash
psql "host=<node> sslmode=verify-full sslrootcert=ca.crt dbname=fastpki user=fastpki" -c 'select 1'
```

`could not find digest for NID UNDEF` is §4.1. Re-run it with `channel_binding=disable`
appended: if that connects, the certificate's signature algorithm is the cause and nothing
else is wrong. Do not leave the parameter in place as a remedy.

**A live TLS listener**, which is the only way to test the handshake rather than just the
chain. Serve the leaf and connect with each client that matters:

```bash
openssl s_server -accept 4443 -cert leaf.crt -key leaf.key -tls1_3 -www &
openssl s_client -connect localhost:4443 -CAfile ca.crt   # prints "Peer signature type"
curl --cacert ca.crt https://localhost:4443/
gnutls-cli --x509cafile ca.crt -p 4443 localhost
```

`Peer signature type:` in the `s_client` output names what was actually negotiated, which is
the fastest way to confirm an algorithm is genuinely in use rather than silently substituted.

### 5.1 How the table in §2 was produced

For each algorithm: a self-signed CA and a `localhost` leaf with `serverAuth` EKU, served by
`openssl s_server -tls1_3`, fetched by each client with the CA as its only trust anchor. The
PostgreSQL column used the stock `postgres:16` image with `ssl_cert_file` / `ssl_key_file`
pointed at the leaf, and `psql` with `sslmode=verify-full`. FastPKI itself requires
PostgreSQL 17 and ships the 17 client, so that column is one major version behind what a
deployment runs (§4.1).

The Windows column used a Windows Server 2022 Standard host: each root was imported with
`certutil -addstore -f Root`, probed with `certutil -dump`, and its leaf checked with
`certutil -verify`; the anchors were removed from the store afterwards. Two extra
certificates isolated the second axis — an Ed25519 leaf and an ML-DSA leaf, both signed by
the **EC** CA — to separate "can Windows verify this signature" from "can Windows hold this
public key".

Two other statements on this page are measurements rather than reasoning: the
`Peer signature type: mldsa65` handshake in §2.1 was taken inside the shipped image, and
the RSA-leaf-from-an-ML-DSA-root chain in §2.3 was built and offered to each client in the
same way as the §2 table.

Client versions behind the table: OpenSSL 3.5.8 (the shipped FastPKI image), OpenSSL 3.6.3,
curl 8.9.1 linked against OpenSSL 3.0.16, GnuTLS 3.8.10, Python 3.13 on OpenSSL 3.6.3,
libpq 16.14, and Windows Server 2022 Standard. **Re-measure before relying on a "fails" cell** — these move with client
releases, and post-quantum support in particular is arriving steadily.
