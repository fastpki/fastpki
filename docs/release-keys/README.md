# Release signing keys

The public keys FastPKI releases are signed with. Both are also compiled into the programs, so
`fastpki-update verify` needs no setup — these files are here for checking a download with
`openssl` instead, and for anyone who wants to see the key without trusting a binary first.

| File | Algorithm | Checkable with |
|---|---|---|
| `release-ecdsa.pub` | ECDSA P-256 | any OpenSSL, including the 3.0 shipped by several long-term distributions |
| `release-mldsa.pub` | ML-DSA-87 (FIPS 204), post-quantum | OpenSSL 3.5 or newer |

## What is signed

Each release carries `SHA256SUMS`, which lists the SHA-256 hash of every file in it, and two
signatures of that one file: `SHA256SUMS.sig` (ECDSA) and `SHA256SUMS.mldsa.sig` (ML-DSA).
Either signature verifying is enough. Two exist because most machines today cannot read a
post-quantum signature, and a release signature has to be checkable before you trust anything
we shipped.

Check the signature first, then the hashes:

```bash
openssl dgst -sha256 -verify release-ecdsa.pub -signature SHA256SUMS.sig SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

or, with OpenSSL 3.5 or newer, the post-quantum signature:

```bash
openssl pkeyutl -verify -pubin -inkey release-mldsa.pub -rawin \
    -in SHA256SUMS -sigfile SHA256SUMS.mldsa.sig
sha256sum -c --ignore-missing SHA256SUMS
```

The hashes on their own are not enough. `SHA256SUMS` is served from the same place as the
files, so it catches a corrupted download but not a substituted one — anyone who could replace
a file could replace the list too. The signature is the part they cannot produce.

## What these signatures do not cover

**Container images pulled from `ghcr.io`.** Compose and Kubernetes pull FastPKI's image from the
registry by tag, and a registry image is not a file listed in `SHA256SUMS`, so these signatures
say nothing about it. The image tarballs attached to a release *are* listed and covered — load
one of those with `docker load` if you need an image whose origin you have checked.

## Changing the keys

Changing these keys means every deployment needs a new FastPKI binary before it will accept a
release signed with the replacements, because the keys are pinned in the programs.
