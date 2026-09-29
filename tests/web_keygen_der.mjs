// Extract the console's browser-side CSR builder verbatim from
// src/web/main.cpp — the DOM-free block between the BUILDER-START/END
// sentinels — and drive it under Node's WebCrypto (the same crypto.subtle the
// browser exposes). This runs the ACTUAL shipped code, not a copy, so the shell
// wrapper can decode the emitted CSRs with openssl and prove the full subject DN,
// every SAN kind, and each key type round-trip correctly.
//
//   node web_keygen_der.mjs <path-to-main.cpp> <out-dir>
//
// Writes <out-dir>/<label>.csr.pem for each case and prints a JSON manifest.
import { readFileSync, writeFileSync } from 'node:fs';

const [srcPath, outDir] = process.argv.slice(2);
if (!srcPath || !outDir) { console.error('usage: web_keygen_der.mjs <main.cpp> <out-dir>'); process.exit(2); }

const src = readFileSync(srcPath, 'utf8');
const start = src.indexOf('// BUILDER-START');
const end = src.indexOf('// BUILDER-END');
if (start < 0 || end < 0 || end < start) { console.error('could not find the BUILDER sentinels in ' + srcPath); process.exit(3); }
const builder = src.slice(start, end);

// Evaluate the extracted builder in this module scope. It references only
// globals that Node provides (crypto.subtle, TextEncoder, atob/btoa) — no DOM.
const factory = new Function('crypto', builder + '\nreturn { buildCsr, encryptPkcs8, ipv6ToBytes, derName, derGeneralNames };');
const { buildCsr, encryptPkcs8 } = factory(globalThis.crypto);

// Full subject DN + one SAN of every supported kind. The CN is added to the SAN
// list by the caller in the real form; here we pass it explicitly to exercise the
// builder directly.
const dn = { CN: 'svc.internal', O: 'Example Ltd', OU: 'Platform', C: 'US', ST: 'California', L: 'San Francisco', E: 'admin@example.org' };
const sans = ['svc.internal', 'alt.internal', '10.0.0.5', '2001:db8::1', 'admin@example.org', 'spiffe://example.org/ns/prod/svc'];

const keyTypes = ['EC256', 'EC384', 'EC521', 'ED25519', 'RSA2048', 'RSA3072', 'RSA4096', 'RSA-PSS2048', 'RSA-PSS3072', 'RSA-PSS4096'];
const manifest = {};
for (const kt of keyTypes) {
  try {
    const { csrPem, keyPem } = await buildCsr(dn, sans, kt);
    const f = `${outDir}/${kt}.csr.pem`;
    writeFileSync(f, csrPem);
    // Also exercise the PBES2 key encryption path on one key so the shell can
    // verify openssl can decrypt it (guards encryptPkcs8 for the new key types).
    if (kt === 'EC384') {
      const { pkcs8 } = await buildCsr(dn, sans, kt);
      const encDer = await encryptPkcs8(pkcs8, 'demo-pass-123');
      const b64 = Buffer.from(Uint8Array.from(encDer)).toString('base64').replace(/(.{64})/g, '$1\n');
      writeFileSync(`${outDir}/EC384.key.enc.pem`, `-----BEGIN ENCRYPTED PRIVATE KEY-----\n${b64}\n-----END ENCRYPTED PRIVATE KEY-----\n`);
      manifest.encKey = `${outDir}/EC384.key.enc.pem`;
    }
    manifest[kt] = f;
  } catch (e) {
    manifest[kt] = 'ERROR: ' + (e && e.message ? e.message : e);
  }
}
// KeyUsage / ExtKeyUsage / otherName (UPN + generic) requested via the CSR.
try {
  const extSans = ['ext.internal', 'upn:alice@corp.example',
                   'othername:1.3.6.1.4.1.99999.1;custom-value'];
  const { csrPem } = await buildCsr(dn, extSans, 'EC256',
    ['digitalSignature', 'keyEncipherment'],
    ['serverAuth', 'clientAuth', '1.3.6.1.5.5.7.3.21']);
  const f = `${outDir}/EXT.csr.pem`;
  writeFileSync(f, csrPem);
  manifest.EXT = f;
} catch (e) {
  manifest.EXT = 'ERROR: ' + (e && e.message ? e.message : e);
}
console.log(JSON.stringify(manifest));
