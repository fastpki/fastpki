// Drive the console's browser-side PKCS#12 builder (the JS-P12 slice) —
// extracted verbatim from src/web/main.cpp between the BUILDER sentinels —
// under Node's WebCrypto, so the shell wrapper can prove the emitted .p12 is
// interoperable with openssl. Two modes, because a CA has to sign the CSR
// (openssl, in the shell) between them:
//
//   node web_p12.mjs <main.cpp> csr <csr-out> <key-out>
//       -> build an EC P-384 keypair + CSR; write the CSR and the *plaintext*
//          PKCS#8 key PEM (the shell signs the CSR into a leaf cert).
//   node web_p12.mjs <main.cpp> p12 <cert-pem> <key-pem> <password> <cn> <p12-out>
//       -> bundle that leaf cert + key into a password-protected PKCS#12.
import { readFileSync, writeFileSync } from 'node:fs';

const [src, mode, ...rest] = process.argv.slice(2);
const s = readFileSync(src, 'utf8');
const start = s.indexOf('// BUILDER-START'), end = s.indexOf('// BUILDER-END');
if (start < 0 || end < 0) { console.error('missing the BUILDER sentinels'); process.exit(3); }
const B = new Function('crypto', s.slice(start, end) + '\nreturn { buildCsr, buildP12 };')(globalThis.crypto);
const pemToDer = pem => Uint8Array.from(Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'));

if (mode === 'csr') {
  const [csrOut, keyOut] = rest;
  const { csrPem, keyPem } = await B.buildCsr({ CN: 'p12.internal', O: 'Acme', OU: 'IT', C: 'US' }, ['p12.internal'], 'EC384');
  writeFileSync(csrOut, csrPem);
  writeFileSync(keyOut, keyPem);
} else if (mode === 'p12') {
  const [certPem, keyPem, password, cn, p12Out] = rest;
  const certDer = pemToDer(readFileSync(certPem, 'utf8'));
  const pkcs8 = pemToDer(readFileSync(keyPem, 'utf8'));
  const p12 = await B.buildP12(certDer, pkcs8, password, cn);
  writeFileSync(p12Out, Buffer.from(p12));
} else {
  console.error('usage: web_p12.mjs <main.cpp> csr|p12 ...'); process.exit(2);
}
