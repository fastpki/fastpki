#!/usr/bin/env python3
# Minimal mock OpenID Connect provider for tests. Serves
# discovery, /authorize (auto-issues a code for a preconfigured user), /token
# (verifies PKCE, returns an RS256-signed id_token), and /jwks. Signatures are
# produced by the local `openssl` CLI, so the JWT verifies for real against the
# JWKS — no third-party libraries needed.
#
# Env: MOCK_PORT, MOCK_ISSUER (base URL it's served at), MOCK_CLIENT_ID,
#      MOCK_KEY (RSA private key PEM), MOCK_USER (sub/email), MOCK_GROUPS (CSV),
#      MOCK_OSSL (openssl path).
import base64, hashlib, json, os, subprocess, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ["MOCK_PORT"]); ISS = os.environ["MOCK_ISSUER"]
CID  = os.environ["MOCK_CLIENT_ID"]; KEY = os.environ["MOCK_KEY"]
USER = os.environ["MOCK_USER"]; GROUPS = [g for g in os.environ.get("MOCK_GROUPS", "").split(",") if g]
OSSL = os.environ.get("MOCK_OSSL", "openssl"); KID = "mockkey1"
codes = {}   # code -> {nonce, challenge}

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def jwks():
    mod = subprocess.check_output([OSSL, "rsa", "-in", KEY, "-noout", "-modulus"]).decode().strip()
    n = b64u(bytes.fromhex(mod.split("=", 1)[1]))
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": n, "e": "AQAB"}]}

def make_id_token(nonce):
    hdr = b64u(json.dumps({"alg": "RS256", "typ": "JWT", "kid": KID}).encode())
    now = int(time.time())
    payload = {"iss": ISS, "aud": CID, "sub": USER, "email": USER,
               "nonce": nonce, "iat": now, "exp": now + 300}
    if GROUPS:                       # omit the claim entirely when empty, like Google
        payload["groups"] = GROUPS
    pl = b64u(json.dumps(payload).encode())
    si = (hdr + "." + pl).encode()
    sig = subprocess.run([OSSL, "dgst", "-sha256", "-sign", KEY], input=si, stdout=subprocess.PIPE).stdout
    return hdr + "." + pl + "." + b64u(sig)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == "/.well-known/openid-configuration":
            return self._j(200, {"issuer": ISS, "authorization_endpoint": ISS + "/authorize",
                                  "token_endpoint": ISS + "/token", "jwks_uri": ISS + "/jwks"})
        if u.path == "/jwks":
            return self._j(200, jwks())
        if u.path == "/authorize":
            code = "c" + str(int(time.time() * 1e6))
            codes[code] = {"nonce": q.get("nonce", [""])[0], "challenge": q.get("code_challenge", [""])[0]}
            redir = q["redirect_uri"][0]; state = q.get("state", [""])[0]
            loc = redir + ("&" if "?" in redir else "?") + "code=" + code + "&state=" + urllib.parse.quote(state)
            self.send_response(302); self.send_header("Location", loc); self.end_headers(); return
        self._j(404, {"error": "not_found"})
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        q = urllib.parse.parse_qs(self.rfile.read(n).decode() if n else "")
        if self.path == "/token":
            c = codes.pop(q.get("code", [""])[0], None)
            if not c: return self._j(400, {"error": "invalid_grant"})
            chal = b64u(hashlib.sha256(q.get("code_verifier", [""])[0].encode()).digest())
            if c["challenge"] and c["challenge"] != chal: return self._j(400, {"error": "invalid_pkce"})
            return self._j(200, {"id_token": make_id_token(c["nonce"]), "access_token": "x", "token_type": "Bearer"})
        self._j(404, {"error": "not_found"})

ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
