#!/usr/bin/env python3
# Minimal mock SAML 2.0 IdP for tests. On the SSO
# endpoint it decodes the SP's AuthnRequest (raw-DEFLATE + base64, HTTP-Redirect
# binding), then returns an auto-POST HTML form carrying a SAML Response whose
# Assertion is signed with the local `xmlsec1` CLI — so the assertion signature
# verifies for real against the IdP cert, no Python crypto libraries needed.
#
# Env: MOCK_PORT, MOCK_KEY (RSA private key PEM), MOCK_CERT (matching cert PEM),
#      MOCK_IDP_ENTITY, MOCK_SP_ENTITY (expected Audience), MOCK_USER (NameID),
#      MOCK_GROUPS (CSV), MOCK_GROUPS_ATTR (default "groups"),
#      MOCK_XMLSEC (xmlsec1 path, default "xmlsec1").
import base64, os, re, subprocess, sys, tempfile, time, urllib.parse, zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ["MOCK_PORT"])
KEY  = os.environ["MOCK_KEY"]; CERT = os.environ["MOCK_CERT"]
IDP  = os.environ["MOCK_IDP_ENTITY"]; SP = os.environ["MOCK_SP_ENTITY"]
USER = os.environ["MOCK_USER"]
GROUPS = [g for g in os.environ.get("MOCK_GROUPS", "").split(",") if g]
GATTR  = os.environ.get("MOCK_GROUPS_ATTR", "groups")
XMLSEC = os.environ.get("MOCK_XMLSEC", "xmlsec1")
ASSERT_NS = "urn:oasis:names:tc:SAML:2.0:assertion"

def t(off=0):  # XSD dateTime, UTC
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + off))

def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))

def build_response(req_id, acs):
    aid = "_a" + os.urandom(12).hex(); rid = "_r" + os.urandom(12).hex()
    groups = "".join(f'<saml:AttributeValue>{esc(g)}</saml:AttributeValue>' for g in GROUPS)
    # The Signature template (empty DigestValue/SignatureValue) goes right after
    # the assertion's Issuer; xmlsec1 fills it in. rsa-sha256 / sha256 (not SHA-1).
    sig_tmpl = (
      '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
      '<ds:SignedInfo>'
      '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
      '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
      f'<ds:Reference URI="#{aid}">'
      '<ds:Transforms>'
      '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
      '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
      '</ds:Transforms>'
      '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
      '<ds:DigestValue></ds:DigestValue>'
      '</ds:Reference></ds:SignedInfo>'
      '<ds:SignatureValue/>'
      # A KeyName lets xmlsec1 1.3's strict key search bind the supplied key
      # (loaded as --privkey-pem:idpkey); 1.2 accepts it too. Our verifier pins
      # the key and ignores KeyInfo, so this affects only the test signer.
      '<ds:KeyInfo><ds:KeyName>idpkey</ds:KeyName></ds:KeyInfo></ds:Signature>')
    xml = (
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
      f'xmlns:saml="{ASSERT_NS}" ID="{rid}" Version="2.0" '
      f'IssueInstant="{t()}" Destination="{esc(acs)}" InResponseTo="{esc(req_id)}">'
      f'<saml:Issuer>{esc(IDP)}</saml:Issuer>'
      '<samlp:Status><samlp:StatusCode '
      'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
      f'<saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{t()}">'
      f'<saml:Issuer>{esc(IDP)}</saml:Issuer>'
      f'{sig_tmpl}'
      '<saml:Subject>'
      f'<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">{esc(USER)}</saml:NameID>'
      '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
      f'<saml:SubjectConfirmationData InResponseTo="{esc(req_id)}" '
      f'Recipient="{esc(acs)}" NotOnOrAfter="{t(300)}"/>'
      '</saml:SubjectConfirmation></saml:Subject>'
      f'<saml:Conditions NotBefore="{t(-300)}" NotOnOrAfter="{t(300)}">'
      f'<saml:AudienceRestriction><saml:Audience>{esc(SP)}</saml:Audience>'
      '</saml:AudienceRestriction></saml:Conditions>'
      f'<saml:AttributeStatement><saml:Attribute Name="{esc(GATTR)}">{groups}'
      '</saml:Attribute></saml:AttributeStatement>'
      '</saml:Assertion></samlp:Response>')
    # Sign the assertion (ID attribute registered for the SAML assertion node).
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml); tmpl = f.name
    try:
        # Keep stdout (the signed XML) clean: xmlsec1 1.3 writes status lines to
        # stderr, so capture the two streams separately (merging them corrupts
        # the document with "extra content at the end").
        r = subprocess.run(
            [XMLSEC, "--sign", "--privkey-pem:idpkey", KEY + "," + CERT,
             "--id-attr:ID", ASSERT_NS + ":Assertion", tmpl],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            raise subprocess.CalledProcessError(r.returncode, XMLSEC, output=r.stderr)
        signed = r.stdout
    finally:
        os.unlink(tmpl)
    return base64.b64encode(signed).decode()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        sr = q.get("SAMLRequest", [None])[0]
        if not sr:
            self.send_response(400); self.end_headers(); self.wfile.write(b"no SAMLRequest"); return
        req = zlib.decompress(base64.b64decode(sr), -15).decode()
        rid = re.search(r'\bID="([^"]+)"', req).group(1)
        m = re.search(r'AssertionConsumerServiceURL="([^"]+)"', req)
        acs = m.group(1) if m else ""
        relay = q.get("RelayState", [""])[0]
        try:
            resp = build_response(rid, acs)
        except subprocess.CalledProcessError as e:
            self.send_response(500); self.end_headers()
            self.wfile.write(b"xmlsec1 sign failed:\n" + e.output); return
        html = (f'<html><body><form id="f" method="POST" action="{esc(acs)}">'
                f'<input type="hidden" name="SAMLResponse" value="{resp}"/>'
                f'<input type="hidden" name="RelayState" value="{esc(relay)}"/>'
                '</form></body></html>').encode()
        self.send_response(200); self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(html))); self.end_headers()
        self.wfile.write(html)

ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
