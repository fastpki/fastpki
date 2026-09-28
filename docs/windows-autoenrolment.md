# Unattended Windows enrolment (MS-XCEP / MS-WSTEP)

How a domain-joined Windows machine enrols against FastPKI without anyone typing a
password, and how to test it.

## Contents

- [What has to be true](#what-has-to-be-true)
- [Setting it up](#setting-it-up)
- [Giving the DC its LDAPS certificate](#giving-the-dc-its-ldaps-certificate)
- [When it does not work](#when-it-does-not-work)
- [Manual test plan](#manual-test-plan)
- [The client caches the policy, and that hides every server-side change](#the-client-caches-the-policy-and-that-hides-every-server-side-change)
- [Unattended enrolment](#unattended-enrolment)
- [Removing FastPKI from a client](#removing-fastpki-from-a-client)

## What has to be true

| | why |
|---|---|
| the MS endpoint is deployed and enabled | `ms` is an opt-in compose profile chosen at install time, and `MS_ENABLED=false` keeps the port shut with the process parked at its gate. Both look identical from the client: the connection simply does not answer |
| the machine is domain-joined | it enrols as its own computer account, `DOMAIN\HOST$` |
| **the clocks agree to within five minutes** | Kerberos rejects an authenticator outside that window. See the symptom table below — this failure does not look like a clock problem |
| an SPN exists for the FastPKI host, and its keytab is uploaded to that directory | the KDC encrypts the service ticket with that account's key; without the matching keytab the server cannot decrypt it |
| the directory has a DNS root and URIs | the realm is the DNS root upper-cased and the KDCs are those URIs — neither is configured separately |
| the container can resolve the directory's hostname | set `DIRECTORY_DNS` to the AD DNS server. Docker's resolver forwards to the *host's*, which on a machine that is not domain-joined has never heard of the AD zone |
| **the enrolling identity holds two grants** | `template:use` on the template and `ms:enrol` scoped to the CA. Without them the policy document is served EMPTY, and Windows reports `WS_E_INVALID_FORMAT` / `ERROR_INVALID_PARAMETER` — naming no permission |
| **the client trusts the CA** | the root in `LocalMachine\Root`, the issuing CA in `LocalMachine\CA`. Every step below is an HTTPS call to the MS endpoint, so without this the first one fails in the TLS handshake |
| **autoenrolment is switched on at the client** | the `AEPolicy` value under `HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment`, normally from Group Policy. Without it `certutil -pulse` fetches the policy and then does nothing at all |
| the policy server is **registered on the client** | Windows does not discover enrolment policy servers. Without the registration `certreq` looks templates up in AD and reports "Template not found" |
| the policy advertises Kerberos | a machine has no password to offer. If the endpoint advertises only username/password, unattended enrolment cannot proceed |
| the CA's key is EC or RSA | measured on Server 2022: an Ed25519, Ed448 or ML-DSA CA imports into the Root store without error and then fails every chain build with `NTE_BAD_ALGID`. See [`compatibility.md`](compatibility.md) |

⚠️ **Almost none of these announce themselves.** An algorithm Windows cannot verify surfaces
as a trust or policy error; a missing grant surfaces as a malformed-document error; a clock
skew surfaces as a broken keytab. The symptom table at the end of this page maps what you
see to what is actually wrong.

## Setting it up

Steps 1 to 3 are on the FastPKI side, per directory (Directories page → the directory →
its editor). Step 4 onwards is on the Windows client, and each step says so.

1. Set the directory's **DNS root** and **URIs** (its domain controllers).

   Use the DNS **name**, not an IP: an `ldaps://` certificate is issued to the DC's name.
   Point the containers at the AD DNS with `DIRECTORY_DNS` in `deploy/.env`, or LDAP cannot
   resolve that name — the symptom is `Can't contact LDAP server`, which reads as a
   firewall or credentials problem.

   For `ldaps://`, set the directory's **CA certificate file** to the anchor that signed the
   DC's LDAPS certificate. ⚠️ That field is a **path inside the container**, not an upload:
   put the PEM on the shared `/var/pki` volume (e.g. `/var/pki/tls/ad-root.crt`) and name it
   there. Without it the handshake cannot verify and the console reports
   *"this directory has no search account"* — naming a bind DN that is present and correct.

   ⚠️ **A domain controller only offers LDAPS once it holds a suitable certificate**, and a
   domain with no certificate authority has none: port 636 accepts the connection and
   presents nothing. FastPKI can issue it — see *Giving the DC its LDAPS certificate* below.

2. Upload that directory's **keytab**. Create it on the DC with the SPN of the FastPKI host:

   ```
   ktpass -princ HTTP/pki.example.org@CORP.EXAMPLE ^
          -mapuser CORP\svc-fastpki +rndPass ^
          -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -out fastpki.keytab
   ```

   ⚠️ `ktpass` prints the new key to stdout. Redirect it if you care where that ends up.

   ⚠️ Check the SPN is not already registered to another account — `setspn -Q HTTP/pki.example.org`.
   If it is, the KDC encrypts tickets with *that* account's key and the server cannot
   decrypt them, and `ktpass` will not move the SPN for you. Export the keytab from the
   account that **already owns** the SPN. The failure is `gss_accept_sec_context:
   Unspecified GSS failure` with no minor code, which looks like a broken keytab rather
   than a wrong owner.

   ⚠️ Use the command as written. Adding `-setupn` changes the account's UPN, which changes
   the salt Active Directory derives the AES key from — so `ktpass` writes a key the KDC
   does not share, and every ticket fails to decrypt with that same no-minor-code error.
   `kinit -k -t fastpki.keytab HTTP/pki.example.org@CORP.EXAMPLE` on any Linux host is
   the quickest way to prove a keytab's key is the one AD holds: it either gets a ticket or
   says `Preauthentication failed`.

3. **Grant the enrolling identity what it needs.** A Kerberos-authenticated machine is
   onboarded with the role `none` and can enrol nothing until an administrator gives it a
   role carrying both:

   ```
   template:use|<TemplateName>
   ms:enrol|<ca-id>
   ```

   Bind that role to the machine account by its **provider-qualified** name —
   `<directory-id>\HOST$`, e.g. `corp\WS01$`. A bare `WS01$` matches nobody, silently: every
   call returns 200, the grant simply never applies.

   ⚠️ **A machine account is not known until it authenticates once**, so on a new deployment
   there is nothing to pick from: it is onboarded, with the role `none`, the first time it
   presents a Kerberos ticket. That is a circle, because the first thing it does is register
   the policy server in **machine** context — which validates as `DOMAIN\HOST$`, authenticates
   fine, and is then served a policy carrying no templates, so the client refuses it with
   `WS_E_INVALID_FORMAT`. A user account with the same grants does not help; the operator
   running the registration is not the identity being checked.

   Bind the role to the name **before** the machine has ever connected. The binding is
   accepted for an identity that does not exist yet and applies the moment it first
   authenticates — the server then goes straight from `onboarded … with role 'none'` to
   `offering N of N templates` in the same request.

   The alternative is to make the machine authenticate once first, so that it appears in
   the Users tab and can be picked from a list. **This part runs on the Windows client, as
   SYSTEM**, and then you come back to FastPKI to bind the role:

   ```powershell
   # as SYSTEM, e.g. from a scheduled task - a key-authenticated session holds no ticket
   Invoke-WebRequest -Uri https://pki.example.org:8446/msxcep/<ca-id> -Method Post `
                     -UseDefaultCredentials -UseBasicParsing
   ```

   Until this is done the endpoint authenticates the machine, serves a policy document with
   an EMPTY template list, and the client reports `WS_E_INVALID_FORMAT` —
   an error that mentions neither permissions nor templates. The server says so plainly in
   its log: `XCEP offering 0 of N templates to '<user>'`.

4. **On the Windows client, trust the CA** — the root into `LocalMachine\Root`, the
   issuing CA into `LocalMachine\CA`. Download both certificates from the console's **CAs**
   page, copy them to the client as `root.cer` and `issuing.cer`, then in an elevated
   PowerShell:

   ```powershell
   certutil -addstore -f Root root.cer
   certutil -addstore -f CA   issuing.cer
   ```

   ⚠️ The issuing CA goes in `CA`, not `Root`. An intermediate in the Root store is treated
   as a trust anchor in its own right.

Then, still on the client but now **as SYSTEM** — not merely elevated:

```powershell
.\Register-FastPKIEnrollment.ps1 -Url https://pki.example.org:8446/msxcep/<ca-id>
```

⚠️ **A local account has no Kerberos ticket, ever.** Running this as the machine's local
Administrator — which is what an SSH session or a local console typically gives you — means
`klist` is empty and every SPNEGO attempt is refused with HTTP 401, which reads as an SPN or
keytab fault. Autoenrolment itself runs as SYSTEM, so testing as SYSTEM is also testing the
thing that will actually run:

```powershell
$a = New-ScheduledTaskAction -Execute 'powershell.exe' `
       -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\path\to\script.ps1'
Register-ScheduledTask -TaskName FastPKIEnrol -Action $a -User SYSTEM -RunLevel Highest -Force
Start-ScheduledTask -TaskName FastPKIEnrol
```

It reads the policy id from the server rather than assuming one, tells you which templates
and which authentication methods are advertised, registers the policy server for the
machine, and triggers autoenrolment.

To see what the server offers without changing anything: add `-Diagnose`.

## Giving the DC its LDAPS certificate

A domain controller serves LDAPS only when it holds a certificate with Server
Authentication, its own FQDN, and a private key — issued by a CA it trusts. A domain with no
certificate authority has none, so port 636 accepts connections and presents nothing.
FastPKI can issue it, and Active Directory picks it up on its own with no restart.

On the DC, save this as `ldaps.inf`:

```ini
[NewRequest]
Subject = "CN=dc1.corp.example"
KeySpec = 1
KeyLength = 2048
MachineKeySet = TRUE
RequestType = PKCS10
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
KeyUsage = 0xa0
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=dc1.corp.example&"
```

Turn it into a CSR, still on the DC:

```powershell
certreq -new ldaps.inf ldaps.req
```

Sign `ldaps.req` with FastPKI — in the console, **Inventory → Request**, or
`POST /api/certs/request` with the PEM as the body and `?ca_instance=<ca-id>`. Download
the issued certificate and copy it back to the DC as `ldaps.cer`, together with the root
(`root.cer`) and the issuing CA (`issuing.cer`).

Back on the DC, install the chain and then the answer:

```powershell
certutil -addstore -f Root root.cer
certutil -addstore -f CA   issuing.cer
certreq -accept -machine ldaps.cer
```

Confirm from any host that can reach the DC:

```
openssl s_client -connect dc1.corp.example:636   # expect the subject and issuer
```

⚠️ Issue it from an **issuing** CA, not the root — the anchor you then give the directory as
its CA certificate file is the root, and the DC must send the intermediate for the chain to
build. Installing the intermediate into `LocalMachine\CA` above is what makes it do so.

⚠️ **Rebuilding the CA invalidates this certificate, and the client's trust with it.** The DC's
LDAPS certificate chains to whichever CA issued it, so re-keying a CA or recreating the
hierarchy leaves the DC serving a certificate FastPKI can no longer verify — and both CAs are
likely to carry the same subject name, so only the key identifiers show the mismatch. The
directory then fails with `Can't contact LDAP server`, which names nothing about certificates.
After any such rebuild, redo this section *and* step 4 of *Setting it up* — the new root and
issuing CA have to reach the DC's stores and every client's stores, not just one of them. On the
DC, the `certutil -addstore -f Root` must come **before** `certreq -accept`, or the install is
refused with `CERT_E_UNTRUSTEDROOT`.

⚠️ **Delete the superseded certificates, or the DC goes on serving one of them.** Installing a
new one does not retire the old: they all stay in `LocalMachine\My` with the same subject, and
Active Directory keeps answering on 636 with a certificate that no longer verifies. Every step
above reports success, so the only sign is the issuer on the wire:

```powershell
# on the DC — list what is there, keeping the thumbprint you just installed
Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.Subject -like "*<dc fqdn>*" } |
  Format-List Subject, Issuer, Thumbprint

# remove each superseded one by thumbprint
Remove-Item -Path Cert:\LocalMachine\My\<thumbprint> -Force
Restart-Service NTDS -Force        # also restarts DNS and the other dependent services
```

Then confirm the issuer that is actually served, from a host that can reach the DC:

```
openssl s_client -connect <dc fqdn>:636 -CAfile root.pem   # expect Verify return code: 0 (ok)
```

Check the **issuer**, not just that the handshake completed. A stale certificate completes the
handshake perfectly and fails only the verification FastPKI does.

## When it does not work

Each of these messages names something other than the real cause.

| what you see | what it usually is |
|---|---|
| `gss_accept_sec_context: Unspecified GSS failure`, no minor code | **Check the clocks first.** A skew beyond five minutes fails here, and the ticket DECRYPTS before it fails — so a krb5 trace shows complete success and only the timestamp check rejects it. Then check for a **stale cached service ticket**: rotating the service account's key (any `ktpass +rndPass`) does not invalidate tickets clients already hold, and a client keeps presenting one until it expires — `klist purge` for a user, `klist purge -li 0x3e7` as SYSTEM for the machine. Also produced by a keytab whose key AD does not share, a stale kvno and an SPN owned by another account. An NTLM fallback is not this: it is detected before GSSAPI is called and reported as such |
| HTTP 401 from a session you are sure is a domain admin | a **local** account, or a key-authenticated SSH session: neither holds a Kerberos ticket. Run as SYSTEM |
| `WS_E_INVALID_FORMAT` / `ERROR_INVALID_PARAMETER` | the identity holds no `template:use` grant, so the policy list is empty. The server log says `XCEP offering 0 of N templates` |
| `certreq` reports "Template not found" | the policy server is not registered on this client |
| `WS_E_ENDPOINT_ACCESS_DENIED` (0x803d0005) | the endpoint **refused the credential** — this is the 401, and not an authorization result. XCEP has no grant check at all, so a missing grant cannot produce it; that is `WS_E_INVALID_FORMAT`, above. In machine context the ticket is the machine's, so look at what it presented: a service ticket cached before the service account's key was rotated (`klist purge -li 0x3e7` as SYSTEM clears it), an SPN owned by another account, a keytab whose key AD does not share, or a ticket whose realm matches no enabled directory |
| `WS_E_SERVER_REQUIRES_BASIC_AUTH` (0x803d001c) | the endpoint is not advertising Kerberos, so a machine has nothing to offer: no keytab is uploaded for any enabled directory, or the file will not load. An upload takes effect immediately — the acceptor keytab is rebuilt when the files change — but the `MS-XCEP Kerberos realms: …` line is written once at startup, so its absence in the log means only that the service has not restarted since. Test by making a request, not by reading that line |
| `certutil -pulse` succeeds and issues nothing | `AEPolicy` is not set, so autoenrolment never ran. Or the machine already holds a valid certificate, which is a success |
| a template edit does not reach the client | two caches, and both must expire: `fastpki-ms` reads the catalogue **once at startup**, so restart it; then the client's own policy cache lives for `MS_XCEP_NEXT_UPDATE_HOURS` |
| `Can't contact LDAP server` | DNS (`DIRECTORY_DNS`), or an `ldaps://` anchor that cannot verify the DC's certificate. An anchor that is the ISSUING CA rather than the root fails here too: a partial chain needs OpenSSL's `-partial_chain`, which libldap does not pass, so give it the root and let the DC send the intermediate |
| `Invalid credentials` for a login you know is right | the directory's base DN does not name the container the user is in. A password check binds as `CN=<user>,<base-dn>`, so an AD base of only the domain root asks for an entry that is not there. Name the user container first and the domain root after it, semicolon-separated: `CN=Users,DC=corp,DC=example;DC=corp,DC=example` |
| console says the directory *"has no search account"* with a bind DN clearly set | the LDAPS handshake failed. Check the directory's CA certificate file |

## Manual test plan

Run on a domain-joined Windows machine, **as SYSTEM** — step 1 exercises Kerberos, and a
local or key-authenticated session holds no ticket, so an elevated-but-not-SYSTEM session
fails it with HTTP 401. *Setting it up* above shows the scheduled task that gives you a
SYSTEM shell. Each step says what a pass looks like, so a failure is distinguishable from
a step that did nothing.

### 1. The service accepts Kerberos at all

```powershell
.\Register-FastPKIEnrollment.ps1 -Url https://pki.example.org:8446/msxcep/<ca-id> -Diagnose
```

**Pass:** it prints a policy id, the template names, and `enrolment accepts: 2 (Kerberos)`.

**If it prints only `4 (username/password)`** the server is not offering Kerberos to this
CA. Either no usable keytab is loaded for an enabled directory — upload one; nothing on the
client will fix it — or this CA has explicit `ca_xcep_uris` rows configured for
username/password, in which case the advertised list comes from those rows and no keytab
upload changes it. Check the CA's XCEP URIs in the console before re-exporting a keytab.

**If it reports HTTP 401** the machine's ticket was refused — SPN or keytab, see above.

### 2. A service ticket is actually issued

```powershell
klist purge
klist get HTTP/pki.example.org
```

**Pass:** a ticket for `HTTP/pki.example.org` appears with an AES encryption type.

**If not**, the SPN is not registered in AD. `setspn -Q HTTP/pki.example.org` from any domain member.

### 3. Enrol

```powershell
.\Register-FastPKIEnrollment.ps1 -Url https://pki.example.org:8446/msxcep/<ca-id>
```

**Pass:** it prints `ISSUED:` with a subject and serial.

**"no NEW certificate was issued" plus a list of existing ones** is not a failure —
autoenrolment does not replace a valid certificate and reports success for doing nothing.
Force one with `-Template <name>`, or delete the existing certificate first.

### 4. The certificate is what was asked for

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*FastPKI*' } |
  Format-List Subject, Issuer, NotAfter, @{n='Template';e={
    ($_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.20.2' }).Format($false) }}
```

**Pass:** subject is the machine account, issuer is the expected CA, and the template is
the one intended.

### 5. The server agrees

On a FastPKI node:

```bash
cd deploy
docker compose exec postgres psql -U fastpki -d fastpki -c \
  "SELECT actor, action, status, detail FROM audit_log ORDER BY ts DESC LIMIT 5;"
```

**Pass:** a `cert_issued` row whose actor is the machine account (`HOST$`) and whose detail
names the CA and the protocol.


## The client caches the policy, and that hides every server-side change

A client that has registered an enrolment policy server **caches the policy document** and
keeps acting on the cached copy. How long is what `<nextUpdateHours>` in the policy says —
`MS_XCEP_NEXT_UPDATE_HOURS`, 24 by default.

Until that expires, **nothing you change on the server reaches that client**: not a new or
edited template, not a permission grant, not a bug fix in a rolled image. The client does
not re-fetch, so the request never arrives and the server has nothing to log. From this
side it looks identical to a server that is refusing.

Clear it on the client before concluding anything — **for the context you are enrolling in**:

```powershell
certutil -f -user -policyserver * -policycache delete   # user certificates
certutil -f       -policyserver * -policycache delete   # machine certificates
```

⚠️ **Without `-user`, `certutil` clears the MACHINE cache only.** Requesting a user
certificate after clearing only the machine cache leaves the client serving stale user
policy, while the command appears to have succeeded. The registration is per-context in the
same way: `Add-CertificateEnrollmentPolicyServer -Context User` and `-Context Machine` are
separate registrations with separate caches.

⚠️ **The cache clear is not evidence — the server log is.** A genuine re-fetch appears as an
MS-XCEP `GetPolicies` request in the `ms` log at the time of the test:

```bash
cd deploy
docker compose logs --since 10m ms 2>&1 | grep XCEP
```

If no XCEP request arrives, the client used its cache and whatever changed on the server was
never seen — whatever the enrolment then did says nothing about our code.

⚠️ **Do not credit a server-side change with fixing a Windows enrolment unless a policy
fetch is visible in the server log on both sides of the comparison.** Clearing the machine
cache and then requesting a *user* certificate leaves the client on stale user policy, so
both the before and the after run act on the same cached document and the comparison says
nothing about the change.

Because there is no way to invalidate the cache from the server, a lower
`MS_XCEP_NEXT_UPDATE_HOURS` is worth considering while templates are still changing: it is
exactly how long a stale policy can keep a client broken.

## Unattended enrolment

`certreq -q -enroll -machine` enrols with no desktop and no password. Two details of the
built-in templates are what make that work:

* **The templates name a Key Storage Provider, with `key_spec = 0` (CNG).** A legacy
  CryptoAPI CSP cannot acquire a silent context, and silent *is* the normal case —
  autoenrolment, scheduled tasks and services have no desktop to prompt on. A template
  naming a legacy CSP fails with `NTE_SILENT_CONTEXT (0x80090022)`.
* **The template metadata must match what the client asked for**, or the client returns
  `ERROR_INVALID_PARAMETER (0x80070057)` without saying which field it objected to.

Run it on a domain-joined client, as the machine account:

```
certreq -q -enroll -machine -policyserver <url> GenericComputer
```

A pass prints `The requested certificate has been issued.`, and the server logs two lines
in the same second:

```
WSTEP: CMC request from '<domain>\<MACHINE>$'
WSTEP issued serial=… user='<domain>\<MACHINE>$' ca_instance=…
```

The `certs` row is owned by the machine account.

## Removing FastPKI from a client

Undo it in this order. Each step is independent, so a client that was only partly set up
skips what it does not have. Everything here needs an elevated shell; the machine-context
items need SYSTEM (a scheduled task registered `-User SYSTEM -RunLevel Highest` is the
usual way in over SSH).

```powershell
# 1. the enrolment policy servers, machine and user
Remove-Item -Recurse -Force 'HKLM:\SOFTWARE\Microsoft\Cryptography\PolicyServers' -EA SilentlyContinue   # as SYSTEM
Remove-Item -Recurse -Force 'HKCU:\SOFTWARE\Microsoft\Cryptography\PolicyServers' -EA SilentlyContinue

# 2. autoenrolment itself
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' `
                    -Name AEPolicy -EA SilentlyContinue

# 3. certificates this CA issued, in both stores
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*<your CA CN>*' } | Remove-Item
Get-ChildItem Cert:\CurrentUser\My  | Where-Object { $_.Issuer -like '*<your CA CN>*' } | Remove-Item

# 4. the trust anchors — BY THUMBPRINT, see the warning below
certutil -delstore Root <root thumbprint>
certutil -delstore CA   <issuing CA thumbprint>

# 5. cached Kerberos service tickets, so nothing presents one for an SPN that is gone
klist purge                 # the interactive user
klist purge -li 0x3e7       # the machine, as SYSTEM
```

⚠️ **Delete anchors by THUMBPRINT, never by subject.** Rebuilding a CA hierarchy commonly
reuses the same names — a second `CN=Example Root CA` with a different key is the normal
result of a rebuild, not a mistake. Windows will then hold two roots with one subject, and
chain building picks between them by key, so an expired or superseded one produces failures
that read as though the *new* certificate were broken. List what is actually installed
before deleting anything:

```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*FastPKI*' } |
  Format-Table Thumbprint, Subject, NotAfter
```

**The domain controller keeps its own copy.** If it was given an LDAPS certificate from
this PKI, or had the root pushed to it, the same anchors are in *its* `LocalMachine\Root`
and are not removed by cleaning a client. They accumulate across rebuilds. Check there too:

```powershell
Invoke-Command -ComputerName <DC> -ScriptBlock {
  Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*FastPKI*' } |
    Format-Table Thumbprint, Subject, NotAfter }
```

**Anything distributed by Group Policy comes back.** Removing an anchor a GPO publishes
lasts until the next `gpupdate`. Remove it from the GPO first, then from the store.
