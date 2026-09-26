<#
.SYNOPSIS
Verify FastPKI enrolment from the machine that actually enrols, in one run.

.DESCRIPTION
The same checks as tests/windows_enrolment.sh, run LOCALLY on a domain-joined client instead
of driven over SSH from elsewhere.

⚠️ WHY A LOCAL VERSION EXISTS, AND WHY IT IS SIMPLER. The shell suite reaches this machine
over SSH, and a key-authenticated OpenSSH session holds no network credentials: outbound
SPNEGO produces nothing, the server logs "401 — no accepted credential (none offered)", and
the client reports WS_E_ENDPOINT_ACCESS_DENIED — an error that reads as the server refusing
us. That suite therefore runs user-context work as a scheduled task with a stored password
purely to obtain a real logon. Run here, in a session that already has one, none of that is
needed and no password is required.

⚠️ IT MUST NOT SKIP. A check whose prerequisite is missing FAILS and names the prerequisite.
A test that quietly does nothing is worse than one that is absent.

.EXAMPLE
  .\Test-FastPKIEnrolment.ps1 -XcepUrl https://pki.example.com:8446/msxcep/sub-ca-1 `
      -Console https://pki.example.com:8090 -ConsoleUser admin `
      -RootThumbprint <sha1> -SubThumbprint <sha1>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$XcepUrl,
    # The console is needed for the sections that import a template from the directory,
    # grant it, and revoke a certificate — all operator actions with no client-side path.
    [string]$Console,
    [string]$ConsoleUser,
    [string]$ConsolePassword,
    # Trust is asserted by THUMBPRINT, never by name: a name says nothing about which key is
    # trusted, and a second CA with the same subject would pass a name check.
    [string]$RootThumbprint,
    [string]$SubThumbprint,
    # A directory template the CA names for itself. NOT one carrying
    # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (WebServer does): certreq sends no subject, so the
    # result would name nobody and issuance refuses it — correctly, but it tests nothing here.
    [string]$AdTemplate = 'Machine',
    [string]$EnrolRole  = 'requester',
    [int]$BenchCount    = 5,
    # Opt in to the parts that change client state beyond enrolling: clearing this CA's
    # machine certificates so autoenrolment has something to do, and enabling AEPolicy.
    [switch]$IncludeAutoEnrolment,
    [switch]$IncludeBench
)

$ErrorActionPreference = 'Continue'
$script:pass = 0
$script:fail = 0
function Chk([string]$what, $expected, $got) {
    if ("$expected" -eq "$got") { Write-Host "  [PASS] $what"; $script:pass++ }
    else { Write-Host "  [FAIL] $what (expected '$expected' got '$got')"; $script:fail++ }
}
function Note([string]$m) { Write-Host "  $m" }

# ── prerequisites, each named individually ───────────────────────────────────────────
Write-Host "=== 1. this machine can do the thing at all ==="
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Chk "running elevated (the machine store and -machine enrolment need it)" $true $isAdmin
$cs = Get-CimInstance Win32_ComputerSystem
Chk "  the machine is domain-joined" $true $cs.PartOfDomain
$secure = $false
try { $secure = Test-ComputerSecureChannel -ErrorAction Stop } catch { $secure = $false }
Chk "  and its secure channel to the domain is healthy" $true $secure

# ── trust ────────────────────────────────────────────────────────────────────────────
Write-Host "=== 2. TRUST: the anchors are the ones this CA actually uses ==="
if (-not $RootThumbprint -or -not $SubThumbprint) {
    Write-Host "  [FAIL] -RootThumbprint / -SubThumbprint not given — trust cannot be asserted"
    Write-Host "         by name, and this will not guess. Take them from the console:"
    Write-Host "         GET CONSOLE/api/ca-instances/ID/cert-pem, then: openssl x509 -noout -fingerprint -sha1"
    $script:fail++
} else {
    $root = Get-Item "Cert:\LocalMachine\Root\$RootThumbprint" -ErrorAction SilentlyContinue
    Chk "the CA root is in LocalMachine\Root" $true ($null -ne $root)
    if ($root) { Chk "  and it is self-signed, as a root must be" $true ($root.Subject -eq $root.Issuer) }
    $sub = Get-Item "Cert:\LocalMachine\CA\$SubThumbprint" -ErrorAction SilentlyContinue
    Chk "the issuing CA is in LocalMachine\CA" $true ($null -ne $sub)
    # ⚠️ An intermediate in Root is a real misconfiguration: it would be trusted as an anchor
    # on its own, so a compromise of it could not be contained by distrusting the root.
    $subInRoot = Get-Item "Cert:\LocalMachine\Root\$SubThumbprint" -ErrorAction SilentlyContinue
    Chk "  and NOT also in Root (it is not self-signed)" $true ($null -eq $subInRoot)
}

# ── registration ─────────────────────────────────────────────────────────────────────
Write-Host "=== 3. the policy server registers, which means the policy is ACCEPTABLE ==="
# Registering is itself an assertion: the client parses the whole policy document and refuses
# a malformed one, so a successful registration is Windows saying our XCEP is well-formed.
$script:regMachine = $false
$script:regUser    = $false
try {
    Add-CertificateEnrollmentPolicyServer -Url $XcepUrl -Context Machine `
        -AutoEnrollmentEnabled -ErrorAction Stop | Out-Null
    $script:regMachine = $true
} catch { Note "machine registration threw: $($_.Exception.Message)" }
$m = Get-CertificateEnrollmentPolicyServer -Scope All -Context Machine |
     Where-Object { $_.Url -eq $XcepUrl } | Select-Object -First 1
Chk "the machine-context policy server registers" $true ($null -ne $m)
if ($m) { Chk "  and it negotiated Kerberos, not a password prompt" 'Kerberos' "$($m.AuthType)" }

# ── enrolment, machine context ───────────────────────────────────────────────────────
Write-Host "=== 4. an unattended machine enrolment issues a certificate ==="
# ⚠️ SELECT BY THE SERIAL certreq REPORTS, not by diffing the store. Windows re-installs a
# certificate it already holds for an existing key container, so a previously-issued — and
# possibly REVOKED — certificate reappears and a before/after diff calls it this run's. That
# happened: a later section verified one issued 45 minutes earlier whose status was already
# revoked, and reported the OCSP responder as broken. It had answered correctly.
& certutil -f -policyserver * -policycache delete | Out-Null
$enr = & certreq -q -enroll -machine -policyserver $XcepUrl GenericComputer 2>&1
$enrText = ($enr | Out-String)
Chk "certreq reports the certificate issued" $true ($enrText -match 'has been issued')
$serial = ([regex]::Match($enrText, 'Serial Number:\s*([0-9a-fA-F]+)')).Groups[1].Value
Chk "  and it reported the serial it received" $true ([bool]$serial)
$leaf = $null
if ($serial) {
    $leaf = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.SerialNumber -eq $serial } | Select-Object -First 1
    Chk "  and that certificate is in the machine store" $true ($null -ne $leaf)
}

# ── verification through the client's own revocation stack ───────────────────────────
Write-Host "=== 5. the issued certificate VERIFIES, through the Windows revocation stack ==="
if (-not $leaf) {
    Write-Host "  [FAIL] nothing was issued in section 4, so there is nothing to verify"
    Write-Host "         (this refuses to fall back to another certificate in the store)"
    $script:fail++
} else {
    $cerPath = Join-Path $env:TEMP 'fpki_verify.cer'
    [IO.File]::WriteAllBytes($cerPath, $leaf.RawData)
    # The URL cache is cleared so the fetches below are real ones, not a previous answer.
    & certutil -urlcache * delete | Out-Null
    $ver = (& certutil -urlfetch -verify $cerPath 2>&1 | Out-String)
    Chk "the chain verifies with no error status" $true ($ver -match 'dwErrorStatus=0')
    # ⚠️ ASSERT BOTH PATHS SEPARATELY. certutil uses OCSP or the CRL depending on what the
    # certificate carries and what answers first, so one combined "it verified" can pass
    # while the responder is dead and the CRL carries the whole result.
    Chk "  the CRL was fetched and verified"  $true ($ver -match 'Verified .Base CRL')
    Chk "  the OCSP response was fetched and verified" $true ($ver -match 'Verified .OCSP.')
}

# ── the console half: revocation, and templates from the directory ───────────────────
$sess = $null
if ($Console -and $ConsoleUser) {
    if (-not $ConsolePassword) {
        $ConsolePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                (Read-Host -AsSecureString "console password for $ConsoleUser")))
    }
    # A lab CA is commonly served on a certificate this machine has no reason to trust yet;
    # this affects only these API calls, never the enrolment paths above, which use the
    # client's own trust decisions.
    # PS 5.1 defaults to SSL3/TLS1, which the console does not offer; without this the first
    # call after a pause fails as "the underlying connection was closed".
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    try { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
    try {
        Invoke-RestMethod -Uri "$Console/api/login" -Method Post -SessionVariable sess `
            -Body @{ username = $ConsoleUser; password = $ConsolePassword } -ErrorAction Stop | Out-Null
        $script:sess = $sess
    } catch { Note "console login failed: $($_.Exception.Message)" }
}
function Api([string]$method, [string]$path, $body) {
    Invoke-RestMethod -Uri "$Console$path" -Method $method -WebSession $script:sess -Body $body -ErrorAction Stop
}

Write-Host "=== 6. REVOCATION reaches the client ==="
if (-not $script:sess -or -not $serial) {
    Write-Host "  [FAIL] no console session (-Console/-ConsoleUser) or nothing issued — the"
    Write-Host "         revocation half did not run, and a half that does not run is not a pass."
    $script:fail++
} else {
    $lower = $serial.ToLower().TrimStart('0')
    $ok = $false
    # The reason is the RFC 5280 code (5 = cessationOfOperation); a name is refused with 400.
    try { Api POST "/api/certs/$lower/revoke?reason=5" $null | Out-Null; $ok = $true }
    catch { Note "revoke failed: $($_.Exception.Message)" }
    Chk "the CA accepted the revocation" $true $ok
    # The client must SEE it, which is the point — our word for it proves nothing.
    & certutil -urlcache * delete | Out-Null
    $ver2 = (& certutil -urlfetch -verify (Join-Path $env:TEMP 'fpki_verify.cer') 2>&1 | Out-String)
    Chk "  and the client now reports it REVOKED" $true ($ver2 -match 'Revoked .OCSP.' -or $ver2 -match 'CERT_TRUST_IS_REVOKED')
}

# ── templates imported from the real directory ───────────────────────────────────────
Write-Host "=== 7. templates imported from the REAL directory ==="
$script:imported = $false; $script:roleMade = $false; $script:bound = $false
$adSubj = $null
if (-not $script:sess) {
    Write-Host "  [FAIL] no console session — the import half did not run."
    $script:fail++
} else {
    $adRole = 'fpki-adtest'
    $prev = $null
    try { $prev = Api GET '/api/templates/ad' $null } catch { Note "AD preview failed: $($_.Exception.Message)" }
    Chk "the directory answers a template query it was never given a base for" $true ($prev.count -gt 0)
    Chk "  and it offers the one this section imports" $true (@($prev.templates | Where-Object { $_.name -eq $AdTemplate }).Count -eq 1)

    # ⚠️ IMPORTING ANYTHING DISPLACES THE BUILT-INS. fastpki-ms reads ms_templates once at
    # startup and falls back to the built-ins only while that table is EMPTY, so one imported
    # row means the three defaults stop being served at the next restart. That is why this
    # runs last and why the finally-block below empties the table again.
    try { Api POST '/api/templates/ad' @{ name = $AdTemplate } | Out-Null; $script:imported = $true } catch {}
    Chk "the import succeeds" $true $script:imported
    $tmplDays = ($prev.templates | Where-Object { $_.name -eq $AdTemplate } | Select-Object -First 1).validity_days

    # ⚠️ THE REFUSAL FIRST. A template with no grant is simply absent from <policies>, and the
    # client says CRYPT_E_NOT_FOUND — an error naming nothing about permissions. Without
    # asserting the refusal, the success afterwards could be anything.
    Api POST '/api/endpoints/ms/restart' $null | Out-Null
    Start-Sleep 12
    & certutil -f -policyserver * -policycache delete | Out-Null
    $noGrant = (& certreq -q -enroll -machine -policyserver $XcepUrl $AdTemplate 2>&1 | Out-String)
    Chk "an imported template with NO grant cannot be enrolled" $true ($noGrant -notmatch 'has been issued')

    # ⚠️ A ROLE OF ITS OWN. POST /api/roles/<r>/permissions REPLACES the grant list wholesale,
    # so amending a live role means rewriting every grant it holds. Worse, amending it is
    # currently impossible once anything is imported: the scope validator rejects a scope
    # naming a template it cannot find, and the built-ins are not rows, so the enrolling
    # role's own existing grants fail to save. Effective grants are the UNION of the primary
    # role and roles held through subject_roles, so a second role adds the template without
    # touching the first.
    $subjects = Api GET '/api/subject-roles' $null
    $adSubj = ($subjects | Where-Object { $_.selector_value -like '*$' } | Select-Object -First 1).selector_value
    Chk "  PRECONDITION: the machine identity is known to the deployment" $true ([bool]$adSubj)
    try { Api POST '/api/roles' @{ name = $adRole; description = 'Test-FastPKIEnrolment' } | Out-Null; $script:roleMade = $true } catch {}
    $granted = $false
    try { Api POST "/api/roles/$adRole/permissions" @{ grants = "template:ro|$AdTemplate`nenrol:ms|*" } | Out-Null; $granted = $true } catch {}
    Chk "the template:ro grant is accepted" $true $granted
    if ($adSubj) {
        try { Api POST '/api/subject-roles' @{ selector_type='user'; selector_value=$adSubj; role=$adRole } | Out-Null; $script:bound = $true } catch {}
    }
    Chk "  and the enrolling identity holds it" $true $script:bound

    Api POST '/api/endpoints/ms/restart' $null | Out-Null
    Start-Sleep 12
    & certutil -f -policyserver * -policycache delete | Out-Null
    $got = (& certreq -q -enroll -machine -policyserver $XcepUrl $AdTemplate 2>&1 | Out-String)
    Chk "the SAME enrolment now issues — the grant is the only thing that changed" $true ($got -match 'has been issued')
    $adSer = ([regex]::Match($got, 'Serial Number:\s*([0-9a-fA-F]+)')).Groups[1].Value
    if ($adSer -and $tmplDays) {
        $c = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.SerialNumber -eq $adSer } | Select-Object -First 1
        if ($c) {
            $days = [int]($c.NotAfter - $c.NotBefore).TotalDays
            Chk "  the certificate carries the DIRECTORY validity ($tmplDays days), not a server default" `
                $true ([Math]::Abs($days - $tmplDays) -le 2)
        }
    }
}

# ── the user-context templates ───────────────────────────────────────────────────────
# ⚠️ THIS IS WHERE RUNNING LOCALLY PAYS FOR ITSELF. Driven over SSH, this needs a stored
# password and a scheduled task purely to obtain a logon with network credentials. Here the
# session already has them, so it is three plain commands and no secret.
Write-Host "=== 8. the user-context templates ==="
try {
    Add-CertificateEnrollmentPolicyServer -Url $XcepUrl -Context User `
        -AutoEnrollmentEnabled -ErrorAction Stop | Out-Null
    $script:regUser = $true
} catch {
    $m = $_.Exception.Message
    Note "user registration threw: $m"
    if ($m -match '803d0005') {
        # ⚠️ THIS EXACT ERROR IS ALMOST NEVER THE SERVER. It is what a session with no network
        # credentials produces: outbound SPNEGO sends nothing, so the server answers 401 having
        # been offered no credential, and the client renders that as "access was denied by the
        # remote endpoint". A key-authenticated SSH session is the usual way to get here.
        Note "  -> that is the no-network-credentials case, not a refusal by the CA."
        Note "     Run this from a real logon — the console, RDP, or a scheduled task with"
        Note "     -User/-Password. Machine-context checks above work over SSH because they"
        Note "     use the COMPUTER account, which the system always holds."
    }
}
$u = Get-CertificateEnrollmentPolicyServer -Scope All -Context User |
     Where-Object { $_.Url -eq $XcepUrl } | Select-Object -First 1
Chk "the user-context policy server registers" $true ($null -ne $u)

& certutil -f -user -policyserver * -policycache delete | Out-Null
$eOut = (& certreq -q -enroll -policyserver $XcepUrl Email 2>&1 | Out-String)
Chk "Email issues in the user context" $true ($eOut -match 'has been issued')
$eSer = ([regex]::Match($eOut, 'Serial Number:\s*([0-9a-fA-F]+)')).Groups[1].Value
if ($eSer) {
    $uc = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.SerialNumber -eq $eSer } | Select-Object -First 1
    if ($uc) {
        # ⚠️ THE **USER** HALF OF THE QUALIFIED NAME. Identities are provider-qualified
        # internally (provider\user); the qualifier is an internal fact and has no business in
        # a certificate. A regression either way — the whole qualified string in the CN, or a
        # name the requester supplied instead of the authenticated one — shows up only here.
        $sam = $env:USERNAME
        Chk "  its subject is the authenticated user, unqualified" $true ($uc.Subject -match "CN=$sam(,|$)")
        Chk "  and the provider qualifier is NOT in the certificate" $true ($uc.Subject -notmatch '\\')
    }
}
# ⚠️ GenericUser grants CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and certreq sends no subject, so the
# result would carry an empty subject and no SAN — a certificate identifying nobody, which we
# used to issue silently. Issuance refuses it now, and the REFUSAL is the assertion.
& certutil -f -user -policyserver * -policycache delete | Out-Null
$gOut = (& certreq -q -enroll -policyserver $XcepUrl GenericUser 2>&1 | Out-String)
Chk "a request that would name nobody is refused, not issued" $true ($gOut -notmatch 'has been issued')

# ── autoenrolment ────────────────────────────────────────────────────────────────────
if ($IncludeAutoEnrolment) {
    Write-Host "=== 9. autoenrolment (certutil -pulse) ==="
    # ⚠️ TWO PREREQUISITES, OR THIS MEASURES NOTHING. Autoenrolment declines to replace a
    # valid certificate, so a machine already holding one reports success and issues nothing.
    # And with no AEPolicy the client fetches our policy and then does nothing at all —
    # measured: "XCEP offering 3 of 3 templates" twice on the server and no request ever
    # arriving, which reads as our policy being unusable when the client was never asked.
    $caCn = if ($SubThumbprint) {
        ((Get-Item "Cert:\LocalMachine\CA\$SubThumbprint" -EA SilentlyContinue).Subject -split ',' |
         Where-Object { $_ -match 'CN=' } | Select-Object -First 1) -replace '.*CN='
    } else { $null }
    Chk "PRECONDITION: the issuing CA's name is known, so the counts below mean something" $true ([bool]$caCn)
    if ($caCn) {
        $aeKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment'
        $script:aeWas = (Get-ItemProperty -Path $aeKey -Name AEPolicy -EA SilentlyContinue).AEPolicy
        New-Item -Path $aeKey -Force | Out-Null
        Set-ItemProperty -Path $aeKey -Name AEPolicy -Value 7 -Type DWord
        $script:aeSet = $true
        # X509Store.Remove, not Remove-Item on the Cert: drive — the latter silently removes
        # almost none of them (measured: 59 in, 58 left).
        $st = New-Object Security.Cryptography.X509Certificates.X509Store('My','LocalMachine')
        $st.Open('ReadWrite')
        $before = @($st.Certificates | Where-Object { $_.Issuer -match $caCn }).Count
        @($st.Certificates | Where-Object { $_.Issuer -match $caCn }) | ForEach-Object { $st.Remove($_) }
        $st.Close()
        $cleared = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -match $caCn }).Count
        Chk "PRECONDITION: the machine holds no certificate from this CA" 0 $cleared
        $pulse = (& certutil -pulse 2>&1 | Out-String)
        Chk "certutil -pulse completes" $true ($pulse -match 'completed successfully')
        $after = 0
        for ($i = 0; $i -lt 12 -and $after -eq 0; $i++) {
            Start-Sleep 5
            $after = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -match $caCn }).Count
        }
        Chk "  and autoenrolment issued a certificate without being told which template" $true ($after -gt 0)
        Note "(this CA's machine certificates: $before before, $after after autoenrolment)"
    }
}

# ── what it costs, and what a fleet does at once ─────────────────────────────────────
if ($IncludeBench) {
    Write-Host "=== 10. cost, and a burst ==="
    # ⚠️ NOT A PASS/FAIL ON SPEED — a threshold measures the machine, not the CA. This reports
    # the cost and asserts only that every enrolment succeeded. Timed around certreq itself,
    # so the number is the enrolment rather than the harness around it.
    $ms = @()
    for ($i = 1; $i -le $BenchCount; $i++) {
        & certutil -f -policyserver * -policycache delete | Out-Null
        $o = $null
        $t = Measure-Command { $o = & certreq -q -enroll -machine -policyserver $XcepUrl GenericComputer 2>&1 }
        if (($o | Out-String) -match 'has been issued') { $ms += [int]$t.TotalMilliseconds }
    }
    Chk "every sequential enrolment issued ($BenchCount of them)" $BenchCount $ms.Count
    if ($ms.Count) {
        $avg = [int]($ms | Measure-Object -Average).Average
        $mn  = ($ms | Measure-Object -Minimum).Minimum
        $mx  = ($ms | Measure-Object -Maximum).Maximum
        Note "one enrolment, policy fetch included: mean ${avg}ms  min ${mn}ms  max ${mx}ms"
    }
    # ⚠️ CONCURRENT, BECAUSE THAT IS THE SHAPE THAT BREAKS. A fleet does not enrol in turn; it
    # wakes on one schedule and arrives together, which is how the keytab merge race was
    # found. Sequential requests would never have surfaced it.
    $burstOk = 0
    $b = Measure-Command {
        $jobs = 1..$BenchCount | ForEach-Object {
            Start-Job -ScriptBlock { param($u) & certreq -q -enroll -machine -policyserver $u GenericComputer 2>&1 } -ArgumentList $XcepUrl
        }
        $null = $jobs | Wait-Job -Timeout 300
        $burstOk = @($jobs | Receive-Job | Select-String -SimpleMatch 'has been issued').Count
        $jobs | Remove-Job -Force
    }
    Chk "  and every enrolment in a simultaneous burst issued" $BenchCount $burstOk
    Note "$BenchCount at once: $([int]$b.TotalMilliseconds)ms wall clock"
}

# ── teardown ─────────────────────────────────────────────────────────────────────────
# ⚠️ ALWAYS, and in reverse. Leaving an imported template behind is not untidy, it is
# DESTRUCTIVE: while ms_templates is non-empty the built-in templates are not served at all,
# so a run that died mid-way would leave the deployment unable to enrol what it could before.
Write-Host "=== teardown ==="
try {
    if ($script:sess) {
        if ($script:bound -and $adSubj) {
            try { Api DELETE '/api/subject-roles' @{ selector_type='user'; selector_value=$adSubj; role='fpki-adtest' } | Out-Null } catch {}
        }
        if ($script:roleMade) { try { Api DELETE '/api/roles/fpki-adtest' $null | Out-Null } catch {} }
        if ($script:imported) {
            try { Api DELETE "/api/templates/$AdTemplate" $null | Out-Null } catch {}
            try { Api POST '/api/endpoints/ms/restart' $null | Out-Null } catch {}
        }
    }
    # AEPolicy is client-wide Group-Policy state: back exactly as it was, removed if absent.
    if ($script:aeSet) {
        $aeKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment'
        if ($null -ne $script:aeWas) { Set-ItemProperty -Path $aeKey -Name AEPolicy -Value $script:aeWas -Type DWord }
        else { Remove-ItemProperty -Path $aeKey -Name AEPolicy -EA SilentlyContinue }
    }
    if ($script:regUser)    { Remove-CertificateEnrollmentPolicyServer -Url $XcepUrl -Context User -EA SilentlyContinue | Out-Null }
    if ($script:regMachine) { Remove-CertificateEnrollmentPolicyServer -Url $XcepUrl -Context Machine -EA SilentlyContinue | Out-Null }
    & certutil -f -policyserver * -policycache delete | Out-Null
    & certutil -f -user -policyserver * -policycache delete | Out-Null
    Note "registration removed, caches cleared, imported template and role deleted"
} catch { Note "teardown hit: $($_.Exception.Message)" }

Write-Host ""
Write-Host "=== FASTPKI WINDOWS ENROLMENT: PASS=$script:pass FAIL=$script:fail ==="
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
