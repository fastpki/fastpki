<#
.SYNOPSIS
  Point a domain-joined Windows machine at a FastPKI enrolment policy (MS-XCEP/WSTEP) and
  enrol, unattended.

.DESCRIPTION
  Windows will not enrol against an enrolment-policy server it has not been told about.
  There is no discovery step: the policy server is a registry registration, normally made
  by Group Policy, and without it `certreq -policyserver <uri>` reports "Template not
  found" because it looks templates up in AD instead.

  This registers the policy server for the MACHINE context, then triggers autoenrolment.

  !! THE POLICY ID IS NOT OURS TO INVENT. Windows keys the registration on the policy's own
  id, which the server states in its GetPolicies response as <policyID>. If the registry
  key name and that value disagree, the client fetches policy and then cannot match it to
  the registration. This script READS it from the server rather than taking it on trust.

.PARAMETER Url
  The XCEP endpoint, e.g. https://pki.example.com:8446/msxcep/sub-ca-dc1

.PARAMETER Template
  Optional. Enrol for this template by name instead of running autoenrolment.

.PARAMETER Diagnose
  Print what the server advertises and what the client did, then stop. Changes nothing.

.EXAMPLE
  .\Register-FastPKIEnrollment.ps1 -Url https://pki.example.com:8446/msxcep/sub-ca-dc1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Url,
    [string]$Template,
    [switch]$Diagnose,
    # Teardown. -Unregister removes the policy-server registration this script created for
    # $Url; add -RemoveCerts to delete the certificates it recorded issuing. Both are needed
    # for anything that runs repeatedly, because registration is otherwise permanent and each
    # run leaves another certificate in the machine store.
    [switch]$Unregister,
    [switch]$RemoveCerts,
    # Where the issued-certificate record lives. Deliberately a file rather than a heuristic:
    # see Remove-RecordedCerts.
    [string]$StatePath = (Join-Path $env:ProgramData 'FastPKI\enrolled.json')
)

$ErrorActionPreference = 'Stop'

function Say($m)  { Write-Host $m }
function Warn($m) { Write-Host "WARNING: $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "FAILED: $m" -ForegroundColor Red; exit 1 }

# -- teardown --------------------------------------------------------------------------
# ⚠️ NEVER DELETE A CERTIFICATE WE CANNOT PROVE WE CREATED. "Issued by something matching
# FastPKI" is a tempting filter and a wrong one: on a real machine that also matches
# certificates an operator enrolled by hand, or that autoenrolment renewed, and deleting
# those to tidy up after a test is a far worse outcome than leaving debris behind. So each
# enrolment RECORDS what it issued -- thumbprint and store -- and teardown removes exactly
# that set. With no record, it removes nothing and says so.
function Record-IssuedCert($thumb, $store, $subject) {
    $dir = Split-Path -Parent $StatePath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $rows = @()
    if (Test-Path $StatePath) {
        try { $rows = @(Get-Content $StatePath -Raw | ConvertFrom-Json) } catch { $rows = @() }
    }
    $rows += [pscustomobject]@{
        thumbprint = $thumb; store = $store; subject = $subject
        url        = $Url;   when  = (Get-Date).ToString('o')
    }
    # ASCII: PowerShell 5.1's default file encoding is UTF-16, which anything else reading
    # this file would have to know about. JSON on disk should be plain.
    ($rows | ConvertTo-Json -Depth 4) | Out-File -FilePath $StatePath -Encoding ascii
}

function Remove-RecordedCerts {
    if (-not (Test-Path $StatePath)) {
        Warn "no record at $StatePath -- nothing is removed."
        Warn "this script only deletes certificates it recorded issuing; anything else on this"
        Warn "machine may be an operator's and is not ours to tidy."
        return 0
    }
    $rows = @(Get-Content $StatePath -Raw | ConvertFrom-Json) | Where-Object { $_.url -eq $Url }
    $gone = 0
    foreach ($r in $rows) {
        $path = Join-Path $r.store $r.thumbprint
        if (Test-Path $path) {
            Remove-Item $path -Force
            Say ("removed cert     : " + $r.subject + "  [" + $r.thumbprint + "]")
            $gone++
        }
    }
    # Keep only the rows for OTHER urls, so a second teardown is a no-op rather than an error.
    $keep = @(Get-Content $StatePath -Raw | ConvertFrom-Json) | Where-Object { $_.url -ne $Url }
    if ($keep) { ($keep | ConvertTo-Json -Depth 4) | Out-File -FilePath $StatePath -Encoding ascii }
    else       { Remove-Item $StatePath -Force }
    return $gone
}

if ($Unregister) {
    # ⚠️ THE SUPPORTED CMDLETS, NOT THE REGISTRY. Remove-CertificateEnrollmentPolicyServer
    # owns the on-disk shape -- the key name, the flags, and the per-context split -- so
    # hand-editing HKLM means re-implementing all three and re-checking them on every
    # Windows release. It also needs no policy id fetched from the server, so teardown works
    # when the CA is down, mid-roll or already deleted, which is exactly when a run aborts
    # and leaves a registration behind.
    #
    # BOTH CONTEXTS. Machine templates register under Machine, user templates under User;
    # removing one silently leaves the other, and the leftover is invisible until the next
    # run behaves oddly.
    $removed = 0
    foreach ($ctx in @('Machine','User')) {
        $present = @(Get-CertificateEnrollmentPolicyServer -Scope All -Context $ctx -ErrorAction SilentlyContinue |
                     Where-Object { $_.Url -eq $Url })
        if (-not $present) { continue }
        try {
            Remove-CertificateEnrollmentPolicyServer -Url $Url -Context $ctx -ErrorAction Stop
            Say "unregistered      : $Url  [$ctx]"
            $removed++
        } catch {
            Warn "could not unregister $Url in the $ctx context: $($_.Exception.Message)"
        }
    }
    if ($removed -eq 0) { Say "no policy-server registration for $Url in either context." }

    # The POLICY cache is a separate cache from the revocation one, and it outlives the
    # registration: a stale copy is why a re-registered server reports "cannot find
    # templates". Clearing it is part of leaving the machine as we found it.
    & certutil -PolicyCache delete       2>&1 | Out-Null
    & certutil -PolicyCache -User delete 2>&1 | Out-Null
    Say "policy cache      : cleared (machine and user)"

    $certs = 0
    if ($RemoveCerts) { $certs = Remove-RecordedCerts }
    Say ""
    Say "teardown complete : $removed registration(s), $certs certificate(s) removed."
    # ⚠️ REVOKED CERTIFICATES ARE LEFT REVOKED, deliberately. Revocation happens on the CA and
    # is the honest end state of a revocation test; un-revoking to tidy up would destroy the
    # evidence the test exists to produce.
    exit 0
}

# -- who we are ------------------------------------------------------------------------
# Machine enrolment needs the MACHINE's identity. Running this as a normal user registers
# the policy for that user instead, and the failure appears much later as "no templates".
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
             [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Die "run this elevated -- machine enrolment writes to HKLM and uses the computer account." }
Say "running as        : $($id.Name)"

# !! A LOCAL ACCOUNT HAS NO KERBEROS TICKET, EVER. Running this as the machine's local
# Administrator -- which is what you get over SSH, or from a console login as ".\Administrator"
# -- means `klist` is empty and every SPNEGO attempt is refused. The endpoint answers 401
# and it reads as a server or keytab problem, which is where an hour goes. Machine
# enrolment wants the MACHINE's identity: run as SYSTEM (a scheduled task with /ru SYSTEM,
# or PsExec -s), or at least as a domain account.
if ($id.Name -notmatch '^NT AUTHORITY\\SYSTEM$') {
    $short = $env:COMPUTERNAME
    if ($id.Name -like "$short\*") {
        Warn "you are running as a LOCAL account ($($id.Name)), which has no Kerberos ticket."
        Warn "SPNEGO will be refused and this will look like a server problem. Run as SYSTEM:"
        Warn "  schtasks /create /tn fastpki-enrol /ru SYSTEM /sc once /st 00:00 /tr ""powershell -File $PSCommandPath -Url $Url"" /f"
        Warn "  schtasks /run /tn fastpki-enrol"
    }
}

$cs = Get-WmiObject Win32_ComputerSystem
if (-not $cs.PartOfDomain) {
    Warn "this machine is not domain-joined; Kerberos enrolment cannot work here."
} else {
    Say "domain            : $($cs.Domain)"
}

# -- what the server says about itself --------------------------------------------------
# GetPolicies is unauthenticated-friendly here only in the sense that we send the
# machine's own credentials; the point is to read policyID and the advertised
# authentication before changing anything.
$soap = @'
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>
<GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
<client/><requestFilter/></GetPolicies></s:Body></s:Envelope>
'@
Say "asking            : $Url"
try {
    $req = [System.Net.WebRequest]::Create($Url)
    $req.Method = 'POST'; $req.ContentType = 'application/soap+xml; charset=utf-8'
    $req.UseDefaultCredentials = $true
    $b = [Text.Encoding]::UTF8.GetBytes($soap); $req.ContentLength = $b.Length
    $s = $req.GetRequestStream(); $s.Write($b,0,$b.Length); $s.Close()
    $xml = (New-Object IO.StreamReader($req.GetResponse().GetResponseStream())).ReadToEnd()
} catch [Net.WebException] {
    $r = $_.Exception.Response
    if ($r) { Die "the policy endpoint answered HTTP $([int]$r.StatusCode). If that is 401, this machine's ticket was refused -- check the SPN and the keytab for that host." }
    Die "could not reach $Url -- $($_.Exception.Message)"
}

$policyId  = [regex]::Match($xml, '<policyID>([^<]+)</policyID>').Groups[1].Value
$templates = [regex]::Matches($xml, '<commonName>([^<]+)</commonName>') | ForEach-Object { $_.Groups[1].Value }
$auths     = [regex]::Matches($xml, '<clientAuthentication>(\d+)</clientAuthentication>') |
                ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
if (-not $policyId) { Die "the response carried no <policyID>; this does not look like an MS-XCEP endpoint." }

$authName = @{ '1'='anonymous'; '2'='Kerberos'; '4'='username/password'; '8'='client certificate' }
Say "policy id         : $policyId"
Say "templates offered : $($templates -join ', ')"
Say "enrolment accepts : $(($auths | ForEach-Object { "$_ ($($authName[$_]))" }) -join ', ')"

# !! A MACHINE HAS NO PASSWORD TO TYPE. If the server advertises only username/password,
# an unattended machine enrolment cannot proceed no matter how it is registered -- say so
# here rather than letting it surface as ERROR_INVALID_PARAMETER much later.
if ($auths -notcontains '2') {
    Warn "this endpoint does not advertise Kerberos (2) for enrolment."
    Warn "an unattended machine enrolment has no password to offer, so it will fail."
    Warn "on the FastPKI side: give the directory a keytab so SPNEGO is offered."
}

if ($Diagnose) { Say ""; Say "diagnose only -- nothing was changed."; exit 0 }

# -- register the policy server for the machine ----------------------------------------
# ⚠️ THE SUPPORTED CMDLET, NOT HAND-WRITTEN REGISTRY KEYS. This used to create
# HKLM\SOFTWARE\Microsoft\Cryptography\PolicyServers\<policyId> and populate URL,
# PolicyID, FriendlyName, Flags, AuthFlags and Cost by hand. That re-implements a layout
# Windows owns -- the key name, the flag semantics and the per-context split -- and it has to
# be re-checked on every release. Add-CertificateEnrollmentPolicyServer writes the same thing
# and stays correct, and Get-/Remove- are its exact inverses, which is what makes teardown
# reliable rather than a second hand-rolled guess.
#
# -AutoEnrollmentEnabled: the policy participates in `certutil -pulse`, which is the path
# that actually matters in production -- a manual certreq is not autoenrolment.
# -RequireStrongValidation: the endpoint is HTTPS and the client should insist on it.
$ctx = 'Machine'   # this script registers the MACHINE context; user templates need -Context User
Add-CertificateEnrollmentPolicyServer -Url $Url -Context $ctx `
    -AutoEnrollmentEnabled -RequireStrongValidation -ErrorAction Stop
Say "registered        : $Url  [$ctx]"
# A stale POLICY cache is why a freshly registered server reports "cannot find templates".
& certutil -PolicyCache delete 2>&1 | Out-Null

# -- enrol -----------------------------------------------------------------------------
$before = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*FastPKI*' })
$seen   = $before | ForEach-Object { $_.SerialNumber }
Say "certificates from FastPKI before: $($before.Count)"

if ($Template) {
    Say "enrolling         : certreq -q -enroll -machine -policyserver $policyId $Template"
    $out = & certreq.exe -q -enroll -machine -policyserver $policyId $Template 2>&1 | Out-String
    Say $out.Trim()
} else {
    Say "enrolling         : certutil -pulse (autoenrolment)"
    $out = & certutil.exe -pulse 2>&1 | Out-String
    Say $out.Trim()
}

Start-Sleep -Seconds 5
$after = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*FastPKI*' })
$new   = $after | Where-Object { $seen -notcontains $_.SerialNumber }

Say ""
if ($new) {
    Say "ISSUED:"
    foreach ($c in $new) {
        Say ("  " + $c.Subject + "  serial=" + $c.SerialNumber + "  expires " + $c.NotAfter.ToString('yyyy-MM-dd'))
        # Recorded so -Unregister -RemoveCerts can delete exactly this and nothing else.
        # Thumbprint, not serial: it is what addresses a certificate in the store.
        Record-IssuedCert $c.Thumbprint 'Cert:\LocalMachine\My' $c.Subject
    }
    exit 0
}

# !! NOTHING ISSUED IS NOT NECESSARILY A FAILURE. Autoenrolment does not re-enrol a machine
# that already holds a valid certificate for a template, and it reports success for doing
# nothing. Distinguish the two rather than calling both "failed".
Say "no NEW certificate was issued."
if ($after.Count -gt 0) {
    Say "this machine already holds $($after.Count) certificate(s) from FastPKI:"
    foreach ($c in $after) {
        $tmpl = ($c.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.20.2' } | ForEach-Object { $_.Format($false) })
        Say ("  " + $c.Subject + "  template=" + $(if ($tmpl) { $tmpl } else { '(none)' }) + "  expires " + $c.NotAfter.ToString('yyyy-MM-dd'))
    }
    Say "autoenrolment will not replace a valid certificate -- that is why it did nothing."
    Say "to force a fresh one, use -Template <name>, or remove the existing certificate first."
}
Say ""
Say "If you expected a certificate, collect this and attach it to the ticket:"
Say "  certutil -pulse -v"
Say "  wevtutil qe Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational /c:20 /rd:true /f:text"
Say "  wevtutil qe Application /q:"*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-AutoEnrollment']]]" /c:20 /rd:true /f:text"
