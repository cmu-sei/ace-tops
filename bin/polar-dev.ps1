# ACE Tool
#
# Copyright 2026 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
# FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
# EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
# MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
# TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu
# for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
# distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
#
# DM26-0670

#<help>
# bin\polar-dev.ps1: bin/polar-dev for Windows, in PowerShell (Windows PowerShell 5.1, which every Windows 10 and 11 has,
# or PowerShell 7). Your dev container, as a pod in whatever cluster kubectl points at. Your machine needs kubectl, ssh
# (Windows' own OpenSSH, with its ssh-agent service running and your key added) and git; everything else (Nix, the tools,
# the builds, up.nu) runs in the pod. You reach it over SSH with your agent forwarded, so git there uses your own key and
# none is kept in the cluster.
#
#   powershell -ExecutionPolicy Bypass -File bin\polar-dev.ps1 <command>
#
#   up        make or update the pod, clone the sources into it if they are not there, and log in
#   attach    log in again
#   cert [u]  copy your Polar certificate out and import it, with the cluster's CA, into your Windows certificate store
#             (Edge and Chrome use it; for Firefox, import the .p12 it leaves in %USERPROFILE%\.config\polar-admin)
#   forward   the port-forwards a browser here needs: Neo4j (7473, 7687) and ACE (8050)
#   sops      copy your personal sops files (infra\targets\*\user.sops.yaml, gitignored) into the pod's checkout;
#             `up` does this too, and what the pod has of its own stays
#   sync      copy ~/.config/polar-deploy (the deployment PKI and its signed history) and polar-admin back here
#   down      sync, then stop the pod (its volumes stay); --purge removes the namespace and the volumes too
#   build-image [tag] [target]
#             build the dev image from this checkout's current commit, in the pod, and push it to the target's registry
#             in the cluster (tag: the short commit; target: POLAR_TARGET, else local-minimal); it prints the `up` that
#             runs it
#
# Settings (environment, as for bin/polar-dev): POLAR_DEV_IMAGE, POLAR_DEV_ARCH (amd64 or arm64; default: the cluster's
# nodes'), POLAR_DEV_STORAGE_CLASS (default: the cluster's), POLAR_DEV_SSH_KEY (the public key to log in with; default:
# the first your agent holds), POLAR_DEV_SOPS_KEY (the private key sops decrypts with; default:
# SOPS_AGE_SSH_PRIVATE_KEY_FILE, else %USERPROFILE%\.ssh\id_ed25519), POLAR_DEV_REPO and POLAR_DEV_BRANCH (what is
# cloned), POLAR_DEV_PORT (local end of the SSH forward, 2222).
#
# The pod is the same one bin/polar-dev makes, and the two can be used on the same cluster. Your Windows user name, in
# lower case with anything but letters, digits and - made a -, names it and is your user in the pod.
#</help>
#
# This file is kept to ASCII: Windows PowerShell 5.1 reads a script without a byte-order mark in the machine's code page.
# Native programs are run with their output captured through System.Diagnostics.Process (Invoke-Captured), never piped
# between each other: Windows PowerShell re-encodes what passes through its pipeline as text, which breaks a tar stream.
# Files go in and out of the pod as one archive, by kubectl cp, and every text sent to the pod is written with LF.

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 2.0

$OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Get-Variable IsWindows -ErrorAction SilentlyContinue) -and $IsWindows)
$Here = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$Login = if ($env:USERNAME) { $env:USERNAME } else { $env:USER }
$U = (($Login.ToLowerInvariant()) -replace '[^a-z0-9-]', '-').Trim('-')
$NS = "polar-dev-$U"
$Deploy = "polar-dev-$U"
$Repo = if ($env:POLAR_DEV_REPO) { $env:POLAR_DEV_REPO } else { 'https://github.com/cmu-sei/ace-tops.git' }
# The 3.0 line by default: the public repository's main is where the next release is built.
$Branch = if ($env:POLAR_DEV_BRANCH) { $env:POLAR_DEV_BRANCH } else { 'release/3.0.x' }
$Port = if ($env:POLAR_DEV_PORT) { $env:POLAR_DEV_PORT } else { '2222' }
$SopsKey = if ($env:POLAR_DEV_SOPS_KEY) { $env:POLAR_DEV_SOPS_KEY } elseif ($env:SOPS_AGE_SSH_PRIVATE_KEY_FILE) { $env:SOPS_AGE_SSH_PRIVATE_KEY_FILE } else { Join-Path $UserHome '.ssh\id_ed25519' }
$RemoteHome = "/home/$U"
# Windows has no user ids; the pod's user is 1000, as the dev pod's own default.
$Uid = '1000'; $Gid = '1000'
$Temp = [IO.Path]::GetTempPath()

function Say([string]$m) { Write-Host "polar-dev: $m" }
function Die([string]$m) { [Console]::Error.WriteLine("polar-dev: $m"); exit 1 }

# ---- Running programs -------------------------------------------------------

# One argument as a Windows command line takes it: quoted when it has a space or a quote, a quote escaped.
function Quote-Arg([string]$a) {
    if ($a -eq '') { return '""' }
    if ($a -notmatch '[\s"]') { return $a }
    $q = ($a -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1'
    return '"' + $q + '"'
}

# Runs a program to its end and returns its exit code and what it wrote, each stream on its own.
function Invoke-Captured([string]$exe, [string[]]$argv) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = (($argv | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    # PowerShell's location is not the process's working folder, which a program started here inherits.
    $psi.WorkingDirectory = (Get-Location).ProviderPath
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    try { $p = [System.Diagnostics.Process]::Start($psi) } catch { return [pscustomobject]@{ Code = 127; Out = ''; Err = "$exe could not be started: $_" } }
    $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    return [pscustomobject]@{ Code = $p.ExitCode; Out = $o.Result; Err = $e.Result }
}

function K([string[]]$argv) { Invoke-Captured 'kubectl' (@('-n', $NS) + $argv) }

# Writes text with LF line ends and no byte-order mark: what the pod, kustomize and bash read.
function Write-Lf([string]$path, [string]$text) {
    [IO.File]::WriteAllText($path, ($text -replace "`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
}

function Lines([string]$s) { if ($null -eq $s) { return @() }; @($s -split "`r?`n" | Where-Object { $_ -ne '' }) }

# ---- The cluster and the pod --------------------------------------------------

function Get-SshOpts {
    $r = Invoke-Captured 'kubectl' @('get', 'namespace', $NS, '-o', 'jsonpath={.metadata.uid}')
    $uid = if ($r.Code -eq 0 -and $r.Out.Length -ge 8) { $r.Out.Substring(0, 8) } else { '' }
    $known = Join-Path $UserHome ".ssh\polar-dev_known_hosts.$uid"
    return @('-A', '-p', $Port, '-o', 'StrictHostKeyChecking=accept-new', '-o', "UserKnownHostsFile=$known")
}

function Get-ClusterArch {
    if ($env:POLAR_DEV_ARCH) { return $env:POLAR_DEV_ARCH }
    $r = Invoke-Captured 'kubectl' @('get', 'nodes', '-o', 'jsonpath={.items[*].status.nodeInfo.architecture}')
    if ($r.Code -ne 0) { Die "cannot read the cluster's nodes for their architecture (set POLAR_DEV_ARCH to amd64 or arm64)" }
    $arches = @($r.Out -split '\s+' | Where-Object { $_ } | Sort-Object -Unique)
    if ($arches.Count -ne 1) { Die "the cluster's nodes are $($arches -join ','): set POLAR_DEV_ARCH to the one the pod should run on" }
    return $arches[0]
}

# The newest of the dev pods (one being replaced may still be there).
function Get-Pod {
    $r = K @('get', 'pod', '-l', 'app=polar-dev', '--sort-by=.metadata.creationTimestamp', '-o', 'jsonpath={.items[-1:].metadata.name}')
    if ($r.Code -eq 0) { return $r.Out.Trim() } else { return '' }
}

# Waits for the rollout, saying what the pod is doing as it happens: its status, each event, and while the init container
# copies the image's Nix store to its volume, how much is copied.
function Wait-Ready {
    $seenStatus = ''; $seenEvents = @{}; $lastCopy = [DateTime]::MinValue; $p = ''
    for ($i = 0; $i -lt 720; $i++) {
        if ((K @('rollout', 'status', "deploy/$Deploy", '--timeout=1s')).Code -eq 0) { Say 'the pod is ready'; return }
        $p = Get-Pod
        if ($p) {
            $st = K @('get', 'pod', $p, '--no-headers')
            $status = if ($st.Code -eq 0) { (($st.Out.Trim()) -split '\s+')[2] } else { '' }
            if ($status -and $status -ne $seenStatus) { Say "pod ${p}: $status"; $seenStatus = $status }
            $ev = K @('get', 'events', '--field-selector', "involvedObject.name=$p", '--sort-by=.lastTimestamp', '-o', 'custom-columns=R:.reason,M:.message', '--no-headers')
            foreach ($line in (Lines $ev.Out)) { if (-not $seenEvents.ContainsKey($line)) { $seenEvents[$line] = $true; Write-Host "  $line" } }
            if ($status -eq 'Init:0/1' -and ((Get-Date) - $lastCopy).TotalSeconds -ge 30) {
                $c = K @('exec', $p, '-c', 'seed', '--', 'nu', '-c', "if ('/seed/store' | path exists) { du /seed | get 0.physical | into string } else { 'nothing yet' }")
                if ($c.Code -eq 0 -and $c.Out.Trim()) { Say "  seeding the Nix store from the image: $($c.Out.Trim()) copied so far" }
                $lastCopy = Get-Date
            }
        }
        Start-Sleep -Seconds 5
    }
    Die "the pod did not become ready in an hour (kubectl -n $NS describe pod $p)"
}

# ---- Your ssh agent -----------------------------------------------------------

# Windows' OpenSSH keeps keys in a service, off by default; ssh from Git for Windows, first on the PATH, has an agent of
# its own that this ssh-add would not be talking to.
function Test-Agent {
    if ($OnWindows) {
        $ssh = Get-Command ssh -ErrorAction SilentlyContinue
        if (-not $ssh) { Die "no ssh on the PATH: add Windows' OpenSSH client (Settings, System, Optional features, OpenSSH Client)" }
        if ($ssh.Source -notlike "*\System32\OpenSSH\*") {
            Say "warning: ssh here is $($ssh.Source), not Windows' own (C:\Windows\System32\OpenSSH). Its agent is not Windows' ssh-agent service; if a login is refused, put C:\Windows\System32\OpenSSH first on your PATH"
        }
        $svc = Get-Service ssh-agent -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') {
            Die "Windows' ssh-agent service is $($svc.Status.ToString().ToLowerInvariant()). In a PowerShell run as administrator: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent. Then, as yourself: ssh-add $UserHome\.ssh\id_ed25519 (your key), and run this again"
        }
    }
    $r = Invoke-Captured 'ssh-add' @('-l')
    if ($r.Code -ne 0) {
        Die "your ssh agent holds no key: ssh-add yours (ssh-add $UserHome\.ssh\id_ed25519), then run this again. The pod's git uses it through the forwarded agent, so POLAR_DEV_SSH_KEY alone is not enough"
    }
}

function Get-PubKey {
    if ($env:POLAR_DEV_SSH_KEY) { return (Get-Content -Raw $env:POLAR_DEV_SSH_KEY).Trim() }
    $r = Invoke-Captured 'ssh-add' @('-L')
    $first = @(Lines $r.Out)
    if ($r.Code -ne 0 -or $first.Count -eq 0 -or $first[0] -like 'The agent has no identities*') {
        Die 'no key in your ssh agent (ssh-add one, or set POLAR_DEV_SSH_KEY to a public key file)'
    }
    return $first[0]
}

# ---- The manifests --------------------------------------------------------------

# The kustomization this user's pod is made from: the base in infra/dev-pod, and what is theirs; the manifests, as text.
function Get-Manifests([string]$image, [string]$arch) {
    if (-not (Test-Path -LiteralPath $SopsKey)) { Die "no key for sops at $SopsKey (set POLAR_DEV_SOPS_KEY)" }
    $key = Get-PubKey
    $class = $env:POLAR_DEV_STORAGE_CLASS
    if (-not $class) {
        # A claim's class cannot change once it is bound: the claims that exist keep theirs.
        $r = K @('get', 'pvc', "polar-dev-nix-$U", '-o', 'jsonpath={.spec.storageClassName}')
        if ($r.Code -eq 0) { $class = $r.Out.Trim() }
    }
    # Beside the base, since kustomize takes a base only by a relative path; removed when done.
    $d = Join-Path $Here "infra\.dev-pod-$U"
    if (Test-Path $d) { Remove-Item -Recurse -Force $d }
    New-Item -ItemType Directory -Path $d | Out-Null
    try {
        # The sops key goes in by a relative name: a Windows path's drive letter is not one kustomize reads.
        Copy-Item -LiteralPath $SopsKey -Destination (Join-Path $d 'sops-key')
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$key`n"))
        $i = $image.LastIndexOf(':')
        $imgName = $image.Substring(0, $i); $imgTag = $image.Substring($i + 1)
        Write-Lf (Join-Path $d 'namespace.yaml') "apiVersion: v1`nkind: Namespace`nmetadata: { name: $NS }`n"
        $pvcPatch = ''
        if ($class) {
            $pvcPatch = @"
  - target: { kind: PersistentVolumeClaim }
    patch: '[{"op": "add", "path": "/spec/storageClassName", "value": "$class"}]'

"@
        }
        $k = @"
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: $NS
nameSuffix: -$U
resources: [namespace.yaml, ../dev-pod]
images: [{ name: polar-dev, newName: $imgName, newTag: $imgTag }]
secretGenerator:
  - { name: polar-dev-ssh, literals: ["authorized_keys_b64=$b64"] }
  - { name: polar-dev-sops, files: ["key=sops-key"] }
patches:
  - target: { kind: ClusterRoleBinding }
    patch: '[{"op": "replace", "path": "/subjects/0", "value": {"kind": "ServiceAccount", "name": "polar-dev-$U", "namespace": "$NS"}}]'
$pvcPatch  - patch: |
      apiVersion: apps/v1
      kind: Deployment
      metadata: { name: polar-dev }
      spec:
        template:
          spec:
            nodeSelector: { kubernetes.io/arch: $arch }
            securityContext: { fsGroup: $Gid }
            initContainers:
              - name: seed
                env: [{ name: CREATE_UID, value: "$Uid" }, { name: CREATE_GID, value: "$Gid" }]
            containers:
              - name: dev
                env: [{ name: CREATE_USER, value: "$U" }, { name: CREATE_UID, value: "$Uid" }, { name: CREATE_GID, value: "$Gid" }]
                volumeMounts:
                  - { name: state, mountPath: $RemoteHome/.local/share/atuin, subPath: atuin }
                  - { name: state, mountPath: $RemoteHome/.config/polar-admin, subPath: polar-admin }
                  - { name: state, mountPath: $RemoteHome/.config/polar-deploy, subPath: polar-deploy }
                  - { name: state, mountPath: $RemoteHome/.cache, subPath: cache }
                  # The pod's SSH host keys live here, so they are the same after a restart and ssh keeps trusting them.
                  - { name: state, mountPath: $RemoteHome/.ssh, subPath: ssh }
"@
        Write-Lf (Join-Path $d 'kustomization.yaml') $k
        $r = Invoke-Captured 'kubectl' @('kustomize', '--load-restrictor', 'LoadRestrictionsNone', $d)
        if ($r.Code -ne 0) { Die "kubectl kustomize failed: $($r.Err.Trim())" }
        return $r.Out
    } finally {
        Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
    }
}

# ---- Why a login is refused -------------------------------------------------------
# A shorter form of bin/polar-dev's: the cause of the last refusal in what ssh -v (or git through it, or the pod's
# dropbear) said, and the hint for it.

function Get-SshCause([string]$text) {
    $c = 'unknown'
    foreach ($l in (Lines $text)) {
        if ($l -match 'no matching host key type found|No matching algo hostkey') { $c = 'hostkey' }
        if ($l -match 'no matching cipher found|No matching algo enc') { $c = 'cipher' }
        if ($l -match 'no matching key exchange method found|No matching algo kex') { $c = 'kex' }
        if ($l -match 'no matching MAC found|No matching algo mac') { $c = 'mac' }
        if ($l -match 'Permission denied \(publickey') { $c = 'publickey' }
        if ($l -match 'Connection refused') { $c = 'refused' }
        if ($l -match 'kex_exchange_identification|Connection closed by|Connection reset by') { $c = 'closed' }
        if ($l -match '[Tt]imed out') { $c = 'timeout' }
        if ($l -match 'Authenticated to ') { $c = 'ok' }
    }
    return $c
}

function Get-SshReason([string]$text) {
    $r = ''
    foreach ($l in (Lines $text)) {
        if ($l -match 'no matching .* found|Permission denied|Connection refused|kex_exchange_identification|Connection closed by|Connection reset by|[Tt]imed out') { $r = $l -replace '^debug[0-9]: ', '' }
    }
    return $r
}

function Get-SshOffer([string]$text) {
    $o = ''
    foreach ($l in (Lines $text)) { if ($l -match 'Their offer: (.*)$') { $o = $Matches[1] } }
    return $o
}

function Get-DropbearRefusals {
    $r = K @('logs', "deploy/$Deploy", '-c', 'dev', '--tail=2000')
    @(Lines $r.Out | Where-Object { $_ -match 'No matching algo|Exit before auth|nonexistent user|[Pp]ubkey auth (attempt|bad)|Max auth tries|must be owned by|AUTHORIZED_KEYS_B64 not set' } | Select-Object -Last 5)
}

function Get-ForwardProcesses {
    $pattern = "*port-forward deploy/$Deploy ${Port}:2223*"
    if ($OnWindows) {
        @(Get-CimInstance Win32_Process -Filter "Name = 'kubectl.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like $pattern } | ForEach-Object { $_.ProcessId })
    } else {
        @(Get-Process kubectl -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like $pattern } | ForEach-Object { $_.Id })
    }
}

$PfLog = Join-Path $Temp "polar-dev-$U-ssh.log"

function Show-Diagnosis([string]$probe, [string[]]$refusals) {
    $refusals = @($refusals | Where-Object { $_ })
    $cause = Get-SshCause $probe
    if ($cause -eq 'unknown' -and $refusals.Count -gt 0) { $cause = Get-SshCause $refusals[-1] }
    $alive = @(Get-ForwardProcesses).Count -gt 0
    $last = if (Test-Path $PfLog) { (Get-Content $PfLog -Tail 1) } else { '' }
    if ($alive) { Say "the port-forward to the pod runs$(if ($last) { "; its log ($PfLog) ends: $last" })" }
    else { Say "the port-forward to the pod has stopped$(if ($last) { "; its log ($PfLog) ends: $last" })" }
    $reason = Get-SshReason $probe
    if (-not $reason) { $reason = (@(Lines $probe) | Select-Object -Last 1) }
    Say "ssh -v says: $reason"
    if ($refusals.Count -gt 0) { Say "the pod's log says:"; $refusals | ForEach-Object { Write-Host "  $_" } }
    switch ($cause) {
        { $_ -in 'hostkey', 'cipher', 'kex', 'mac' } {
            $offer = Get-SshOffer $probe
            Say "your ssh accepts no $cause algorithm the pod offers. The pod offers: $(if ($offer) { $offer } else { '(ssh did not say)' })"
            Say "that is your ssh's policy (ssh -G -p $Port 127.0.0.1 shows it). The pod's image may predate the fixes for a strict policy: build one with build-image, or set POLAR_DEV_IMAGE to a newer image, then up again"
        }
        'publickey' {
            $from = if ($env:POLAR_DEV_SSH_KEY) { "POLAR_DEV_SSH_KEY=$env:POLAR_DEV_SSH_KEY" } else { "your agent's first key" }
            Say "the pod refused your key (the pod was given $from). Your agent holds:"
            Lines (Invoke-Captured 'ssh-add' @('-l')).Out | ForEach-Object { Write-Host "  $_" }
            Say "if the pod's key is not among them, ssh-add it, or set POLAR_DEV_SSH_KEY to the public half of one that is; then up again gives the pod that key"
        }
        'ok' { Say "a login that trusts any host key works: the pod's host key is not the one $UserHome\.ssh\polar-dev_known_hosts.* holds for it (ssh -p $Port $U@127.0.0.1 says more)" }
        default {
            if (-not $alive) { Say "the port-forward has stopped: the pod may have been stopped or replaced (kubectl -n $NS get pods); attach starts it again" }
            elseif ($cause -eq 'refused') { Say "the port-forward runs, but nothing answers at 127.0.0.1:${Port}: another program may hold that port; set POLAR_DEV_PORT to a free one" }
            else { Say "the port-forward runs, but the pod's end does not answer: dropbear may not be running in the pod (kubectl -n $NS logs deploy/$Deploy -c dev)" }
        }
    }
    return $cause
}

function Invoke-Probe {
    $r = Invoke-Captured 'ssh' @('-v', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no', '-o', "UserKnownHostsFile=$(if ($OnWindows) { 'NUL' } else { '/dev/null' })", '-p', $Port, "$U@127.0.0.1", 'true')
    return "$($r.Out)`n$($r.Err)"
}

# ---- SSH to the pod ---------------------------------------------------------------

function Test-SshAnswers {
    $o = Get-SshOpts
    (Invoke-Captured 'ssh' ($o + @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', "$U@127.0.0.1", 'true'))).Code -eq 0
}

# Starts the forward to the pod's SSH and waits until a login works. A forward left from before that does not reach the pod
# is replaced. A refusal that waiting does not change is said after a few tries; anything else, when it gives up.
function Start-SshForward {
    if (Test-SshAnswers) { return }
    Get-ForwardProcesses | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
    $sp = @{ FilePath = 'kubectl'; ArgumentList = @('-n', $NS, 'port-forward', "deploy/$Deploy", "${Port}:2223"); RedirectStandardOutput = $PfLog; RedirectStandardError = "$PfLog.err"; PassThru = $true }
    if ($OnWindows) { $sp.WindowStyle = 'Hidden' }
    Start-Process @sp | Out-Null
    for ($n = 1; $n -le 60; $n++) {
        if (Test-SshAnswers) { return }
        if ($n -eq 5) {
            $probe = Invoke-Probe
            if ((Get-SshCause $probe) -in 'hostkey', 'cipher', 'kex', 'mac', 'publickey') {
                Show-Diagnosis $probe (Get-DropbearRefusals) | Out-Null
                Die "the pod's SSH refuses this login (above)"
            }
        }
        Start-Sleep -Seconds 2
    }
    Show-Diagnosis (Invoke-Probe) (Get-DropbearRefusals) | Out-Null
    Die "the pod's SSH does not answer at 127.0.0.1:$Port (kubectl -n $NS logs deploy/$Deploy -c dev; $PfLog)"
}

function Enter-Pod([string[]]$rest) {
    Start-SshForward
    $o = Get-SshOpts
    & ssh @($o + @('-t', "$U@127.0.0.1") + $rest)
    exit $LASTEXITCODE
}

function Invoke-InPod([string]$command) {
    $o = Get-SshOpts
    Invoke-Captured 'ssh' ($o + @("$U@127.0.0.1", $command))
}

# ---- Files in and out of the pod ------------------------------------------------------
# One archive each way: tar (Windows' own, bsdtar) on this side, kubectl cp for the archive, tar in the pod.

function Copy-ToPod([string]$fromDir, [string[]]$names, [string]$toDir, [string[]]$tarFlags) {
    $p = Get-Pod
    if (-not $p) { Die "no dev pod in $NS" }
    $arc = "polar-dev-$U-in.tar"
    $local = Join-Path $Temp $arc
    $r = Invoke-Captured 'tar' (@('-C', $fromDir, '-cf', $local) + $names)
    if ($r.Code -ne 0) { Die "tar could not pack $($names -join ', ') from ${fromDir}: $($r.Err.Trim())" }
    # kubectl cp reads C: in a Windows path as a pod's name, so the archive goes by its name alone, from its folder.
    Push-Location $Temp
    try { $r = K @('cp', $arc, "${p}:/tmp/$arc", '-c', 'dev') } finally { Pop-Location }
    Remove-Item -Force $local -ErrorAction SilentlyContinue
    if ($r.Code -ne 0) { Die "kubectl cp into $p failed: $($r.Err.Trim())" }
    $r = K (@('exec', $p, '-c', 'dev', '--', 'tar', '-C', $toDir, '--no-same-owner') + $tarFlags + @('-xf', "/tmp/$arc"))
    K @('exec', $p, '-c', 'dev', '--', 'rm', '-f', "/tmp/$arc") | Out-Null
    if ($r.Code -ne 0) { Die "unpacking into $toDir in $p failed: $($r.Err.Trim())" }
}

function Copy-FromPod([string]$fromDir, [string]$name, [string]$toDir) {
    $p = Get-Pod
    if (-not $p) { Die "no dev pod in $NS" }
    $arc = "polar-dev-$U-out.tar"
    # A socket there (gpg-agent's, in a deployment PKI's GnuPG home) cannot be copied; tar leaves it out, and is told not to say so.
    $r = K @('exec', $p, '-c', 'dev', '--', 'tar', '--warning=no-file-ignored', '-C', $fromDir, '-cf', "/tmp/$arc", $name)
    if ($r.Code -ne 0) { Die "packing $fromDir/$name in $p failed: $($r.Err.Trim())" }
    Push-Location $Temp
    try { $r = K @('cp', "${p}:/tmp/$arc", $arc, '-c', 'dev') } finally { Pop-Location }
    K @('exec', $p, '-c', 'dev', '--', 'rm', '-f', "/tmp/$arc") | Out-Null
    if ($r.Code -ne 0) { Die "kubectl cp out of $p failed: $($r.Err.Trim())" }
    New-Item -ItemType Directory -Force -Path $toDir | Out-Null
    $local = Join-Path $Temp $arc
    $r = Invoke-Captured 'tar' @('-C', $toDir, '-xf', $local)
    Remove-Item -Force $local -ErrorAction SilentlyContinue
    if ($r.Code -ne 0) { Die "tar could not unpack into ${toDir}: $($r.Err.Trim())" }
}

$ConfigDir = Join-Path $UserHome '.config'

function Copy-ConfigIn([string]$name) {
    if (-not (Test-Path (Join-Path $ConfigDir $name))) { return }
    Copy-ToPod $ConfigDir @($name) "$RemoteHome/.config" @()
    K @('exec', "deploy/$Deploy", '-c', 'dev', '--', 'chown', '-R', "${Uid}:${Gid}", "$RemoteHome/.config/$name") | Out-Null
}

function Copy-ConfigOut([string]$name) { Copy-FromPod "$RemoteHome/.config" $name $ConfigDir }

# ---- Your personal sops files ------------------------------------------------------
# Gitignored, so the pod's clone has none. They are encrypted, and the key the pod is given opens them.

function Copy-UserSops {
    $files = @(Get-ChildItem -Path (Join-Path $Here 'infra\targets') -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($f in 'user.sops.yaml', '.user.sops.yaml') {
            if (Test-Path -LiteralPath (Join-Path $_.FullName $f)) { "infra/targets/$($_.Name)/$f" }
        }
    })
    if ($files.Count -eq 0) { Say "no user.sops.yaml under $Here\infra\targets: nothing personal to copy into the pod"; return }
    Say 'your personal sops files go into the pod''s checkout, unless it has its own:'
    $files | ForEach-Object { Write-Host "  $_" }
    Copy-ToPod $Here $files '/workspace' @('--skip-old-files')
    $r = K (@('exec', "deploy/$Deploy", '-c', 'dev', '--', 'chown', "${Uid}:${Gid}") + @($files | ForEach-Object { "/workspace/$_" }))
    if ($r.Code -ne 0) { Die "giving you your personal sops files in the pod failed: $($r.Err.Trim())" }
}

# ---- Your certificate ----------------------------------------------------------------
# Made into a .p12 in the pod (Windows PowerShell has no reader for a PEM key), copied out, and imported into your
# Windows store: the client certificate into Personal, the cluster's CA into Trusted Root (Windows asks you to confirm).

function Install-Cert([string]$user) {
    Copy-ConfigOut 'polar-admin'
    $dir = Join-Path $ConfigDir 'polar-admin'
    foreach ($f in "$user.crt", "$user.key", 'ca.pem') { if (-not (Test-Path (Join-Path $dir $f))) { Die "missing $dir\$f" } }
    $pa = "$RemoteHome/.config/polar-admin"
    $cmd = "if test -r /run/container-env.fish; source /run/container-env.fish; end; openssl pkcs12 -export -inkey $pa/$user.key -in $pa/$user.crt -certfile $pa/ca.pem -name 'Polar $user' -out $pa/$user.p12 -passout pass:changeit"
    $r = K @('exec', "deploy/$Deploy", '-c', 'dev', '--', 'fish', '-c', $cmd)
    if ($r.Code -ne 0) { Die "making the .p12 in the pod failed: $($r.Err.Trim())" }
    Copy-ConfigOut 'polar-admin'
    $p12 = Join-Path $dir "$user.p12"
    if (-not $OnWindows) { Say "made $p12 (password: changeit); importing it is Windows' step"; return }
    Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.FriendlyName -eq "Polar $user" } | Remove-Item
    $pw = ConvertTo-SecureString 'changeit' -AsPlainText -Force
    Import-PfxCertificate -FilePath $p12 -CertStoreLocation Cert:\CurrentUser\My -Password $pw | Out-Null
    Import-Certificate -FilePath (Join-Path $dir 'ca.pem') -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
    Say "imported Polar $user into your Windows certificate store, and the cluster's CA as trusted. Edge and Chrome use them (restart the browser); Firefox keeps its own: import $p12 there (password changeit). Next: bin\polar-dev.ps1 forward"
}

# ---- build-image ---------------------------------------------------------------------

$BuildInPod = @'
set -euo pipefail
say() { echo "polar-dev (in the pod): $*"; }
die() { echo "polar-dev (in the pod): $*" >&2; exit 1; }
trap 'cd /; rm -rf "$scratch"' EXIT
export HOME=/root XDG_CACHE_HOME=/root/.cache
unset XDG_CONFIG_HOME XDG_DATA_HOME
mkdir -p "$XDG_CACHE_HOME"
git clone -q "$scratch/polar.bundle" "$scratch/src" || die "cloning the bundle failed"
cd "$scratch/src"
say "nix build .#packages.$machine-linux.devContainer"
nix build -L -o "$scratch/image" ".#packages.$machine-linux.devContainer" || die "nix build failed (above)"
say "nu infra/cluster-registry.nu up $target: the registry in the cluster, made if it is not there"
nu infra/cluster-registry.nu up "$target" || die "the target's registry in the cluster is not up (above)"
dest=registry.polar-registry.svc:5000/polar-dev:$tag
say "pushing the image to $dest"
skopeo --insecure-policy copy --dest-tls-verify=false "docker-archive:$scratch/image" "docker://$dest" || die "skopeo could not push to $dest (above)"
got=$(skopeo inspect --tls-verify=false --format '{{.Architecture}}' "docker://$dest") || die "skopeo could not read $dest back (above)"
[ "$got" = "$arch" ] || die "$dest is an image for $got, not for $arch"
say "$dest is for $arch"
'@

function Invoke-BuildImage([string]$tag, [string]$target) {
    if (-not $target) { $target = if ($env:POLAR_TARGET) { $env:POLAR_TARGET } else { 'local-minimal' } }
    $scratch = '/tmp/polar-dev-build-image'
    if ((Invoke-Captured 'git' @('-C', $Here, 'rev-parse', '--git-dir')).Code -ne 0) { Die "$Here is not a git checkout: build-image bundles its current commit" }
    $commit = (Invoke-Captured 'git' @('-C', $Here, 'rev-parse', '--short', 'HEAD')).Out.Trim()
    if (-not $tag) { $tag = $commit }
    if ($tag -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$') { Die "$tag cannot be an image's tag (letters, digits, _ . and -, not first; at most 128)" }
    if (-not (Test-Path (Join-Path $Here "infra\targets\$target"))) { Die "there is no target $target in infra/targets: name one, or set POLAR_TARGET" }
    $p = Get-Pod
    if (-not $p -or (K @('rollout', 'status', "deploy/$Deploy", '--timeout=5s')).Code -ne 0) { Die "no dev pod is ready in ${NS}: up first" }
    $machine = (K @('exec', $p, '-c', 'dev', '--', 'uname', '-m')).Out.Trim()
    $arch = switch ($machine) { 'x86_64' { 'amd64' } 'aarch64' { 'arm64' } default { Die "the pod runs on $machine; build-image knows x86_64 and aarch64" } }
    if ((Invoke-Captured 'git' @('-C', $Here, 'status', '--porcelain', '--untracked-files=no')).Out.Trim()) { Say "uncommitted changes are left out: the image is built from $commit" }
    $br = Invoke-Captured 'git' @('-C', $Here, 'symbolic-ref', '--quiet', '--short', 'HEAD')
    $branch = if ($br.Code -eq 0) { $br.Out.Trim() } else { '' }
    $tmp = Join-Path $Temp "polar-dev-$U-build"
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Say "bundling $commit$(if ($branch) { " ($branch)" }) from $Here"
        $refs = @('HEAD'); if ($branch) { $refs += $branch }
        $r = Invoke-Captured 'git' (@('-C', $Here, 'bundle', 'create', (Join-Path $tmp 'polar.bundle')) + $refs)
        if ($r.Code -ne 0) { Die "git bundle create failed in ${Here}: $($r.Err.Trim())" }
        $settings = "scratch='$scratch' machine='$machine' arch='$arch' target='$target' tag='$tag'`n"
        Write-Lf (Join-Path $tmp 'build.bash') ($settings + $BuildInPod)
        Say "copying it into $p ($scratch)"
        K @('exec', $p, '-c', 'dev', '--', 'rm', '-rf', $scratch) | Out-Null
        K @('exec', $p, '-c', 'dev', '--', 'mkdir', '-p', $scratch) | Out-Null
        Copy-ToPod $tmp @('polar.bundle', 'build.bash') $scratch @()
    } finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
    Say "building the dev image for $machine-linux in $p, then pushing it to $target's registry in the cluster (a first build fetches and builds a lot: many minutes)"
    & kubectl -n $NS exec $p -c dev -- fish -c "test -r /run/container-env.fish; and source /run/container-env.fish; exec bash $scratch/build.bash"
    if ($LASTEXITCODE -ne 0) { Die "building or pushing the image in $p failed (above)" }
    $np = (Invoke-Captured 'kubectl' @('-n', 'polar-registry', 'get', 'svc', 'registry', '-o', 'jsonpath={.spec.ports[0].nodePort}')).Out.Trim()
    if (-not $np) { $np = '30500' }
    Say "pushed polar-dev:$tag ($arch) to the registry in the cluster. Put the pod on it with:"
    Write-Host "  `$env:POLAR_DEV_IMAGE = 'localhost:$np/polar-dev:$tag'; bin\polar-dev.ps1 up"
}

# ---- The commands ----------------------------------------------------------------------

function Show-Help {
    $inside = $false
    foreach ($l in (Get-Content -LiteralPath $PSCommandPath)) {
        if ($l -eq '#<help>') { $inside = $true; continue }
        if ($l -eq '#</help>') { break }
        if ($inside) { Write-Host ($l -replace '^# ?', '') }
    }
}

$cmd = if ($args.Count -gt 0) { [string]$args[0] } else { '' }
# @(...) around it: PowerShell gives back a one-element array from an if as the element alone.
$rest = @(if ($args.Count -gt 1) { $args[1..($args.Count - 1)] | ForEach-Object { [string]$_ } })

if (-not $U) { Die "cannot make a name from your user name '$Login'" }

# Every command but the help talks to the cluster: say so plainly when kubectl cannot reach it, before anything is half done.
if ($cmd -in 'up', 'attach', 'cert', 'forward', 'sops', 'sync', 'down', 'build-image') {
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) { Die 'no kubectl on the PATH (Docker Desktop installs one; or winget install Kubernetes.kubectl)' }
    if ((Invoke-Captured 'kubectl' @('version', '--request-timeout=5s')).Code -ne 0) { Die "the cluster does not answer (KUBECONFIG is $(if ($env:KUBECONFIG) { $env:KUBECONFIG } else { 'not set' })): point kubectl at it, then run this again" }
}

switch ($cmd) {
    'up' {
        Test-Agent
        $arch = Get-ClusterArch
        $image = if ($env:POLAR_DEV_IMAGE) { $env:POLAR_DEV_IMAGE } else { "docker.io/daveman1010220/polar-dev:latest-$arch" }
        # The pod's image as it runs now; a change not asked for is confirmed (a script is not asked).
        $cur = K @('get', 'deploy', $Deploy, '-o', 'jsonpath={.spec.template.spec.containers[?(@.name=="dev")].image}')
        $current = if ($cur.Code -eq 0) { $cur.Out.Trim() } else { '' }
        if ($current -and $current -ne $image) {
            if ($env:POLAR_DEV_IMAGE) { Say "the pod runs $current; this applies $image (POLAR_DEV_IMAGE): a changed image re-seeds the Nix store (several minutes)" }
            else {
                Say "the pod runs $current; this applies $image (set POLAR_DEV_IMAGE=$current to keep it)"
                Say 'a changed image re-seeds the Nix store (several minutes)'
                if (-not [Console]::IsInputRedirected) {
                    $answer = Read-Host 'polar-dev: replace it? [y/N]'
                    if ($answer -notmatch '^(y|yes)$') { Die "nothing applied: the pod stays on $current" }
                }
            }
        }
        Say "applying $NS (image $image, on $arch nodes)"
        $manifests = Get-Manifests $image $arch
        $file = Join-Path $Temp "polar-dev-$U.yaml"
        Write-Lf $file $manifests
        $r = Invoke-Captured 'kubectl' @('apply', '-f', $file)
        Remove-Item -Force $file -ErrorAction SilentlyContinue
        Lines $r.Out | ForEach-Object { Write-Host "  $_" }
        if ($r.Code -ne 0) { Die "kubectl apply failed: $($r.Err.Trim())" }
        Say 'waiting for the pod (a first start pulls the image and copies its Nix store to a volume: several minutes)'
        Wait-Ready
        # The state that lives on this machine goes in, unless the pod has its own already (it keeps what it made).
        foreach ($d in 'polar-deploy', 'polar-admin') {
            $ls = K @('exec', "deploy/$Deploy", '-c', 'dev', '--', 'ls', '-A', "$RemoteHome/.config/$d")
            if ($ls.Code -eq 0 -and $ls.Out.Trim()) { Say "~/.config/${d}: the pod has its own, left as it is" }
            elseif (Test-Path (Join-Path $ConfigDir $d)) { Say "copying ~/.config/$d into the pod"; Copy-ConfigIn $d }
        }
        Say "forwarding 127.0.0.1:$Port to the pod's SSH"
        Start-SshForward
        if ((Invoke-InPod 'test -d /workspace/.git').Code -eq 0) { Say '/workspace already has a checkout' }
        else {
            Say "cloning $Repo ($Branch) into /workspace, with your forwarded agent"
            $c = Invoke-InPod "GIT_SSH_COMMAND='ssh -o StrictHostKeyChecking=accept-new' git clone -b '$Branch' '$Repo' /workspace"
            if ($c.Out) { Write-Host $c.Out.TrimEnd() }
            if ($c.Code -ne 0) {
                Write-Host $c.Err.TrimEnd()
                if ((Get-SshCause $c.Err) -eq 'publickey') {
                    Say "the git server knows none of the keys your agent holds; add one to your account there, or set POLAR_DEV_REPO to a remote you can reach. /workspace stays empty until then: up again clones it"
                } else { Say 'the clone failed (above): /workspace stays empty; up again clones it' }
            }
        }
        # Not into a /workspace the clone left empty: git will not clone into one that has something in it.
        if ((Invoke-InPod 'test -d /workspace/.git').Code -eq 0) { Copy-UserSops }
        Say 'logging in (bin\polar-dev.ps1 attach to come back)'
        Enter-Pod @()
    }
    'attach' { Enter-Pod $rest }
    'cert' { Install-Cert $(if ($rest.Count -gt 0) { $rest[0] } else { $U }) }
    'forward' {
        $neo = @{ FilePath = 'kubectl'; ArgumentList = @('-n', 'polar-graph', 'port-forward', 'svc/polar-db-svc', '7473:7473', '7687:7687'); RedirectStandardOutput = (Join-Path $Temp "polar-dev-$U-neo4j.log"); RedirectStandardError = (Join-Path $Temp "polar-dev-$U-neo4j.err.log") }
        $ace = @{ FilePath = 'kubectl'; ArgumentList = @('-n', 'polar', 'port-forward', 'svc/ace-svc', '8050:8050'); RedirectStandardOutput = (Join-Path $Temp "polar-dev-$U-ace.log"); RedirectStandardError = (Join-Path $Temp "polar-dev-$U-ace.err.log") }
        if ($OnWindows) { $neo.WindowStyle = 'Hidden'; $ace.WindowStyle = 'Hidden' }
        Start-Process @neo; Start-Process @ace
        Say "Neo4j at https://localhost:7473, ACE at http://localhost:8050 (logs in $Temp`polar-dev-$U-*.log)"
    }
    'sops' { Copy-UserSops }
    'sync' { Copy-ConfigOut 'polar-deploy'; Copy-ConfigOut 'polar-admin'; Say "copied polar-deploy and polar-admin to $ConfigDir" }
    'down' {
        Copy-ConfigOut 'polar-deploy'; Copy-ConfigOut 'polar-admin'
        Get-ForwardProcesses | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
        if ($rest -contains '--purge') {
            & kubectl delete namespace $NS
            & kubectl delete clusterrolebinding "polar-dev-$U" --ignore-not-found
        } else { & kubectl -n $NS scale "deploy/$Deploy" --replicas=0 }
    }
    'build-image' { Invoke-BuildImage $(if ($rest.Count -gt 0) { $rest[0] } else { '' }) $(if ($rest.Count -gt 1) { $rest[1] } else { '' }) }
    default { Show-Help; exit 1 }
}
