<#
.SYNOPSIS
    Discovery host attivi sulla rete 10.0.0.0/8 con output XML Nmap.
.DESCRIPTION
    Esegue scansioni host-discovery (-sn) su tutte le 256 subnet /16 della
    rete 10.0.0.0/8, con parallelismo controllato tramite Start-Job.
    L'output di ogni subnet viene salvato in formato XML per parsing automatico.
.PARAMETER BatchSize
    Numero massimo di job in esecuzione contemporaneamente (default 8).
.PARAMETER OutputDir
    Directory di output per i file XML (default .\nmap_xml).
.PARAMETER NmapPath
    Percorso dell'eseguibile nmap (default: cerca nel PATH).
.EXAMPLE
    .\nmap-discovery-10net.ps1
.EXAMPLE
    .\nmap-discovery-10net.ps1 -BatchSize 16 -OutputDir C:\scans
#>
param (
    [int]$BatchSize    = 8,
    [string]$OutputDir = ".\nmap_xml",
    [string]$NmapPath  = "nmap"
)

$ErrorActionPreference = "Stop"
$jobPrefix = "disc10"   # prefisso per riconoscere SOLO i nostri job

# --- 1. Verifica che nmap sia disponibile ---
$nmapCmd = Get-Command $NmapPath -ErrorAction SilentlyContinue
if (-not $nmapCmd) {
    Write-Error "nmap non trovato ('$NmapPath'). Installalo o passa -NmapPath <percorso>."
    return
}
$nmapExe = $nmapCmd.Source

# --- 2. Avviso privilegi: su Windows -sn usa raw socket e vuole i diritti admin ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Non sei Amministratore: il discovery -sn potrebbe dare risultati incompleti."
}

# --- 3. Crea la directory e risolvila in percorso ASSOLUTO ---
#     (fondamentale: i Start-Job hanno una working directory diversa,
#      quindi un percorso relativo NON punterebbe dove ti aspetti)
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
$OutputDir = (Resolve-Path $OutputDir).Path

Write-Host "Nmap:       $nmapExe"   -ForegroundColor Cyan
Write-Host "Batch size: $BatchSize" -ForegroundColor Cyan
Write-Host "Output:     $OutputDir" -ForegroundColor Cyan
Write-Host "Avvio discovery XML su 10.0.0.0/8 (256 subnet /16)..." -ForegroundColor Cyan

# --- 4. Blocco eseguito da ogni job ---
$scanBlock = {
    param($id, $outDir, $nmapExe)
    $xmlFile = Join-Path $outDir ("scan_10.{0}.0.0.xml" -f $id)
    # 2>&1: cattura anche stderr, cosi eventuali errori di nmap tornano nel job
    & $nmapExe -sn -n ("10.{0}.0.0/16" -f $id) -oX $xmlFile 2>&1
}

# --- 5. Throttle "rolling": mantiene sempre al massimo $BatchSize job attivi ---
$total = 256

function Drain-FinishedJobs {
    # raccoglie l'output dei job finiti (per far emergere gli errori) e li rimuove
    foreach ($jb in @(Get-Job -Name "$jobPrefix*" | Where-Object State -ne 'Running')) {
        $out = Receive-Job $jb
        if ($jb.State -eq 'Failed') {
            Write-Warning "Job $($jb.Name) FALLITO: $out"
        }
        Remove-Job $jb
    }
}

for ($id = 0; $id -lt $total; $id++) {

    # se ci sono gia' troppi job in esecuzione, aspetta che si liberino
    while (@(Get-Job -Name "$jobPrefix*" | Where-Object State -eq 'Running').Count -ge $BatchSize) {
        Drain-FinishedJobs
        Start-Sleep -Milliseconds 200
    }
    Drain-FinishedJobs

    Start-Job -Name ("{0}_{1}" -f $jobPrefix, $id) `
              -ScriptBlock $scanBlock `
              -ArgumentList $id, $OutputDir, $nmapExe | Out-Null

    Write-Host ("[{0,3}/{1}] avviato scan 10.{2}.0.0/16" -f ($id + 1), $total, $id) `
        -ForegroundColor DarkGray
}

# --- 6. Attendi e raccogli i job rimanenti ---
Write-Host "Attendo il completamento dei job rimanenti..." -ForegroundColor Cyan
Get-Job -Name "$jobPrefix*" | Wait-Job | Out-Null
Drain-FinishedJobs

# --- 7. Riepilogo ---
$xmlCount = @(Get-ChildItem -Path $OutputDir -Filter *.xml).Count
Write-Host "Completato. $xmlCount file XML salvati in $OutputDir" -ForegroundColor Yellow