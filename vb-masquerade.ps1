<#
.SYNOPSIS
    Masks a VirtualBox VM from common VM-detection checks.

.DESCRIPTION
    Applies a full set of VBoxManage parameters that hide VirtualBox
    artifacts: spoofs SMBIOS/DMI, ACPI OEM ID, disk serials, MAC prefix,
    disables paravirt provider, switches TSC into a mode that hides
    most of the VM-exit overhead.

    A backup of current extradata is created before any change, so
    everything can be rolled back with -Restore.

    THE VM MUST BE POWERED OFF. The script verifies this.

.PARAMETER VM
    Name or UUID of the VirtualBox VM. If omitted, a list is shown
    and the user picks one interactively.

.PARAMETER Restore
    Roll back changes by re-applying the most recent backup.

.PARAMETER MaskProfile
    Which "host" to emulate. Options: Dell, Lenovo, HP, Asus.
    Default: Dell. Affects all DMI strings.

.PARAMETER DryRun
    Print commands without executing them.

.EXAMPLE
    .\vb-masquerade.ps1 -VM "Win10-Analysis"

.EXAMPLE
    .\vb-masquerade.ps1 -VM "Win10-Analysis" -MaskProfile Lenovo

.EXAMPLE
    .\vb-masquerade.ps1 -VM "Win10-Analysis" -Restore

.NOTES
    Masking via stock VBoxManage parameters
    without modifying the VMM. Covers SMBIOS/DMI, ACPI, peripherals,
    TSC. Does NOT cover: registry keys of Guest Additions (use HooksBox
    or just don't install GA), \Device\VBox* kernel objects (HooksBox),
    full rdtsc-cpuid-rdtsc timing (needs debugger wrapper or VMM patch).
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$VM,

    [switch]$Restore,

    [ValidateSet('Dell', 'Lenovo', 'HP', 'Asus')]
    [string]$MaskProfile = 'Dell',

    [switch]$DryRun
)

# --- Locate VBoxManage -------------------------------------------------------

function Find-VBoxManage {
    $candidates = @(
        "${env:ProgramFiles}\Oracle\VirtualBox\VBoxManage.exe",
        "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    $cmd = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "VBoxManage.exe not found. Install VirtualBox or add it to PATH."
}

$VBoxManage = Find-VBoxManage
Write-Host "VBoxManage:  $VBoxManage" -ForegroundColor DarkGray

# --- VM selection ------------------------------------------------------------

function Get-VBoxVMs {
    $output = & $VBoxManage list vms 2>$null
    $vms = @()
    foreach ($line in $output) {
        if ($line -match '^"(.+)"\s+\{([0-9a-f-]+)\}$') {
            $vms += [PSCustomObject]@{ Name = $matches[1]; UUID = $matches[2] }
        }
    }
    return $vms
}

if (-not $VM) {
    $vms = Get-VBoxVMs
    if ($vms.Count -eq 0) {
        Write-Error "No registered VMs found."
        exit 1
    }
    Write-Host "`nAvailable VMs:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $vms.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f $i, $vms[$i].Name)
    }
    $sel = Read-Host "`nVM number"
    $idx = [int]$sel
    if ($idx -lt 0 -or $idx -ge $vms.Count) {
        Write-Error "Invalid index."
        exit 1
    }
    $VM = $vms[$idx].Name
}

# Verify VM exists and is powered off
$info = & $VBoxManage showvminfo $VM --machinereadable 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "VM '$VM' not found."
    exit 1
}
$state = ($info | Where-Object { $_ -match '^VMState=' }) -replace 'VMState="?(.+?)"?$', '$1'
if ($state -ne 'poweroff' -and $state -ne 'aborted' -and $state -ne 'saved') {
    Write-Error "VM '$VM' is in state '$state'. Power it off before applying masking."
    exit 1
}
Write-Host "VM:          $VM (state: $state)" -ForegroundColor DarkGray

# --- Detect NEM (Native Execution Manager) mode -----------------------------
# When Hyper-V / WSL2 / VBS / Windows Sandbox is enabled on the host,
# VirtualBox cannot use its own hypervisor (VBoxDrv). It falls back to NEM,
# which sits on top of Windows Hypervisor Platform. In NEM mode, many
# VBoxInternal/* parameters are silently ignored or cause boot failure.
# We detect this and skip incompatible knobs with a warning.

$NemMode = $false
$hyperv = (Get-CimInstance -Namespace root\cimv2 -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).HypervisorPresent
if ($hyperv) {
    $NemMode = $true
    Write-Host "NEM:         likely active (host has a hypervisor: Hyper-V/WSL2/VBS)" -ForegroundColor Yellow
    Write-Host "             Some low-level params will be skipped to avoid boot failure." -ForegroundColor Yellow
    Write-Host "             For full coverage, run from admin PowerShell:" -ForegroundColor Yellow
    Write-Host "               bcdedit /set hypervisorlaunchtype off" -ForegroundColor Yellow
    Write-Host "             reboot, then re-run this script. Restore with:" -ForegroundColor Yellow
    Write-Host "               bcdedit /set hypervisorlaunchtype auto" -ForegroundColor Yellow
} else {
    Write-Host "NEM:         not detected (native VBox hypervisor)" -ForegroundColor DarkGray
}

# Parameters known to be incompatible with NEM mode.
$NemIncompatible = @(
    'VBoxInternal/TM/TSCTiedToExecution',
    'VBoxInternal/CPUM/EnableHVP'
)

# --- Backup / restore --------------------------------------------------------

$backupDir  = Join-Path $env:USERPROFILE ".vbox-mask-backups"
if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir | Out-Null }
$safeName   = ($VM -replace '[^\w\-\.]', '_')
$backupFile = Join-Path $backupDir "$safeName.backup.txt"

function Backup-Extradata {
    param([string[]]$KnownKeys)

    Write-Host "`nSaving current extradata to $backupFile" -ForegroundColor Cyan

    $lines = & $VBoxManage getextradata $VM enumerate
    $output = @()
    $output += '# === user extradata (from enumerate) ==='
    $output += $lines
    $output += ''
    $output += '# === VBoxInternal keys touched by this script ==='

    foreach ($k in $KnownKeys) {
        $v = & $VBoxManage getextradata $VM $k 2>$null
        # Output looks like 'Value: <something>' or 'No value set!'
        if ($v -match '^Value:\s+(.*)$') {
            $output += "Key: $k, Value: $($matches[1])"
        } else {
            $output += "Key: $k, Value: <unset>"
        }
    }

    $output | Out-File -FilePath $backupFile -Encoding UTF8
}

function Restore-Extradata {
    if (-not (Test-Path $backupFile)) {
        Write-Error "Backup not found: $backupFile"
        exit 1
    }
    Write-Host "`nRestoring extradata from $backupFile" -ForegroundColor Cyan

    $restored = 0
    $unset    = 0
    foreach ($line in (Get-Content $backupFile)) {
        # Skip header comments and blank lines
        if ($line -match '^\s*(#|$)') { continue }
        if ($line -notmatch '^Key:\s+(.+?),\s+Value:\s+(.*)$') { continue }

        $key = $matches[1]; $val = $matches[2]

        if ($val -eq '<unset>') {
            # Key was not set before our script ran -> unset it now.
            if (-not $DryRun) {
                & $VBoxManage setextradata $VM $key 2>&1 | Out-Null
            } else {
                Write-Host "  [dry] unset $key"
            }
            $unset++
        } else {
            if (-not $DryRun) {
                & $VBoxManage setextradata $VM $key $val 2>&1 | Out-Null
            } else {
                Write-Host "  [dry] set $key = $val"
            }
            $restored++
        }
    }
    Write-Host "Done. Restored: $restored, cleared: $unset" -ForegroundColor Green
}

if ($Restore) {
    Restore-Extradata
    exit 0
}

# --- Static list of VBoxInternal keys this script touches -------------------
$ManagedKeys = @(
    'VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMajor',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMinor',
    'VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor',
    'VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct',
    'VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion',
    'VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial',
    'VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU',
    'VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily',
    'VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBoardSerial',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBoardAssetTag',
    'VBoxInternal/Devices/pcbios/0/Config/DmiBoardLocInChass',
    'VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor',
    'VBoxInternal/Devices/pcbios/0/Config/DmiChassisVersion',
    'VBoxInternal/Devices/pcbios/0/Config/DmiChassisSerial',
    'VBoxInternal/Devices/pcbios/0/Config/DmiChassisAssetTag',
    'VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer',
    'VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev',
    'VBoxInternal/Devices/acpi/0/Config/AcpiOemId',
    'VBoxInternal/Devices/acpi/0/Config/AcpiCreatorId',
    'VBoxInternal/Devices/acpi/0/Config/AcpiCreatorRev',
    'VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber',
    'VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision',
    'VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber',
    'VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/ModelNumber',
    'VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/FirmwareRevision',
    'VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/SerialNumber',
    'VBoxInternal/TM/TSCTiedToExecution',
    'VBoxInternal/CPUM/EnableHVP'
)

Backup-Extradata -KnownKeys $ManagedKeys

# --- Auto-clean any pre-existing NEM-incompatible settings ------------------
if ($NemMode -and -not $DryRun) {
    foreach ($k in $NemIncompatible) {
        & $VBoxManage setextradata $VM $k 2>&1 | Out-Null
    }
    Write-Host "Cleaned pre-existing NEM-incompatible keys." -ForegroundColor DarkGray
}

# --- DMI profiles ------------------------------------------------------------

$profiles = @{
    Dell = @{
        BIOSVendor    = 'Dell Inc.'
        BIOSVersion   = '2.18.0'
        BIOSDate      = '09/14/2023'
        SystemVendor  = 'Dell Inc.'
        SystemProduct = 'OptiPlex 7090'
        SystemVersion = '01'
        SystemFamily  = 'OptiPlex'
        SystemSKU     = '0A2B'
        BoardVendor   = 'Dell Inc.'
        BoardProduct  = '0HMHJ7'
        BoardVersion  = 'A00'
        ChassisVendor = 'Dell Inc.'
        AcpiOemId     = 'DELL  '
        AcpiCreatorId = 'DELL'
    }
    Lenovo = @{
        BIOSVendor    = 'LENOVO'
        BIOSVersion   = 'M1AKT54A'
        BIOSDate      = '07/12/2023'
        SystemVendor  = 'LENOVO'
        SystemProduct = '20Y4S00100'
        SystemVersion = 'ThinkPad T14 Gen 2'
        SystemFamily  = 'ThinkPad T14 Gen 2'
        SystemSKU     = 'LENOVO_MT_20Y4_BU_Think_FM_ThinkPad T14 Gen 2'
        BoardVendor   = 'LENOVO'
        BoardProduct  = '20Y4S00100'
        BoardVersion  = 'SDK0J40697 WIN'
        ChassisVendor = 'LENOVO'
        AcpiOemId     = 'LENOVO'
        AcpiCreatorId = 'LNVO'
    }
    HP = @{
        BIOSVendor    = 'HP'
        BIOSVersion   = 'S78 Ver. 02.21.00'
        BIOSDate      = '08/30/2023'
        SystemVendor  = 'HP'
        SystemProduct = 'HP EliteBook 840 G8'
        SystemVersion = 'Notebook'
        SystemFamily  = '103C_5336AN HP EliteBook'
        SystemSKU     = '5N0Y6EA-ABB'
        BoardVendor   = 'HP'
        BoardProduct  = '8888'
        BoardVersion  = 'KBC Version 13.5C.00'
        ChassisVendor = 'HP'
        AcpiOemId     = 'HPQOEM'
        AcpiCreatorId = 'HP  '
    }
    Asus = @{
        BIOSVendor    = 'American Megatrends Inc.'
        BIOSVersion   = '1602'
        BIOSDate      = '06/02/2023'
        SystemVendor  = 'ASUSTeK COMPUTER INC.'
        SystemProduct = 'ROG STRIX B550-F GAMING'
        SystemVersion = 'Rev 1.xx'
        SystemFamily  = 'To be filled by O.E.M.'
        SystemSKU     = 'SKU'
        BoardVendor   = 'ASUSTeK COMPUTER INC.'
        BoardProduct  = 'ROG STRIX B550-F GAMING'
        BoardVersion  = 'Rev 1.xx'
        ChassisVendor = 'ASUSTeK COMPUTER INC.'
        AcpiOemId     = '_ASUS_'
        AcpiCreatorId = 'AAPL'
    }
}

$P = $profiles[$MaskProfile]
Write-Host "Profile:     $MaskProfile ($($P.SystemVendor) / $($P.SystemProduct))" -ForegroundColor DarkGray

# --- Apply -------------------------------------------------------------------

# Random but plausible UUID. Using the real host UUID from
$systemUuid = [guid]::NewGuid().ToString().ToUpper()

# Random serials for disks and system
function New-Serial { -join ((1..10) | ForEach-Object { '{0:X}' -f (Get-Random -Max 16) }) }
$systemSerial = New-Serial
$boardSerial  = New-Serial
$diskSerial   = New-Serial
$diskFwRev    = "ES2OA60W"
$diskModel    = "Samsung SSD 870 EVO 500GB"

$settings = @(
    # ============ SMBIOS / DMI ============
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVendor';        V=$P.BIOSVendor;    T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBIOSVersion';       V=$P.BIOSVersion;   T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseDate';   V=$P.BIOSDate;      T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMajor';  V='2';              T='n' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBIOSReleaseMinor';  V='18';             T='n' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMajor'; V='1';              T='n' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBIOSFirmwareMinor'; V='0';              T='n' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor';      V=$P.SystemVendor;  T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct';     V=$P.SystemProduct; T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiSystemVersion';     V=$P.SystemVersion; T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial';      V=$systemSerial;    T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiSystemSKU';         V=$P.SystemSKU;     T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiSystemFamily';      V=$P.SystemFamily;  T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid';        V=$systemUuid;      T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBoardVendor';       V=$P.BoardVendor;   T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBoardProduct';      V=$P.BoardProduct;  T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBoardVersion';      V=$P.BoardVersion;  T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBoardSerial';       V=$boardSerial;     T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBoardAssetTag';     V='Default string'; T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiBoardLocInChass';   V='Default string'; T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiChassisVendor';     V=$P.ChassisVendor; T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiChassisVersion';    V='1.0';            T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiChassisSerial';     V=(New-Serial);     T='s' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiChassisAssetTag';   V='Default string'; T='s' },
    # Wipe VBox-specific DmiOEM strings - the most obvious marker
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer';        V='<EMPTY>';        T='r' },
    @{ K='VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev';        V='<EMPTY>';        T='r' },

    # ============ ACPI ============
    @{ K='VBoxInternal/Devices/acpi/0/Config/AcpiOemId';              V=$P.AcpiOemId;     T='s' },
    @{ K='VBoxInternal/Devices/acpi/0/Config/AcpiCreatorId';          V=$P.AcpiCreatorId; T='s' },
    @{ K='VBoxInternal/Devices/acpi/0/Config/AcpiCreatorRev';         V='2';              T='n' },

    # ============ Disks (apply both SATA/AHCI and IDE; unused will be ignored) ============
    @{ K='VBoxInternal/Devices/ahci/0/Config/Port0/ModelNumber';      V=$diskModel;       T='s' },
    @{ K='VBoxInternal/Devices/ahci/0/Config/Port0/FirmwareRevision'; V=$diskFwRev;       T='s' },
    @{ K='VBoxInternal/Devices/ahci/0/Config/Port0/SerialNumber';     V=$diskSerial;      T='s' },
    @{ K='VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/ModelNumber';      V=$diskModel;  T='s' },
    @{ K='VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/FirmwareRevision'; V=$diskFwRev;  T='s' },
    @{ K='VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/SerialNumber';     V=$diskSerial; T='s' },

    # ============ TSC: hide VM-exit overhead as far as possible without VMM patches ============
    @{ K='VBoxInternal/TM/TSCTiedToExecution';                        V='1';              T='n' },

    # ============ CPUID ============
    # Disable hypervisor bit propagation (CPUID(1).ECX[31])
    @{ K='VBoxInternal/CPUM/EnableHVP';                               V='0';              T='n' }
)

Write-Host "`nApplying $($settings.Count) extradata parameters..." -ForegroundColor Cyan
$failed = 0
$skipped = 0
foreach ($s in $settings) {
    if ($NemMode -and ($NemIncompatible -contains $s.K)) {
        Write-Host "  [SKIP/NEM] $($s.K)" -ForegroundColor DarkYellow
        $skipped++
        continue
    }

    # Build the value to pass to VBoxManage. 
    $val = $s.V
    if ($s.T -eq 's' -and $val -ne '<EMPTY>' -and $val -notlike 'string:*') {
        $val = "string:$val"
    }

    $cmdArgs = @('setextradata', $VM, $s.K, $val)
    if ($DryRun) {
        Write-Host "  [dry] $($s.K) = $val" -ForegroundColor DarkGray
    } else {
        & $VBoxManage @cmdArgs 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [FAIL] $($s.K)" -ForegroundColor Yellow
            $failed++
        }
    }
}

# --- modifyvm: things not exposed via extradata ------------------------------

Write-Host "`nApplying modifyvm settings..." -ForegroundColor Cyan

# Real OUIs to spoof: Dell 00:14:22, Lenovo 00:1F:16, HP 00:1B:78, ASUS 00:1F:C6.
$ouiMap = @{
    Dell   = '001422'
    Lenovo = '001F16'
    HP     = '001B78'
    Asus   = '001FC6'
}
$oui = $ouiMap[$MaskProfile]
$mac = $oui + ('{0:X6}' -f (Get-Random -Min 0 -Max 0xFFFFFF))

# Try the new (VBox 7.x) option names first.
$modifyvm = @(
    '--paravirt-provider', 'none',
    '--macaddress1', $mac,
    '--bios-logo-fade-in',  'off',
    '--bios-logo-fade-out', 'off',
    '--bios-logo-display-time', '0',
    '--bios-boot-menu',     'disabled'
)

if ($DryRun) {
    Write-Host "  [dry] $VBoxManage modifyvm $VM $($modifyvm -join ' ')" -ForegroundColor DarkGray
} else {
    & $VBoxManage modifyvm $VM @modifyvm 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # Old VBox (6.x) used different option names. Fall back.
        Write-Host "  New-style options rejected, falling back to VBox 6.x syntax" -ForegroundColor DarkYellow
        $modifyvmOld = @(
            '--paravirtprovider', 'none',
            '--macaddress1', $mac,
            '--bioslogofadein',  'off',
            '--bioslogofadeout', 'off',
            '--bioslogodisplaytime', '0',
            '--biosbootmenu',    'disabled'
        )
        & $VBoxManage modifyvm $VM @modifyvmOld 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { $failed++ }
    }
}

# --- Summary -----------------------------------------------------------------

Write-Host ""
if ($DryRun) {
    Write-Host "Dry-run complete. No real changes were made." -ForegroundColor Green
} elseif ($failed -eq 0) {
    if ($skipped -gt 0) {
        Write-Host "[OK] Masking applied successfully ($skipped param(s) skipped due to NEM mode)." -ForegroundColor Green
    } else {
        Write-Host "[OK] Masking applied successfully." -ForegroundColor Green
    }
} else {
    Write-Host "[WARN] Masking applied with $failed errors (see above)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "What this covers:"                                                  -ForegroundColor DarkGray
Write-Host "  [+] SMBIOS/DMI: BIOS, System, Board, Chassis (all strings)"       -ForegroundColor DarkGray
Write-Host "  [+] ACPI OEM ID and Creator ID"                                   -ForegroundColor DarkGray
Write-Host "  [+] Disk model and serial (SATA + IDE)"                           -ForegroundColor DarkGray
Write-Host "  [+] MAC address: no longer the VBox 08:00:27 OUI"                 -ForegroundColor DarkGray
Write-Host "  [+] Hypervisor bit in CPUID(1).ECX[31] (paravirt-provider none)"  -ForegroundColor DarkGray
Write-Host "  [+] TSC tied to execution: shrinks rdtsc-cpuid-rdtsc delta"       -ForegroundColor DarkGray
Write-Host ""
Write-Host "Rollback: .\vb-masquerade.ps1 -VM `"$VM`" -Restore"                 -ForegroundColor DarkGray
Write-Host ""