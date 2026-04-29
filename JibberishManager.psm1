#Requires -Version 5.1
<#
.SYNOPSIS
    JibberishManager — a dependency-free PowerShell module for encrypting
    and retrieving user credentials using AES-256 + PBKDF2.

.DESCRIPTION
    Each user gets a unique random sugar (salt). The AES-256 encryption key
    is derived from (MasterKey + UserSugar) via PBKDF2-SHA1 with 100,000
    iterations, so every user has a unique key even when sharing a master key.

    CLASSES
        UserSugar       — holds UserID, UserName, Sugar (base64 salt)
        UserJibberish   — holds UserID, Jibberish (base64 IV+ciphertext)

    FILE LAYOUT
        <ModuleRoot>\User-Sugar.json        public read, no sensitive data
        <ModuleRoot>\MyVault\               ACL-restricted folder
        <ModuleRoot>\MyVault\User-Jibberish.json   owner-only read/write

    MASTER KEY  — environment variable JIBBERISH_MASTER
        Resolution order (first found wins):
            1. SYSTEM level  machine-wide, requires admin, survives reboot
            2. USER level    current user only, survives reboot

    FIRST-TIME SETUP
        Import-Module JibberishManager
        Initialize-JibberishVault
        Set-JibberishKey
        Save-Jibberish -UserName 'Alice' -Data 'P@ssw0rd!'
        Get-Jibberish  -UserName 'Alice'

.NOTES
    No external module dependencies. Requires PowerShell 5.1 or later.
    Author : Naw.Awn
    Version: 1.0.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Classes ───────────────────────────────────────────────────────────────────
# Defined at the top so they are available to all functions in the module.
# UserID is typed [int] so numeric comparison and sorting work correctly.
# With StrictMode -Version Latest, typed classes guarantee every property
# exists before access — eliminating the PropertyNotFound errors.

class UserSugar {
    [int]   $UserID
    [string]$UserName
    [string]$Sugar

    UserSugar([int]$userID, [string]$userName, [string]$sugar) {
        $this.UserID   = $userID
        $this.UserName = $userName
        $this.Sugar    = $sugar
    }
}

class UserJibberish {
    [int]   $UserID
    [string]$Jibberish

    UserJibberish([int]$userID, [string]$jibberish) {
        $this.UserID    = $userID
        $this.Jibberish = $jibberish
    }
}

# ── Internal constants ────────────────────────────────────────────────────────

$script:EnvVarName        = 'JIBBERISH_MASTER'
$script:PBKDF2Iterations  = 100000
$script:AesKeyBytes       = 32
$script:AesIVBytes        = 16
$script:UserSugarBytes    = 32
$script:ClipboardSeconds  = 10

$script:DefaultSugarFile     = Join-Path $PSScriptRoot 'User-Sugar.json'
$script:DefaultVaultFolder   = Join-Path $PSScriptRoot 'MyVault'
$script:DefaultJibberishFile = Join-Path $script:DefaultVaultFolder 'User-Jibberish.json'

# ── Private: JSON helpers ─────────────────────────────────────────────────────

function _LoadSugar {
<#
.SYNOPSIS
    Reads User-Sugar.json and returns a typed [UserSugar[]] array.
    Returns an empty array if the file does not exist or is empty.
    ConvertFrom-Json returns a bare object for single-entry files —
    @($parsed) normalises both single and multi-entry cases.
#>
    param([string]$Path)

    if (-not (Test-Path $Path)) { return @() }

    $raw = Get-Content -Path $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

    $parsed = $raw | ConvertFrom-Json
    $result = @()
    foreach ($item in @($parsed)) {
        $result += [UserSugar]::new([int]$item.UserID, [string]$item.UserName, [string]$item.Sugar)
    }
    return $result
}

function _LoadJibberish {
<#
.SYNOPSIS
    Reads User-Jibberish.json and returns a typed [UserJibberish[]] array.
    Returns an empty array if the file does not exist or is empty.
#>
    param([string]$Path)

    if (-not (Test-Path $Path)) { return @() }

    $raw = Get-Content -Path $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

    $parsed = $raw | ConvertFrom-Json
    $result = @()
    foreach ($item in @($parsed)) {
        $result += [UserJibberish]::new([int]$item.UserID, [string]$item.Jibberish)
    }
    return $result
}

function _SaveSugar {
<#
.SYNOPSIS
    Serialises a [UserSugar[]] array to disk as a JSON array.
#>
    param([string]$Path, [UserSugar[]]$Data)
    @($Data) | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8 -Force
}

function _SaveJibberish {
<#
.SYNOPSIS
    Serialises a [UserJibberish[]] array to disk as a JSON array.
#>
    param([string]$Path, [UserJibberish[]]$Data)
    @($Data) | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8 -Force
}

function _NextUserID {
<#
.SYNOPSIS
    Returns the next available integer UserID.
#>
    param([UserSugar[]]$SugarEntries)
    if ($SugarEntries.Count -eq 0) { return 1 }
    $max = ($SugarEntries | Measure-Object -Property UserID -Maximum).Maximum
    return [int]$max + 1
}

function _FindSugarByName {
<#
.SYNOPSIS
    Returns the [UserSugar] entry matching UserName, or $null.
#>
    param([UserSugar[]]$SugarEntries, [string]$UserName)
    if ($SugarEntries.Count -eq 0) { return $null }
    foreach ($entry in $SugarEntries) {
        if ($entry.UserName -eq $UserName) { return $entry }
    }
    return $null
}

function _FindJibberishByID {
<#
.SYNOPSIS
    Returns the [UserJibberish] entry matching UserID, or $null.
#>
    param([UserJibberish[]]$JibberishEntries, [int]$UserID)
    if ($JibberishEntries.Count -eq 0) { return $null }
    foreach ($entry in $JibberishEntries) {
        if ($entry.UserID -eq $UserID) { return $entry }
    }
    return $null
}

# ── Private: crypto helpers ───────────────────────────────────────────────────

function _GenerateRandomBytes {
<#
.SYNOPSIS
    Returns a byte array of cryptographically random bytes.
    Uses RNGCryptoServiceProvider which is available on all .NET versions
    supported by PowerShell 5.1.
#>
    param([int]$Count)
    $bytes = New-Object byte[] $Count
    $rng   = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return $bytes
}

function _DeriveAesKey {
<#
.SYNOPSIS
    Derives a 256-bit AES key from a master key and per-user sugar bytes
    using PBKDF2 with 100,000 iterations.
    Uses the 3-argument Rfc2898DeriveBytes constructor which is compatible
    with all .NET versions available under PowerShell 5.1.
#>
    param([string]$MasterKey, [byte[]]$SugarBytes)
    $masterBytes = [System.Text.Encoding]::UTF8.GetBytes($MasterKey)
    $pbkdf2      = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $masterBytes, $SugarBytes, $script:PBKDF2Iterations
    )
    try   { return $pbkdf2.GetBytes($script:AesKeyBytes) }
    finally { $pbkdf2.Dispose() }
}

function _AesEncrypt {
<#
.SYNOPSIS
    Encrypts a plaintext string with AES-256-CBC.
    Generates a fresh random IV on every call so encrypting the same
    plaintext twice always produces different output.
    Returns base64( [16-byte IV] || [N-byte ciphertext] ).
#>
    param([string]$Plaintext, [byte[]]$Key)

    $aes           = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize   = 256
    $aes.BlockSize = 128
    $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key       = $Key
    $aes.GenerateIV()

    $enc = $aes.CreateEncryptor()
    try {
        $plainBytes  = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
        $cipherBytes = $enc.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        $blob        = New-Object byte[] ($script:AesIVBytes + $cipherBytes.Length)
        [Array]::Copy($aes.IV,      0, $blob, 0,                  $script:AesIVBytes)
        [Array]::Copy($cipherBytes, 0, $blob, $script:AesIVBytes, $cipherBytes.Length)
        return [Convert]::ToBase64String($blob)
    }
    finally { $enc.Dispose(); $aes.Dispose() }
}

function _AesDecrypt {
<#
.SYNOPSIS
    Decrypts a base64 AES-256-CBC blob produced by _AesEncrypt.
    Reads the IV from the first 16 bytes of the decoded blob.
#>
    param([string]$CipherBase64, [byte[]]$Key)

    $blob        = [Convert]::FromBase64String($CipherBase64)
    $iv          = $blob[0..($script:AesIVBytes - 1)]
    $cipherBytes = $blob[$script:AesIVBytes..($blob.Length - 1)]

    $aes           = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize   = 256
    $aes.BlockSize = 128
    $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key       = $Key
    $aes.IV        = $iv

    $dec = $aes.CreateDecryptor()
    try {
        $plainBytes = $dec.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
        return [System.Text.Encoding]::UTF8.GetString($plainBytes)
    }
    finally { $dec.Dispose(); $aes.Dispose() }
}

# ── Private: misc helpers ─────────────────────────────────────────────────────

function _IsAdmin {
<#
.SYNOPSIS
    Returns $true if the current session has administrator privileges.
#>
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function _AssertVaultExists {
<#
.SYNOPSIS
    Throws a descriptive error if the MyVault folder does not exist.
#>
    param([string]$VaultFolder)
    if (-not (Test-Path $VaultFolder)) {
        throw "MyVault folder not found at '$VaultFolder'. Run Initialize-JibberishVault first."
    }
}
function _ClearClipboardAfter {
<#
.SYNOPSIS
    Starts a background Process that clears the clipboard after $Seconds.
    The calling shell is not blocked during the wait.
    Start-Job -Scriptblock {} doesn't work as expected.
#>
    param([int]$Seconds)
    Start-Process powershell -WindowStyle Hidden -ArgumentList @(
        "-NoProfile",
        "-STA",
        "-Command", "Start-Sleep -Seconds $Seconds; Set-Clipboard $null"
    )
}

# ── Public: Vault initialisation ─────────────────────────────────────────────

function Initialize-JibberishVault {
<#
.SYNOPSIS
    Creates the MyVault folder and locks its ACL to the current user only.

.DESCRIPTION
    Run once during first-time setup before Save-Jibberish or Get-Jibberish.
    Steps performed:
        1. Creates <ModuleRoot>\MyVault\ if it does not already exist.
        2. Disables ACL inheritance so no parent permissions bleed through.
        3. Strips all existing access rules.
        4. Grants the current user Read, Write, Modify, ListDirectory,
           CreateFiles and Delete on the folder and all contents.
        5. Optionally grants a second account read-only access via -ReadOnlyUser.
        6. Prints the resulting ACL for verification.

    Re-running on an existing vault resets the ACL — useful if permissions drift.

.PARAMETER VaultFolder
    Override the vault path. Defaults to MyVault beside the module.

.PARAMETER ReadOnlyUser
    Optional second account granted read-only access (e.g. DOMAIN\SvcAccount).

.PARAMETER Force
    Suppress the confirmation prompt when re-initialising an existing vault.

.EXAMPLE
    Initialize-JibberishVault

.EXAMPLE
    Initialize-JibberishVault -ReadOnlyUser 'DOMAIN\MySvcAccount'

.EXAMPLE
    Initialize-JibberishVault -Force
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param(
        [string]$VaultFolder  = $script:DefaultVaultFolder,
        [string]$ReadOnlyUser = '',
        [switch]$Force
    )

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    if ((Test-Path $VaultFolder) -and -not $Force) {
        $answer = Read-Host "MyVault already exists at '$VaultFolder'. Re-initialise and reset ACL? (y/N)"
        if ($answer -notmatch '^[Yy]$') {
            Write-Host "Cancelled." -ForegroundColor Yellow
            return
        }
    }

    if (-not (Test-Path $VaultFolder)) {
        if ($PSCmdlet.ShouldProcess($VaultFolder, 'Create MyVault folder')) {
            New-Item -ItemType Directory -Path $VaultFolder -Force | Out-Null
        }
    }

    if ($PSCmdlet.ShouldProcess($VaultFolder, "Lock ACL to '$currentUser'")) {
        $acl = Get-Acl -Path $VaultFolder
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

        $ownerRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser,
            [System.Security.AccessControl.FileSystemRights]'Read,Write,Modify,ListDirectory,CreateFiles,Delete',
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($ownerRule)

        if (-not [string]::IsNullOrWhiteSpace($ReadOnlyUser)) {
            $readRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ReadOnlyUser,
                [System.Security.AccessControl.FileSystemRights]'Read,ListDirectory',
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($readRule)
        }
        Set-Acl -Path $VaultFolder -AclObject $acl
    }

    $verifyAcl = Get-Acl -Path $VaultFolder
    Write-Host ""
    Write-Host "MyVault initialised at:" -ForegroundColor Green
    Write-Host "  $VaultFolder" -ForegroundColor White
    Write-Host ""
    Write-Host "Access rules applied:" -ForegroundColor Green
    $verifyAcl.Access | ForEach-Object {
        Write-Host ("  [{0}]  {1,-30}  {2}" -f $_.AccessControlType, $_.IdentityReference, $_.FileSystemRights)
    }
    Write-Host ""
    Write-Host "Inheritance disabled. Run Set-JibberishKey next if not done already." -ForegroundColor Cyan
}

# ── Public: Master Key management ────────────────────────────────────────────

function Set-JibberishKey {
<#
.SYNOPSIS
    Stores the master key in the JIBBERISH_MASTER environment variable.

.DESCRIPTION
    Attempts SYSTEM level first (machine-wide, requires admin). Falls back to
    USER level automatically if admin rights are unavailable. Use -Level to
    force a specific level.

    If -MasterKey is omitted a cryptographically random 32-byte key is
    generated and displayed once — copy it before the console scrolls.

.PARAMETER MasterKey
    The master key string. Omit to auto-generate a secure random key.

.PARAMETER Level
    Auto (default) | System | User

.EXAMPLE
    Set-JibberishKey

.EXAMPLE
    Set-JibberishKey -MasterKey 'MyStr0ngKey!'

.EXAMPLE
    Set-JibberishKey -MasterKey 'MyStr0ngKey!' -Level User
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$MasterKey,
        [ValidateSet('Auto','System','User')]
        [string]$Level = 'Auto'
    )

    if ([string]::IsNullOrWhiteSpace($MasterKey)) {
        $randBytes = _GenerateRandomBytes -Count 32
        $MasterKey = [Convert]::ToBase64String($randBytes)
        Write-Warning "Generated master key - save this somewhere safe, it will NOT be shown again:"
        Write-Host $MasterKey -ForegroundColor Yellow
    }

    $resolvedLevel = $Level
    if ($Level -eq 'Auto') {
        if (_IsAdmin) { $resolvedLevel = 'System' } else { $resolvedLevel = 'User' }
    }
    if ($resolvedLevel -eq 'System' -and -not (_IsAdmin)) {
        Write-Warning "Admin rights required for SYSTEM level. Falling back to USER level."
        $resolvedLevel = 'User'
    }

    $envTarget = if ($resolvedLevel -eq 'System') { 'Machine' } else { 'User' }

    if ($PSCmdlet.ShouldProcess("$envTarget env var '$($script:EnvVarName)'", 'Store master key')) {
        [System.Environment]::SetEnvironmentVariable($script:EnvVarName, $MasterKey, $envTarget)
        $env:JIBBERISH_MASTER = $MasterKey

        if ($resolvedLevel -eq 'System') {
            Write-Host "Master key stored at SYSTEM level (machine-wide, survives reboot)." -ForegroundColor Green
        }
        else {
            Write-Host "Master key stored at USER level (current user only, survives reboot)." -ForegroundColor Green
        }
    }
}

function Get-JibberishKey {
<#
.SYNOPSIS
    Resolves JIBBERISH_MASTER from the environment.

.DESCRIPTION
    Resolution order:
        1. SYSTEM level environment variable
        2. USER level environment variable
        3. Current session variable
    Throws a descriptive error if none found.

.EXAMPLE
    $key = Get-JibberishKey
#>
    [CmdletBinding()]
    param()

    $key = [System.Environment]::GetEnvironmentVariable($script:EnvVarName, 'Machine')
    if (-not [string]::IsNullOrWhiteSpace($key)) {
        Write-Verbose "Master key resolved from SYSTEM environment variable."
        return $key
    }

    $key = [System.Environment]::GetEnvironmentVariable($script:EnvVarName, 'User')
    if (-not [string]::IsNullOrWhiteSpace($key)) {
        Write-Verbose "Master key resolved from USER environment variable."
        return $key
    }

    $key = $env:JIBBERISH_MASTER
    if (-not [string]::IsNullOrWhiteSpace($key)) {
        Write-Verbose "Master key resolved from current session variable."
        return $key
    }

    throw "Master key not found. Run Set-JibberishKey to configure it."
}

function Remove-JibberishKey {
<#
.SYNOPSIS
    Removes JIBBERISH_MASTER from one or both environment levels.

.PARAMETER Level
    System | User | Both (default)

.EXAMPLE
    Remove-JibberishKey

.EXAMPLE
    Remove-JibberishKey -Level System
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [ValidateSet('System','User','Both')]
        [string]$Level = 'Both'
    )

    $targets = if ($Level -eq 'Both') { @('System','User') } else { @($Level) }

    foreach ($t in $targets) {
        $envTarget = if ($t -eq 'System') { 'Machine' } else { 'User' }
        if ($PSCmdlet.ShouldProcess("$envTarget env var '$($script:EnvVarName)'", 'Remove master key')) {
            try {
                [System.Environment]::SetEnvironmentVariable($script:EnvVarName, $null, $envTarget)
                Write-Verbose "Removed '$($script:EnvVarName)' from $envTarget level."
            }
            catch {
                Write-Warning "Could not remove $envTarget level (may need admin): $_"
            }
        }
    }

    Remove-Item "Env:\$($script:EnvVarName)" -ErrorAction SilentlyContinue
    Write-Host "JIBBERISH_MASTER removed." -ForegroundColor Yellow
}

function Test-JibberishKey {
<#
.SYNOPSIS
    Returns $true if JIBBERISH_MASTER is accessible, $false otherwise.
    Use as a pre-flight check before calling Save-Jibberish or Get-Jibberish.

.EXAMPLE
    if (-not (Test-JibberishKey)) { throw "Master key not configured." }
#>
    [CmdletBinding()]
    param()
    try {
        $key = Get-JibberishKey
        return (-not [string]::IsNullOrWhiteSpace($key))
    }
    catch { return $false }
}

# ── Public: Jibberish management ─────────────────────────────────────────────

function Save-Jibberish {
<#
.SYNOPSIS
    Encrypts data for a user and saves it into the two JSON stores.

.DESCRIPTION
    NEW USER
        Generates a 32-byte random sugar, assigns the next available UserID,
        appends a new [UserSugar] entry to User-Sugar.json and a new
        [UserJibberish] entry to MyVault\User-Jibberish.json.

    EXISTING USER
        Reuses the existing UserID and sugar. Replaces only that user's
        Jibberish entry — all other users are completely untouched.

    CRYPTO CHAIN
        Random sugar  +  MasterKey  ──PBKDF2──►  AES-256 key
        AES-256 key   +  plaintext  ──AES-CBC──►  base64(IV || cipher)

.PARAMETER UserName
    The username to store data for.

.PARAMETER Data
    The plaintext data to encrypt.

.EXAMPLE
    Save-Jibberish -UserName 'Alice' -Data 'P@ssw0rd!'

.EXAMPLE
    Save-Jibberish -UserName 'Alice' -Data 'NewP@ss!'
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Data,
        [string]$SugarFile     = $script:DefaultSugarFile,
        [string]$JibberishFile = $script:DefaultJibberishFile,
        [string]$VaultFolder   = $script:DefaultVaultFolder
    )

    _AssertVaultExists -VaultFolder $VaultFolder

    $masterKey        = Get-JibberishKey
    $sugarEntries     = @(_LoadSugar     -Path $SugarFile)
    $jibberishEntries = @(_LoadJibberish -Path $JibberishFile)
    $existingUser     = _FindSugarByName -SugarEntries $sugarEntries -UserName $UserName

    if ($null -eq $existingUser) {
        $userID   = _NextUserID -SugarEntries $sugarEntries
        $sugarRaw = _GenerateRandomBytes -Count $script:UserSugarBytes
        $sugarB64 = [Convert]::ToBase64String($sugarRaw)
        $sugarEntries += [UserSugar]::new($userID, $UserName, $sugarB64)
        Write-Verbose "New user '$UserName' assigned UserID $userID."
    }
    else {
        $userID   = $existingUser.UserID
        $sugarRaw = [Convert]::FromBase64String($existingUser.Sugar)
        Write-Verbose "Updating jibberish for existing user '$UserName' (UserID $userID)."
    }

    $aesKey    = _DeriveAesKey -MasterKey $masterKey -SugarBytes $sugarRaw
    $encrypted = _AesEncrypt   -Plaintext $Data       -Key $aesKey

    $existingEntry = _FindJibberishByID -JibberishEntries $jibberishEntries -UserID $userID
    if ($null -ne $existingEntry) {
        $jibberishEntries = @($jibberishEntries | ForEach-Object {
            if ($_.UserID -eq $userID) { [UserJibberish]::new($userID, $encrypted) }
            else                       { $_ }
        })
    }
    else {
        $jibberishEntries += [UserJibberish]::new($userID, $encrypted)
    }

    if ($PSCmdlet.ShouldProcess($UserName, 'Save encrypted jibberish')) {
        _SaveSugar     -Path $SugarFile     -Data $sugarEntries
        _SaveJibberish -Path $JibberishFile -Data $jibberishEntries
        Write-Host "Jibberish saved for '$UserName' (UserID $userID). Total users: $($sugarEntries.Count)." -ForegroundColor Green
    }
}

function Get-Jibberish {
<#
.SYNOPSIS
    Decrypts a user's data and copies it to the clipboard for 10 seconds.

.DESCRIPTION
    Looks up the user in User-Sugar.json, fetches their encrypted blob from
    MyVault\User-Jibberish.json by UserID, derives the AES key, decrypts,
    and copies the plaintext to the clipboard. A background job clears the
    clipboard after ClipboardSeconds. The plaintext is never written to disk
    or printed to the console.

.PARAMETER UserName
    The username whose data to retrieve.

.PARAMETER ClipboardSeconds
    Seconds before the clipboard is cleared. Default: 10.

.EXAMPLE
    Get-Jibberish -UserName 'Alice'

.EXAMPLE
    Get-Jibberish -UserName 'Alice' -ClipboardSeconds 30
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserName,
        [string]$SugarFile        = $script:DefaultSugarFile,
        [string]$JibberishFile    = $script:DefaultJibberishFile,
        [string]$VaultFolder      = $script:DefaultVaultFolder,
        [int]   $ClipboardSeconds = $script:ClipboardSeconds
    )

    _AssertVaultExists -VaultFolder $VaultFolder

    $masterKey        = Get-JibberishKey
    $sugarEntries     = @(_LoadSugar     -Path $SugarFile)
    $jibberishEntries = @(_LoadJibberish -Path $JibberishFile)

    $userEntry = _FindSugarByName -SugarEntries $sugarEntries -UserName $UserName
    if ($null -eq $userEntry) {
        throw "User '$UserName' not found in '$SugarFile'. Run Save-Jibberish first."
    }

    $jibberishEntry = _FindJibberishByID -JibberishEntries $jibberishEntries -UserID $userEntry.UserID
    if ($null -eq $jibberishEntry) {
        throw "No jibberish found for '$UserName' (UserID $($userEntry.UserID)) in '$JibberishFile'."
    }

    $sugarRaw  = [Convert]::FromBase64String($userEntry.Sugar)
    $aesKey    = _DeriveAesKey -MasterKey $masterKey -SugarBytes $sugarRaw
    $plaintext = _AesDecrypt   -CipherBase64 $jibberishEntry.Jibberish -Key $aesKey

    Add-Type -AssemblyName PresentationCore
    [System.Windows.Clipboard]::SetText($plaintext)
    _ClearClipboardAfter -Seconds $ClipboardSeconds

    Write-Host "Jibberish for '$UserName' copied to clipboard - auto-clears in $ClipboardSeconds seconds." -ForegroundColor Cyan

    $plaintext = $null
    [System.GC]::Collect()
}

function Remove-Jibberish {
<#
.SYNOPSIS
    Removes a user's entries from both JSON files entirely.

.DESCRIPTION
    Deletes the matching row from User-Sugar.json and
    MyVault\User-Jibberish.json. All other users remain intact.

.PARAMETER UserName
    The username to remove.

.EXAMPLE
    Remove-Jibberish -UserName 'Bob'

.EXAMPLE
    Remove-Jibberish -UserName 'Bob' -Confirm:$false
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][string]$UserName,
        [string]$SugarFile     = $script:DefaultSugarFile,
        [string]$JibberishFile = $script:DefaultJibberishFile
    )

    $sugarEntries     = @(_LoadSugar     -Path $SugarFile)
    $jibberishEntries = @(_LoadJibberish -Path $JibberishFile)

    $userEntry = _FindSugarByName -SugarEntries $sugarEntries -UserName $UserName
    if ($null -eq $userEntry) {
        Write-Warning "User '$UserName' not found - nothing to remove."
        return
    }

    $userID = $userEntry.UserID

    if ($PSCmdlet.ShouldProcess($UserName, "Remove user and jibberish (UserID $userID)")) {
        $sugarEntries     = @($sugarEntries     | Where-Object { $_.UserName -ne $UserName })
        $jibberishEntries = @($jibberishEntries | Where-Object { $_.UserID   -ne $userID   })

        _SaveSugar     -Path $SugarFile     -Data $sugarEntries
        _SaveJibberish -Path $JibberishFile -Data $jibberishEntries
        Write-Host "User '$UserName' (UserID $userID) removed. Remaining users: $($sugarEntries.Count)." -ForegroundColor Yellow
    }
}

function Get-JibberishUser {
<#
.SYNOPSIS
    Lists all registered users. Displays UserID and UserName only.
    No sugar values or encrypted data are ever shown.

.EXAMPLE
    Get-JibberishUser

    UserID UserName
    ------ --------
         1 Alice
         2 Bob
         3 Carol
#>
    [CmdletBinding()]
    param([string]$SugarFile = $script:DefaultSugarFile)

    $entries = @(_LoadSugar -Path $SugarFile)

    if ($entries.Count -eq 0) {
        Write-Host "No users registered yet. Use Save-Jibberish to add users." -ForegroundColor Yellow
        return
    }

    $entries | Select-Object UserID, UserName | Sort-Object UserID | Format-Table -AutoSize
}

# ── Module exports ────────────────────────────────────────────────────────────

Export-ModuleMember -Function @(
    'Initialize-JibberishVault',
    'Save-Jibberish',
    'Get-Jibberish',
    'Remove-Jibberish',
    'Get-JibberishUser',
    'Set-JibberishKey',
    'Get-JibberishKey',
    'Remove-JibberishKey',
    'Test-JibberishKey'
)
