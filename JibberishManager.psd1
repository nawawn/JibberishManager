#
# Module manifest for JibberishManager
#
# Place this file at:
#   JibberishManager\1.0.0\JibberishManager.psd1
#
# alongside:
#   JibberishManager\1.0.0\JibberishManager.psm1
#

@{
    # ── Identity ───────────────────────────────────────────────────────────────
    ModuleVersion     = '1.0.0'
    GUID              = 'a3f7c2d1-84be-4e09-b5f6-1c2d3e4f5a6b'   # uniquely identifies this module
    RootModule        = 'JibberishManager.psm1'

    # ── Authorship ─────────────────────────────────────────────────────────────
    Author            = 'Naw Awn'
    CompanyName       = ''
    Copyright         = ''
    Description       = 'Encrypts and retrieves user data using AES-256 + PBKDF2. No external dependencies.'

    # ── Requirements ──────────────────────────────────────────────────────────
    PowerShellVersion = '5.1'                  # minimum PS version required

    # ── Exported functions ────────────────────────────────────────────────────
    # Explicit list means only these are visible after Import-Module.
    # Nothing else leaks out — internal _helpers stay private.
    FunctionsToExport = @(
        'Initialize-JibberishVault'
        'Save-Jibberish'
        'Get-Jibberish'
        'Remove-Jibberish'
        'Get-JibberishUser'
        'Set-JibberishKey'
        'Get-JibberishKey'
        'Remove-JibberishKey'
        'Test-JibberishKey'
    )

    # Nothing else to export
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    # ── Metadata (optional — shown in Get-Module and PowerShell Gallery) ───────
    PrivateData = @{
        PSData = @{
            Tags         = @('encryption', 'aes', 'credentials')
            ReleaseNotes = 'Initial release.'
        }
    }
}
