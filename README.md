# JibberishManager

Secure PowerShell module for storing and retrieving user secrets using salted encryption, split storage, and DPAPI-protected master keys.

**Important Note:** This module is provided as-is and is not a replacement for enterprise-grade secret management systems.

\# JibberishManager — Architecture \& Flow
\## Security Model

> Three separate things are required to decrypt any credential.
> An attacker who obtains any two cannot decrypt anything.

```

┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
│   User-Sugar.json   │   │  User-Jibberish.json │   │  JIBBERISH\_MASTER │
│                     │   │                      │   │                    │
│  UserID             │   │  UserID              │   │  Environment var   │
│  UserName           │   │  Jibberish           │   │  SYSTEM or USER    │
│  Sugar (base64)     │   │  (base64 IV+cipher)  │   │  level             │
│                     │   │                      │   │                    │
│  Public read        │   │  MyVault\\ only      │   │  Never on disk     │
│  No secrets here    │   │  ACL-restricted      │   │  Survives reboot   │
└─────────────────────┘   └─────────────────────┘   └─────────────────────┘
        (1)                        (2)                        (3)
         │                          │                          │
         └──────────────────────────┴──────────────────────────┘
                                    ▼
                          All three required
                          to decrypt anything
```
\---
\## Crypto Chain

```
 Per-user Sugar (32 random bytes)
          │   +   JIBBERISH\_MASTER (UTF-8 bytes)
          ▼

 ┌─────────────────────────────────────────┐
 │  PBKDF2  (Rfc2898DeriveBytes)           │
 │  100,000 iterations                     │
 │  Output: 32 bytes                       │
 └─────────────────────────────────────────┘
          │
          ▼
 256-bit AES key  ◄── unique per user because each Sugar is unique
          │   +   Random 16-byte IV (freshly generated every call)
          ▼
 ┌─────────────────────────────────────────┐
 │  AES-256-CBC encrypt                    │
 │  PKCS7 padding                          │
 └─────────────────────────────────────────┘
          │
          ▼
 base64( \[16-byte IV] ║ \[N-byte ciphertext] )
          │
          ▼
 Stored as Jibberish in User-Jibberish.json
```
\---
\## File Layout

```
<ModuleRoot>\\
│
├── JibberishManager.psm1          Module script
├── JibberishManager.psd1          Module manifest
│
├── en-US\\
│   └── about\_JibberishManager.help.txt
│
├── User-Sugar.json                Public read
│   \[
│     { "UserID": 1, "UserName": "Alice", "Sugar": "<base64>" },
│     { "UserID": 2, "UserName": "Bob",   "Sugar": "<base64>" }
│   ]
│
└── MyVault\\                       ACL-restricted (owner only)
   └── User-Jibberish.json
       \[
         { "UserID": 1, "Jibberish": "<base64 IV+cipher>" },
         { "UserID": 2, "Jibberish": "<base64 IV+cipher>" }
       ]
```
\---

\## Master Key Resolution

```
Get-JibberishKey called
        │
        ▼
 ┌─────────────────────────────────┐
 │  SYSTEM env var                 │  ◄── machine-wide, set by admin
 │  JIBBERISH\_MASTER (Machine)    │      survives reboot
 └─────────────────────────────────┘
        │ not found
        ▼
 ┌─────────────────────────────────┐
 │  USER env var                   │  ◄── current user only
 │  JIBBERISH\_MASTER (User)       │      survives reboot
 └─────────────────────────────────┘
        │ not found
        ▼
 ┌─────────────────────────────────┐
 │  Session variable               │  ◄── current session only
 │  $env:JIBBERISH\_MASTER         │      lost on close
 └─────────────────────────────────┘
        │ not found
        ▼
 throw "Run Set-JibberishKey"

```

\---

\## Save-Jibberish Flow

```
Save-Jibberish -UserName 'Alice' -Data 'P@ssw0rd!'
        │
        ▼
 Assert MyVault exists
        │
        ▼
 Get-JibberishKey  ───────────────────────►  master key
        │
        ▼
 Load User-Sugar.json  ──►  \[UserSugar\[]]
 Load User-Jibberish.json  ──►  \[UserJibberish\[]]
        │
        ▼
 User exists in Sugar?
        │
   ┌────┴────┐
  NO        YES
   │          │
   ▼          ▼
 Generate   Reuse existing
 new Sugar  Sugar + UserID
 new UserID
   │          │
   └────┬─────┘
        │
        ▼
 PBKDF2(master key + Sugar)  ──►  AES-256 key
        │
        ▼
 AES-256-CBC encrypt(Data)  ──►  base64(IV + cipher)
        │
        ▼
 Upsert \[UserJibberish] entry
        │
        ▼
 Save User-Sugar.json
 Save User-Jibberish.json
        │
        ▼
 "Jibberish saved for 'Alice' (UserID 1)"
```
\---

\## Get-Jibberish Flow

```
Get-Jibberish -UserName 'Alice'
        │
        ▼
 Assert MyVault exists
        │
        ▼
 Get-JibberishKey  ───────────────────────►  master key
        │
        ▼
 Load User-Sugar.json  ──►  find Alice  ──►  UserID + Sugar
        │
        ▼
 Load User-Jibberish.json  ──►  find by UserID  ──►  Jibberish blob
        │
        ▼
 Split blob:  \[0..15] = IV  │  \[16..N] = ciphertext
        │
        ▼
 PBKDF2(master key + Sugar)  ──►  AES-256 key
        │
        ▼
 AES-256-CBC decrypt(ciphertext, IV)  ──►  plaintext
        │
        ▼
 Set clipboard  ──►  plaintext in clipboard
        │
        ▼
 Start background job (10 seconds)
        │
        ▼
 Null plaintext from memory
        │
        ▼
 "Copied to clipboard - auto-clears in 10 seconds"
        │   (10 seconds later, background job runs)
        ▼
 Clipboard.Clear()
```
\---

\## MyVault ACL
```
Initialize-JibberishVault
        │
        ▼
 Create MyVault\\ folder (if not exists)
        │
        ▼
 Disable ACL inheritance         ◄── no parent permissions bleed through
        │
        ▼
 Strip all existing access rules
        │
        ▼
 Grant current user:
   Read, Write, Modify
   ListDirectory, CreateFiles, Delete
   ContainerInherit + ObjectInherit  ◄── applies to folder AND all files
        │
        ▼
 Optional: grant -ReadOnlyUser
   Read, ListDirectory only
        │
        ▼
 Print verified ACL to console
```
\---
\## PowerShell Classes

```powershell
class UserSugar {
   \[int]   $UserID       # int — numeric comparison and sort
   \[string]$UserName
   \[string]$Sugar        # base64-encoded 32-byte random salt
}

class UserJibberish {
   \[int]   $UserID       # int — matches UserSugar.UserID
   \[string]$Jibberish    # base64-encoded IV + ciphertext
}
```
> Strongly typed classes ensure StrictMode -Version Latest never throws
> a PropertyNotFound error — every property is guaranteed to exist.
\---

\## Function Reference
| Function                   | Purpose                                         |
|----------------------------|-------------------------------------------------|
| `Initialize-JibberishVault`| Create MyVault folder and lock ACL              |
| `Set-JibberishKey`         | Store master key in env var (SYSTEM or USER)    |
| `Get-JibberishKey`         | Resolve master key from env var                 |
| `Remove-JibberishKey`      | Delete master key from env var                  |
| `Test-JibberishKey`        | Returns $true if master key is accessible       |
| `Save-Jibberish`           | Encrypt and store a user credential             |
| `Get-Jibberish`            | Decrypt to clipboard, auto-clear after 10s      |
| `Remove-Jibberish`         | Remove a user from both JSON files              |
| `Get-JibberishUser`        | List all users (UserID + UserName only)         |
\---
\## First-Time Setup Sequence
```
1\.  Import-Module JibberishManager
2\.  Initialize-JibberishVault
        └──► Creates MyVault\\, locks ACL to current user
3\.  Set-JibberishKey
        └──► Stores JIBBERISH\_MASTER in SYSTEM or USER env var
4\.  Save-Jibberish -UserName 'Alice' -Data 'P@ssw0rd!'
     Save-Jibberish -UserName 'Bob'   -Data 'Hunter2!'
        └──► Encrypts and stores credentials for each user
5\.  Get-JibberishUser
        └──► Lists registered users (no sensitive data shown)
6\.  Get-Jibberish -UserName 'Alice'
        └──► Decrypts to clipboard, clears after 10 seconds
```
