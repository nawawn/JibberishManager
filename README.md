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

&#x20; Per-user Sugar (32 random bytes)

&#x20;          │

&#x20;          │   +   JIBBERISH\_MASTER (UTF-8 bytes)

&#x20;          │

&#x20;          ▼

&#x20; ┌─────────────────────────────────────────┐

&#x20; │  PBKDF2  (Rfc2898DeriveBytes)           │

&#x20; │  100,000 iterations                     │

&#x20; │  Output: 32 bytes                       │

&#x20; └─────────────────────────────────────────┘

&#x20;          │

&#x20;          ▼

&#x20; 256-bit AES key  ◄── unique per user because each Sugar is unique

&#x20;          │

&#x20;          │   +   Random 16-byte IV (freshly generated every call)

&#x20;          │

&#x20;          ▼

&#x20; ┌─────────────────────────────────────────┐

&#x20; │  AES-256-CBC encrypt                    │

&#x20; │  PKCS7 padding                          │

&#x20; └─────────────────────────────────────────┘

&#x20;          │

&#x20;          ▼

&#x20; base64( \[16-byte IV] ║ \[N-byte ciphertext] )

&#x20;          │

&#x20;          ▼

&#x20; Stored as Jibberish in User-Jibberish.json

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

&#x20;   └── User-Jibberish.json

&#x20;       \[

&#x20;         { "UserID": 1, "Jibberish": "<base64 IV+cipher>" },

&#x20;         { "UserID": 2, "Jibberish": "<base64 IV+cipher>" }

&#x20;       ]

```



\---



\## Master Key Resolution



```

Get-JibberishKey called

&#x20;        │

&#x20;        ▼

&#x20; ┌─────────────────────────────────┐

&#x20; │  SYSTEM env var                 │  ◄── machine-wide, set by admin

&#x20; │  JIBBERISH\_MASTER (Machine)     │      survives reboot

&#x20; └─────────────────────────────────┘

&#x20;        │ not found

&#x20;        ▼

&#x20; ┌─────────────────────────────────┐

&#x20; │  USER env var                   │  ◄── current user only

&#x20; │  JIBBERISH\_MASTER (User)        │      survives reboot

&#x20; └─────────────────────────────────┘

&#x20;        │ not found

&#x20;        ▼

&#x20; ┌─────────────────────────────────┐

&#x20; │  Session variable               │  ◄── current session only

&#x20; │  $env:JIBBERISH\_MASTER          │      lost on close

&#x20; └─────────────────────────────────┘

&#x20;        │ not found

&#x20;        ▼

&#x20; throw "Run Set-JibberishKey"

```



\---



\## Save-Jibberish Flow



```

Save-Jibberish -UserName 'Alice' -Data 'P@ssw0rd!'

&#x20;        │

&#x20;        ▼

&#x20; Assert MyVault exists

&#x20;        │

&#x20;        ▼

&#x20; Get-JibberishKey  ──────────────────────────────────►  master key

&#x20;        │

&#x20;        ▼

&#x20; Load User-Sugar.json  ──►  \[UserSugar\[]]

&#x20; Load User-Jibberish.json  ──►  \[UserJibberish\[]]

&#x20;        │

&#x20;        ▼

&#x20; User exists in Sugar?

&#x20;        │

&#x20;   ┌────┴────┐

&#x20;  NO        YES

&#x20;   │          │

&#x20;   ▼          ▼

&#x20; Generate   Reuse existing

&#x20; new Sugar  Sugar + UserID

&#x20; new UserID

&#x20;   │          │

&#x20;   └────┬─────┘

&#x20;        │

&#x20;        ▼

&#x20; PBKDF2(master key + Sugar)  ──►  AES-256 key

&#x20;        │

&#x20;        ▼

&#x20; AES-256-CBC encrypt(Data)  ──►  base64(IV + cipher)

&#x20;        │

&#x20;        ▼

&#x20; Upsert \[UserJibberish] entry

&#x20;        │

&#x20;        ▼

&#x20; Save User-Sugar.json

&#x20; Save User-Jibberish.json

&#x20;        │

&#x20;        ▼

&#x20; "Jibberish saved for 'Alice' (UserID 1)"

```



\---



\## Get-Jibberish Flow



```

Get-Jibberish -UserName 'Alice'

&#x20;        │

&#x20;        ▼

&#x20; Assert MyVault exists

&#x20;        │

&#x20;        ▼

&#x20; Get-JibberishKey  ──────────────────────────────────►  master key

&#x20;        │

&#x20;        ▼

&#x20; Load User-Sugar.json  ──►  find Alice  ──►  UserID + Sugar

&#x20;        │

&#x20;        ▼

&#x20; Load User-Jibberish.json  ──►  find by UserID  ──►  Jibberish blob

&#x20;        │

&#x20;        ▼

&#x20; Split blob:  \[0..15] = IV  │  \[16..N] = ciphertext

&#x20;        │

&#x20;        ▼

&#x20; PBKDF2(master key + Sugar)  ──►  AES-256 key

&#x20;        │

&#x20;        ▼

&#x20; AES-256-CBC decrypt(ciphertext, IV)  ──►  plaintext

&#x20;        │

&#x20;        ▼

&#x20; Set clipboard  ──►  plaintext in clipboard

&#x20;        │

&#x20;        ▼

&#x20; Start background job (10 seconds)

&#x20;        │

&#x20;        ▼

&#x20; Null plaintext from memory

&#x20;        │

&#x20;        ▼

&#x20; "Copied to clipboard - auto-clears in 10 seconds"

&#x20;        │

&#x20;        │   (10 seconds later, background job runs)

&#x20;        ▼

&#x20; Clipboard.Clear()

```



\---



\## MyVault ACL



```

Initialize-JibberishVault

&#x20;        │

&#x20;        ▼

&#x20; Create MyVault\\ folder (if not exists)

&#x20;        │

&#x20;        ▼

&#x20; Disable ACL inheritance         ◄── no parent permissions bleed through

&#x20;        │

&#x20;        ▼

&#x20; Strip all existing access rules

&#x20;        │

&#x20;        ▼

&#x20; Grant current user:

&#x20;   Read, Write, Modify

&#x20;   ListDirectory, CreateFiles, Delete

&#x20;   ContainerInherit + ObjectInherit  ◄── applies to folder AND all files

&#x20;        │

&#x20;        ▼

&#x20; Optional: grant -ReadOnlyUser

&#x20;   Read, ListDirectory only

&#x20;        │

&#x20;        ▼

&#x20; Print verified ACL to console

```



\---



\## PowerShell Classes



```powershell

class UserSugar {

&#x20;   \[int]   $UserID       # int — numeric comparison and sort

&#x20;   \[string]$UserName

&#x20;   \[string]$Sugar        # base64-encoded 32-byte random salt

}



class UserJibberish {

&#x20;   \[int]   $UserID       # int — matches UserSugar.UserID

&#x20;   \[string]$Jibberish    # base64-encoded IV + ciphertext

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

&#x20;        └──► Creates MyVault\\, locks ACL to current user



3\.  Set-JibberishKey

&#x20;        └──► Stores JIBBERISH\_MASTER in SYSTEM or USER env var



4\.  Save-Jibberish -UserName 'Alice' -Data 'P@ssw0rd!'

&#x20;   Save-Jibberish -UserName 'Bob'   -Data 'Hunter2!'

&#x20;        └──► Encrypts and stores credentials for each user



5\.  Get-JibberishUser

&#x20;        └──► Lists registered users (no sensitive data shown)



6\.  Get-Jibberish -UserName 'Alice'

&#x20;        └──► Decrypts to clipboard, clears after 10 seconds

```



