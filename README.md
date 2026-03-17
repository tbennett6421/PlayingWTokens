# PlayingWTokens

Educational tools for exploring the Windows access token model — how tokens work, what controls their use, and how impersonation decisions are made by the kernel.

## Building

Requires `mingw-w64` cross-compiler. On macOS:

```
brew install mingw-w64
make
```

Binaries are output to `dist/`.

## Tools

### enum_tokens

Enumerates process tokens on a Windows system and evaluates whether the current process could use each token for impersonation. Displays token type, user identity, integrity level, privileges, and protection status (PPL).

The impersonation verdict is based on the Windows access check rules:

1. If the token's impersonation level is below `SecurityImpersonation`, it's identification-only (can't run code).
2. If the caller holds `SeImpersonatePrivilege`, full impersonation is allowed.
3. Otherwise, impersonation is allowed only if the caller's integrity level ≤ the token's integrity level AND both belong to the same user.

```
Usage: enum_tokens.exe [options] [target]

Target:
  <PID>            Filter by process ID
  <name.exe>       Filter by process name (case-insensitive)

Options:
  -t               Table view (compact one-line-per-process summary)
  -x               Exclude protected and inaccessible processes
  -h, --help       Show this help
```

**Examples:**

```
enum_tokens.exe                Show all process tokens (detailed view)
enum_tokens.exe -t             Table view for quick scanning
enum_tokens.exe -t -x          Table view, skip protected processes
enum_tokens.exe svchost.exe    Show tokens for all svchost instances
enum_tokens.exe 928            Show token for a specific PID
```

**Color coding:**

- Verdict: green = usable, yellow = identification only, red = restricted
- Privileges: cyan + `<<` = interesting privilege enabled, yellow = interesting but disabled

### impersonate

Demonstrates the full token impersonation chain by targeting a specific PID. Bypasses the token object DACL by using `DuplicateHandle` via the target's handle table rather than `OpenProcessToken`.

The chain: `OpenProcess` → `NtQuerySystemInformation` (enumerate handles) → `DuplicateHandle` → `DuplicateTokenEx` → `ImpersonateLoggedOnUser` or `CreateProcessWithTokenW`.

Tokens matching the caller's own identity are automatically skipped.

```
Usage: impersonate.exe <PID> [command]

Modes:
  impersonate.exe <PID>          Demo: impersonate, print identity, revert
  impersonate.exe <PID> <cmd>    Launch <cmd> as the stolen identity

Options:
  -h, --help                     Show this help
```

**Examples:**

```
impersonate.exe 928              Demo impersonation of PID 928
impersonate.exe 928 cmd.exe      Launch a SYSTEM cmd prompt
impersonate.exe 928 calc.exe     Launch calc.exe as SYSTEM
```

## Requirements

- Windows 10+ (uses `ENABLE_VIRTUAL_TERMINAL_PROCESSING` for color, `NtQuerySystemInformation` for handle enumeration)
- `enum_tokens`: Run as Administrator for full visibility. Standard users see only their own processes.
- `impersonate`: Requires `SeDebugPrivilege` (to open other users' processes) and `SeImpersonatePrivilege` (to use the stolen token). Both are present in an elevated admin token.

## Key Concepts

- **SeDebugPrivilege** bypasses DACL checks on process and thread objects, but NOT on token objects.
- **OpenProcessToken** performs its own access check against the token's DACL — SeDebugPrivilege doesn't help.
- The workaround is `DuplicateHandle` with `PROCESS_DUP_HANDLE` — copying an existing handle from the target's handle table bypasses the token DACL entirely.
- Protected Process Light (PPL) processes cannot be opened even with SeDebugPrivilege. The kernel enforces this at a level below the normal access check.
