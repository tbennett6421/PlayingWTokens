# PlayingWTokens

Educational tools for exploring the Windows access token model — how tokens work, what controls their use, and how impersonation decisions are made by the kernel.

## Building

Requires `mingw-w64` cross-compiler. On macOS:

```
brew install mingw-w64
make
```

Binaries are output to `dist/`.

### BOFs (Beacon Object Files)

BOF versions of the tools live in `src/bof/`. Build with:

```
make bof
```

Output: `dist/bof/*.x64.o` and `dist/bof/*.x86.o`. These are raw COFF object files loadable by Cobalt Strike, COFFLoader, Sliver, or any compatible BOF loader.

| BOF | Arguments | Description |
|-----|-----------|-------------|
| `enum_tokens_bof` | `int pid` (0=all) | Enumerate tokens and assess impersonation viability |
| `impersonate_bof` | `int pid`, `z cmd` | Steal token from specific PID, spawn command |
| `bulk_impersonate_bof` | `z user_filter`, `z cmd` | Target user identity across all processes, spawn command |

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

### bulk_impersonate

Targets a specific user identity (by SID, username, or substring) and iterates through all processes running as that user until a token can be stolen and used to launch a command.

Uses a two-strategy approach per process:
1. `OpenProcessToken` with `TOKEN_DUPLICATE` (fast, works when the token DACL allows it)
2. Fallback: `OpenProcess(PROCESS_DUP_HANDLE)` + system handle table scan via `NtQuerySystemInformation` (the SeDebugPrivilege path)

Stops on the first successful spawn.

```
Usage: bulk_impersonate.exe <user_filter> <command>
```

The user filter matches case-insensitively against SID string, `DOMAIN\user`, or bare username.

**Examples:**

```
bulk_impersonate.exe SYSTEM cmd.exe
bulk_impersonate.exe S-1-5-18 whoami.exe
bulk_impersonate.exe "NETWORK SERVICE" cmd.exe
bulk_impersonate.exe Administrator powershell.exe
```

### whoami_privs

Reimplements `whoami /priv` using the Win32 API directly. Displays the current username, process integrity level, and a formatted table of all token privileges with their enabled/disabled state.

```
Usage: whoami_privs.exe
```

### check_high_integrity_primative

Quick check that reports whether the current process is running at high integrity (elevated). Exits 0 on success, 1 on failure — useful as a gate in scripts or toolchains.

```
Usage: check_high_integrity_primative.exe
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
