# appcontainer-node-sandbox

**GSoC 2026 Proof-of-Concept — Native Windows AppContainer Sandbox for Gemini CLI**

Working proof-of-concept for [GSoC 2026 idea #8](https://github.com/google-gemini/gemini-cli/wiki/GSoC-2026-Ideas):
*Native Windows Sandbox using AppContainer*. All C++ and TypeScript code is **fully
implemented and tested** on Windows 11.

---

## Test Results (Windows 11)

```
=== AppContainer Sandbox Integration Test ===

[1] Creating AppContainer profile...
    handleId = 1
    SID      = S-1-15-2-...

[2] Granting read+write ACL on test directory...
    ACL applied

[3] Test A — write to C:\Windows\ (isolation should BLOCK this)...
    cmd.exe exit code : 1
    File exists       : false
  PASS  AppContainer blocked write to C:\Windows\

[4] Test B — write to ACL-granted test dir (should SUCCEED)...
    cmd.exe exit code : 0
    File exists       : true
  PASS  AppContainer wrote successfully to ACL-granted directory

=== Results ===
  Passed: 2
  Failed: 0
```

---

## What This Is

Gemini CLI currently has two sandbox drivers:

| Driver | Platform | How it works |
|---|---|---|
| `sandbox-exec` (macOS Seatbelt) | macOS only | Shell wrapper that sets a policy profile then exec's the target |
| `docker` / `podman` | All platforms | Spawns a container image; requires Docker Desktop or Podman |

**The problem on Windows:** `GEMINI_SANDBOX=true` requires Docker Desktop — a 500 MB
external dependency. The native Windows equivalent is **AppContainer**, an OS-level
security primitive (since Windows 8) that provides process isolation via
capability-based access control and Low integrity level enforcement.

This project implements the third driver:

| Driver | Platform | How it works |
|---|---|---|
| `appcontainer` (this) | Windows 8+ | Win32 API: `CreateAppContainerProfile` + `SetNamedSecurityInfo` ACLs + `CreateProcessW` with `SECURITY_CAPABILITIES` + WFP network filters |

---

## Implemented Features

### AppContainer Process Isolation (Complete)
- **Profile management**: `CreateAppContainerProfile` / `DeriveAppContainerSidFromAppContainerName` / `DeleteAppContainerProfile`
- **Filesystem ACLs**: `SetNamedSecurityInfo` + `SetEntriesInAcl` — per-path read/write/readwrite with inheritance flags
- **Process spawning**: `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute(SECURITY_CAPABILITIES)` + `CreateProcessW`
- **Process lifecycle**: `WaitForSingleObject` + `GetExitCodeProcess` + `TerminateProcess`
- **Capability SIDs**: `InternetClient`, `InternetClientServer`, `PrivateNetworkClientServer`

### WFP Network Isolation (Complete)
- **Block-all filter**: `FwpmFilterAdd0` on `FWPM_LAYER_ALE_AUTH_CONNECT_V4` matching AppContainer SID (weight=1)
- **Allow-list filters**: Per-rule permit filters for specific ip:port (weight=15, overrides block)
- **High-level API**: `installWfpFilters(handleId, rules[])` — opens engine, installs block + allows in one call
- **Granular API**: `openFilterEngine`, `addBlockOutboundFilter`, `addAllowFilter`, `removeFilter`, `closeFilterEngine`

### TypeScript Integration Layer (Complete)
- Config builder with `open` / `proxied` network profiles (mirrors Seatbelt profiles)
- Abort signal support (maps to `TerminateProcess`)
- `AppContainerError` with Win32 error codes
- Full type definitions for all config, handle, and result types

---

## Architecture

```
gemini-cli (TypeScript)
  │
  └── sandboxConfig.ts
        getSandboxCommand()
          if (os.platform() === 'win32') return 'appcontainer'   ← hook point
          │
          ▼
      sandbox.ts
        start_appcontainer_sandbox()                              ← hook point
          │
          ▼
      this package → src/index.ts
        buildConfig()         → AppContainerConfig
        createSandbox()       → AppContainerHandle
        runInSandbox()        → SandboxResult
        destroySandbox()      → void
          │
          ▼
      native/appcontainer.node               (C++ Node-API addon)
        createProfile()     → CreateAppContainerProfile()
        setFsAcl()          → SetNamedSecurityInfo() + SetEntriesInAcl()
        installWfpFilters() → FwpmEngineOpen0() + FwpmFilterAdd0()
        spawnInContainer()  → CreateProcessW(SECURITY_CAPABILITIES)
        waitForProcess()    → WaitForSingleObject()
        deleteProfile()     → DeleteAppContainerProfile()
```

---

## Win32 API Sequences

### Process Spawning (appcontainer.cc)

```c
// 1. Create the container profile
PSID pSid;
CreateAppContainerProfile(L"gemini-cli-<session>", ..., &pSid);

// 2. Grant filesystem access via ACL
EXPLICIT_ACCESS ea = { .grfAccessPermissions = GENERIC_READ | GENERIC_WRITE };
ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
ea.Trustee.ptstrName   = (LPWSTR)pSid;
SetEntriesInAcl(1, &ea, pOldDacl, &pNewDacl);
SetNamedSecurityInfo(targetDir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, ...);

// 3. Spawn inside AppContainer
SECURITY_CAPABILITIES sc = { .AppContainerSid = pSid };
InitializeProcThreadAttributeList(attrList, 1, 0, &size);
UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, ...);
CreateProcessW(NULL, cmdLine, ..., EXTENDED_STARTUPINFO_PRESENT, ...);
```

### Network Isolation (wfp_rules.cc)

```c
// Block-all outbound for AppContainer SID (low weight)
FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
FWPM_FILTER0 blockFilter = { .layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                              .action.type = FWP_ACTION_BLOCK, .weight.uint8 = 1 };
FwpmFilterAdd0(hEngine, &blockFilter, NULL, &blockFilterId);

// Allow specific endpoint (high weight — overrides block)
FWPM_FILTER0 allowFilter = { .action.type = FWP_ACTION_PERMIT, .weight.uint8 = 15 };
// Conditions: SID + remoteIP + remotePort
FwpmFilterAdd0(hEngine, &allowFilter, NULL, &allowFilterId);
```

---

## Parity with macOS Seatbelt

| Seatbelt Feature | AppContainer Equivalent | Status |
|---|---|---|
| `(deny file-write*)` | Default: no ACL on host paths | Done |
| `(allow file-write* (subpath X))` | `SetNamedSecurityInfo` grants write on X | Done |
| `(allow file-write* (subpath TMP_DIR))` | Grant write on `os.tmpdir()` | Done |
| `(allow network-outbound)` — open | `InternetClient` capability SID | Done |
| `(deny network-outbound)` + proxy | WFP block-all + allow-list | Done |
| `(allow network-inbound localhost:9229)` | WFP allow for 127.0.0.1:9229 | Done |
| `(subpath INCLUDE_DIR_0..4)` | Additional `SetNamedSecurityInfo` per dir | Done |
| Registry isolation | Automatic (per-instance hive) | Built-in |
| Process isolation (Low IL) | Automatic | Built-in |

---

## File Structure

```
appcontainer-node-sandbox/
├── package.json              — Node.js package with node-gyp build scripts
├── binding.gyp               — Build config: links userenv.lib, Fwpuclnt.lib, Advapi32.lib
├── tsconfig.json             — TypeScript config (ES2022, Node16)
├── src/
│   ├── types.ts              — TypeScript types (AppContainerConfig, Handles, etc.)
│   ├── sandbox-windows.ts    — TS wrapper: createSandbox/runInSandbox/destroySandbox
│   └── index.ts              — Public API + buildConfig() helper
├── native/
│   ├── appcontainer.h        — AppContainer C++ declarations + Win32 includes
│   ├── appcontainer.cc       — AppContainer profile, ACL, process spawning, WFP orchestration
│   ├── wfp_rules.h           — WFP function declarations
│   └── wfp_rules.cc          — WFP engine/filter management
└── test/
    └── run-test.js           — Integration test: isolation + ACL verification
```

---

## Build & Test

**Requirements:**
- Windows 10/11
- Visual Studio 2022 with "Desktop development with C++" workload
- Node.js 20+
- Windows SDK 10.0.19041+

```powershell
npm install
npm run build:native    # compiles appcontainer.node via MSVC + node-gyp
npm run build:ts        # compiles TypeScript → dist/
npm test                # runs integration test
```

---

## Integration Points in Gemini CLI

1. **`sandboxConfig.ts:getSandboxCommand()`** — add `win32 → 'appcontainer'`
2. **`sandbox.ts:start_sandbox()`** — add `appcontainer` dispatch branch
3. **`VALID_SANDBOX_COMMANDS`** — add `'appcontainer'` to the union type

---

## GSoC 2026

- **Idea**: #8 — Native Windows Sandbox using AppContainer
- **Difficulty**: Hard | **Size**: 350 hours | **Area**: Security
- **Mentor**: Gaurav Ghosh
- **Applicant**: Anushka Pandit ([AnushkaPandit-21](https://github.com/AnushkaPandit-21))
