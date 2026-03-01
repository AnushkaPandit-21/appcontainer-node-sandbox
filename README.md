# gsoc-poc-appcontainer

**GSoC 2026 Proof-of-Concept — Native Windows AppContainer Sandbox for Gemini CLI**

This is the architectural scaffold for the native Windows sandbox driver proposed
under GSoC 2026 idea #8: *Native Windows Sandbox using AppContainer*.

The project demonstrates the full integration structure — TypeScript public API,
native addon interface, Win32 API call sequences, and build configuration — without
yet implementing the C++ function bodies (those are fully commented with the exact
Win32 sequences to implement).

---

## What this is

Gemini CLI currently has two sandbox drivers:

| Driver | Platform | How it works |
|---|---|---|
| `sandbox-exec` (macOS Seatbelt) | macOS only | Shell wrapper that sets a policy profile then exec's the target process |
| `docker` / `podman` | All platforms | Spawns a container image; requires Docker Desktop or Podman installed |

**The problem on Windows:** There is no native sandbox. `GEMINI_SANDBOX=true` on
Windows requires Docker Desktop — a 500 MB external dependency. The native
Windows equivalent is **AppContainer**, an OS-level security primitive available
since Windows 8 that provides process-level isolation via capability-based
access control and Low integrity level enforcement.

This project implements the third driver:

| Driver | Platform | How it works |
|---|---|---|
| `appcontainer` (this project) | Windows 8+ | Native Win32 API: creates an AppContainer profile, sets filesystem ACLs via `SetNamedSecurityInfo`, then spawns `node.exe` via `CreateProcess` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` |

---

## Architecture

```
gemini-cli (TypeScript)
  │
  └── packages/cli/src/config/sandboxConfig.ts
        getSandboxCommand()
          if (os.platform() === 'win32') return 'appcontainer'   ← NEW
          │
          ▼
      packages/cli/src/utils/sandbox.ts
        start_appcontainer_sandbox()                              ← NEW
          │
          ▼
      packages/windows-sandbox/src/index.ts      (this project)
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
        spawnInContainer()  → InitializeProcThreadAttributeList()
                              UpdateProcThreadAttribute(SECURITY_CAPABILITIES)
                              CreateProcess()
        waitForProcess()    → WaitForSingleObject() + GetExitCodeProcess()
        deleteProfile()     → DeleteAppContainerProfile()
```

---

## Win32 API sequence (CreateProcess inside AppContainer)

This is the core of the implementation. The sequence below is what
`spawnInContainer()` in `native/appcontainer.cc` will execute:

```c
// 1. Create the container profile (once per session)
PSID pSid;
HRESULT hr = CreateAppContainerProfile(
    L"gemini-cli-<session-id>",   // unique name
    L"Gemini CLI Sandbox",        // display name
    L"Gemini CLI Sandbox",        // description
    pCapabilities,                // capability SID array (or NULL for max isolation)
    dwCapabilityCount,
    &pSid                         // out: AppContainer SID
);

// 2. Grant filesystem access to the project directory
EXPLICIT_ACCESS ea = {};
ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
ea.grfAccessMode        = GRANT_ACCESS;
ea.grfInheritance       = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
ea.Trustee.ptstrName    = (LPWSTR)pSid;
PACL pNewDacl;
SetEntriesInAcl(1, &ea, pOldDacl, &pNewDacl);
SetNamedSecurityInfo(targetDir, SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);

// 3. Set up SECURITY_CAPABILITIES for CreateProcess
SECURITY_CAPABILITIES sc = {
    .AppContainerSid = pSid,
    .Capabilities    = pCapabilities,
    .CapabilityCount = dwCapabilityCount,
};

// 4. Build PROC_THREAD_ATTRIBUTE_LIST
SIZE_T size = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &size);
LPPROC_THREAD_ATTRIBUTE_LIST attrList = HeapAlloc(GetProcessHeap(), 0, size);
InitializeProcThreadAttributeList(attrList, 1, 0, &size);
UpdateProcThreadAttribute(attrList, 0,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    &sc, sizeof(sc), NULL, NULL);

// 5. Spawn node.exe inside the AppContainer
STARTUPINFOEXW siex = {};
siex.StartupInfo.cb = sizeof(siex);
siex.lpAttributeList = attrList;
PROCESS_INFORMATION pi = {};
CreateProcessW(
    L"C:\\Program Files\\nodejs\\node.exe",
    cmdLine,          // "node.exe <nodeArgs> <cliArgs>"
    NULL, NULL,
    TRUE,             // inherit stdio handles
    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
    pEnvBlock,        // KEY=VALUE\0KEY=VALUE\0\0
    targetDir,        // working directory
    (LPSTARTUPINFOW)&siex,
    &pi
);

// 6. Wait and clean up
WaitForSingleObject(pi.hProcess, INFINITE);
DWORD exitCode;
GetExitCodeProcess(pi.hProcess, &exitCode);
CloseHandle(pi.hProcess);
DeleteAppContainerProfile(L"gemini-cli-<session-id>");
```

---

## Network isolation (proxied profile)

For the proxied sandbox profile (equivalent to macOS `*-proxied` Seatbelt profiles),
network access is restricted via **Windows Filtering Platform (WFP)**:

```c
// Open WFP engine
HANDLE hEngine;
FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

// Add a block-all filter for this AppContainer SID
FWPM_FILTER0 blockFilter = {};
blockFilter.layerKey  = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
blockFilter.action.type = FWP_ACTION_BLOCK;
// Add AppContainer SID condition matching pSid

// Add a permit filter for the proxy endpoint only (127.0.0.1:8877)
FWPM_FILTER0 allowFilter = {};
allowFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
allowFilter.action.type = FWP_ACTION_PERMIT;
allowFilter.weight.type = FWP_UINT8;
allowFilter.weight.uint8 = 15;  // higher weight = evaluated first
// Add remoteIP + remotePort conditions
```

---

## Parity with macOS Seatbelt

| Seatbelt Feature | AppContainer Equivalent |
|---|---|
| `(deny file-write*)` | Default: AppContainer SID has no ACL on host paths |
| `(allow file-write* (subpath TARGET_DIR))` | `SetNamedSecurityInfo` grants write on `targetDir` |
| `(allow file-write* (subpath TMP_DIR))` | Grant write on `os.tmpdir()` |
| `(allow network-outbound)` — open profile | `InternetClient` capability SID |
| `(deny network-outbound)` + proxy only — proxied profile | No capability SIDs + WFP block-all + WFP allow `localhost:8877` |
| `(allow network-inbound (local ip "localhost:9229"))` | WFP allow inbound on loopback:9229 |
| `(allow default)` vs `(deny default)` | Not directly applicable — AppContainer is always deny-by-default for paths not explicitly ACL'd |
| `(subpath INCLUDE_DIR_0..4)` | Additional `SetNamedSecurityInfo` calls for each include dir |
| Registry isolation | Automatic — AppContainer gets a per-instance registry hive |
| Process isolation (Low integrity) | Automatic — AppContainer runs at Low integrity level |

---

## File structure

```
gsoc-poc-appcontainer/
├── package.json              — Node.js package with node-gyp build scripts
├── binding.gyp               — node-gyp build: Win32 only, links userenv.lib + Fwpuclnt.lib
├── tsconfig.json             — TypeScript config
├── src/
│   ├── types.ts              — All TypeScript types and interfaces
│   │                           (AppContainerConfig, AppContainerHandle, RunOptions, ...)
│   ├── sandbox-windows.ts    — TypeScript wrapper: loads addon, implements
│   │                           createSandbox / runInSandbox / destroySandbox
│   └── index.ts              — Public API + buildConfig() helper
└── native/
    ├── appcontainer.h        — C++ declarations and Win32 include chain
    └── appcontainer.cc       — C++ Node-API functions (scaffolded with TODO comments)
                                showing exact Win32 API sequences to implement
```

---

## Build requirements

- Windows 10/11 (Windows 8+ for AppContainer APIs)
- Visual Studio 2022 with "Desktop development with C++" workload
  (provides MSVC compiler and Windows SDK)
- Node.js 20+
- `npm install -g node-gyp`
- Windows SDK 10.0.19041+ (for `userenv.h`, `fwpmu.h`)

```powershell
npm install
npm run build:native    # compiles appcontainer.node via MSVC + node-gyp
npm run build:ts        # compiles TypeScript → dist/
```

---

## How this fits into the GSoC proposal

This proof-of-concept demonstrates:

1. **Understanding of the existing architecture** — the TypeScript API surface
   mirrors exactly what `sandbox.ts` expects at its dispatch layer
2. **Knowledge of the Win32 API chain** — every function call is documented with
   the exact Win32 sequence in the TODO comments
3. **Correct build configuration** — `binding.gyp` links the right Windows libs
   (`userenv.lib` for AppContainer, `Fwpuclnt.lib` for WFP) and sets the correct
   minimum Windows version (`_WIN32_WINNT=0x0602`)
4. **Type safety** — the TypeScript types enforce correct usage at the
   integration boundary
5. **Parity mapping** — every macOS Seatbelt restriction has a documented
   AppContainer/WFP equivalent

The full GSoC project would implement the `TODO` bodies in `appcontainer.cc`,
integrate this package into `packages/windows-sandbox/` in the gemini-cli monorepo,
add the `win32` detection branch in `sandboxConfig.ts`, and write the security audit.
