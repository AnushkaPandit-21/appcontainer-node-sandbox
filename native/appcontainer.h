/**
 * appcontainer.h
 *
 * Declarations for the Gemini CLI Windows AppContainer native addon.
 *
 * Win32 API surface used:
 *   userenv.h  — CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
 *                DeleteAppContainerProfile
 *   sddl.h     — ConvertSidToStringSidW
 *   aclapi.h   — SetEntriesInAcl, SetNamedSecurityInfoW, GetNamedSecurityInfoW
 *   fwpmu.h    — FwpmEngineOpen0, FwpmFilterAdd0 (WFP, future)
 *
 * Windows version requirement: Windows 8 / Server 2012 (NT 6.2) or later.
 */

#pragma once

// ---- Windows headers (must precede all other includes) --------------------
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN8
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT  0x0602   // Windows 8
#endif

#include <windows.h>
#include <userenv.h>    // CreateAppContainerProfile, DeleteAppContainerProfile
#include <sddl.h>       // ConvertSidToStringSidW
#include <aclapi.h>     // SetEntriesInAcl, SetNamedSecurityInfoW

// ---- Node-API header ------------------------------------------------------
#include <napi.h>

// ---------------------------------------------------------------------------
// N-API exported function declarations
// (AppContainerContext is an internal type defined in appcontainer.cc)
// ---------------------------------------------------------------------------

/** createProfile(profileName, displayName, capabilities[]) → {handleId, sid} */
Napi::Value CreateProfile(const Napi::CallbackInfo& info);

/** setFsAcl(handleId, path, permission, recursive) → void */
Napi::Value SetFsAcl(const Napi::CallbackInfo& info);

/** installWfpFilters(handleId, rules[]) → wfpHandleId */
Napi::Value InstallWfpFilters(const Napi::CallbackInfo& info);

/** removeWfpFilters(handleId) → void */
Napi::Value RemoveWfpFilters(const Napi::CallbackInfo& info);

/** spawnInContainer(handleId, executable, args[], env[], cwd, inheritStdio) → processHandleId */
Napi::Value SpawnInContainer(const Napi::CallbackInfo& info);

/** waitForProcess(processHandleId) → exitCode */
Napi::Value WaitForProcess(const Napi::CallbackInfo& info);

/** terminateProcess(processHandleId, exitCode) → void */
Napi::Value TerminateContainerProcess(const Napi::CallbackInfo& info);

/** deleteProfile(handleId) → void */
Napi::Value DeleteProfile(const Napi::CallbackInfo& info);

/** Module init — registers all exported functions. */
Napi::Object Init(Napi::Env env, Napi::Object exports);
