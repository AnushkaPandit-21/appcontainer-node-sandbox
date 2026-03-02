/**
 * wfp_rules.h
 *
 * N-API functions for Windows Filtering Platform (WFP) network isolation.
 *
 * These implement the "proxied" sandbox profile equivalent:
 *   – openFilterEngine   → FwpmEngineOpen0
 *   – addBlockOutboundFilter → FwpmFilterAdd0 (block-all for AppContainer SID)
 *   – addAllowFilter     → FwpmFilterAdd0 (permit specific ip:port)
 *   – removeFilter       → FwpmFilterDeleteById0
 *   – closeFilterEngine  → FwpmEngineClose0
 *
 * Requires administrator privileges at runtime.
 * Layer used: FWPM_LAYER_ALE_AUTH_CONNECT_V4 (IPv4 outbound connection events)
 */

#pragma once

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
#define _WIN32_WINNT 0x0602  // Windows 8
#endif

#include <windows.h>
#include <fwpmu.h>      // FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0
#include <fwptypes.h>   // FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWP_VALUE0
#include <sddl.h>       // ConvertStringSidToSidW

#include <napi.h>

// ---------------------------------------------------------------------------
// N-API function declarations
// ---------------------------------------------------------------------------

/** openFilterEngine() → engineHandleId */
Napi::Value WfpOpenEngine(const Napi::CallbackInfo& info);

/** addBlockOutboundFilter(engineHandleId, sidString) → filterHandleId */
Napi::Value WfpAddBlockFilter(const Napi::CallbackInfo& info);

/** addAllowFilter(engineHandleId, sidString, remoteIp, remotePort) → filterHandleId */
Napi::Value WfpAddAllowFilter(const Napi::CallbackInfo& info);

/** removeFilter(engineHandleId, filterHandleId) → void */
Napi::Value WfpRemoveFilter(const Napi::CallbackInfo& info);

/** closeFilterEngine(engineHandleId) → void */
Napi::Value WfpCloseEngine(const Napi::CallbackInfo& info);

/** Registers all WFP exports on the given exports object. */
void RegisterWfpExports(Napi::Env env, Napi::Object exports);
