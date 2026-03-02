/**
 * wfp_rules.cc
 *
 * WFP network isolation for AppContainer processes.
 *
 * Design:
 *   – g_wfpEngines  maps engineHandleId (uint32) → HANDLE (WFP engine)
 *   – g_wfpFilters  maps filterHandleId (uint32) → UINT64 (WFP filter id)
 *
 * WFP filter strategy for "proxied" profile:
 *   1. Low-weight block filter: matches AppContainer SID → blocks all outbound
 *   2. High-weight allow filter: matches SID + remoteIp + remotePort → permits
 *
 * Note: FwpmEngineOpen0 and FwpmFilterAdd0 require administrator privileges.
 */

#include "wfp_rules.h"
#include <map>
#include <string>

// ---------------------------------------------------------------------------
// Handle stores
// ---------------------------------------------------------------------------

static std::map<uint32_t, HANDLE>  g_wfpEngines;
static std::map<uint32_t, UINT64>  g_wfpFilters;
static uint32_t g_nextEngineId = 1;
static uint32_t g_nextFilterId = 1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::wstring utf8ToWide_wfp(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
  std::wstring r(n - 1, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &r[0], n);
  return r;
}

// Parse "a.b.c.d" into a uint32 in host byte order.
// WFP FWPM_CONDITION_IP_REMOTE_ADDRESS uses host byte order for FWP_UINT32.
static bool parseIpv4(const std::string& ipStr, UINT32* out) {
  unsigned a, b, c, d;
  if (sscanf_s(ipStr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
  if (a > 255 || b > 255 || c > 255 || d > 255) return false;
  *out = (a << 24) | (b << 16) | (c << 8) | d;
  return true;
}

// ---------------------------------------------------------------------------
// WfpOpenEngine
// JS: openFilterEngine() → engineHandleId
// ---------------------------------------------------------------------------

Napi::Value WfpOpenEngine(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  HANDLE hEngine = nullptr;
  DWORD err = FwpmEngineOpen0(
    NULL,                 // local machine
    RPC_C_AUTHN_WINNT,    // Windows authentication
    NULL,                 // current user credentials
    NULL,                 // default session
    &hEngine
  );

  if (err != ERROR_SUCCESS) {
    char msg[128];
    if (err == ERROR_ACCESS_DENIED || err == 5) {
      sprintf_s(msg, "FwpmEngineOpen0 failed: access denied (run as Administrator, error %lu)", err);
    } else {
      sprintf_s(msg, "FwpmEngineOpen0 failed: error %lu", err);
    }
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t id = g_nextEngineId++;
  g_wfpEngines[id] = hEngine;
  return Napi::Number::New(env, id);
}

// ---------------------------------------------------------------------------
// WfpAddBlockFilter
// JS: addBlockOutboundFilter(engineHandleId, sidString) → filterHandleId
//
// Adds a low-weight block filter on FWPM_LAYER_ALE_AUTH_CONNECT_V4 that
// matches all outbound IPv4 connections from the given AppContainer SID.
// ---------------------------------------------------------------------------

Napi::Value WfpAddBlockFilter(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsString()) {
    Napi::TypeError::New(env, "addBlockOutboundFilter(engineHandleId, sidString)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t engineId = info[0].As<Napi::Number>().Uint32Value();
  auto it = g_wfpEngines.find(engineId);
  if (it == g_wfpEngines.end()) {
    Napi::Error::New(env, "Invalid engine handle ID").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  HANDLE hEngine = it->second;

  std::wstring sidStr = utf8ToWide_wfp(info[1].As<Napi::String>().Utf8Value());

  // Convert the AppContainer SID string to a PSID.
  PSID pSid = nullptr;
  if (!ConvertStringSidToSidW(sidStr.c_str(), &pSid)) {
    char msg[128];
    sprintf_s(msg, "ConvertStringSidToSidW failed: error %lu", GetLastError());
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Single condition: match on the AppContainer (package) SID.
  FWPM_FILTER_CONDITION0 cond = {};
  cond.fieldKey               = FWPM_CONDITION_ALE_PACKAGE_ID;
  cond.matchType              = FWP_MATCH_EQUAL;
  cond.conditionValue.type    = FWP_SID;
  cond.conditionValue.sid     = reinterpret_cast<SID*>(pSid);

  // Block filter with low weight — evaluated last, acts as default-deny.
  FWPM_FILTER0 filter         = {};
  filter.layerKey             = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  filter.action.type          = FWP_ACTION_BLOCK;
  filter.numFilterConditions  = 1;
  filter.filterCondition      = &cond;
  filter.weight.type          = FWP_UINT8;
  filter.weight.uint8         = 1;   // low weight → allow filters override this

  UINT64 wfpFilterId = 0;
  DWORD err = FwpmFilterAdd0(hEngine, &filter, NULL, &wfpFilterId);
  LocalFree(pSid);

  if (err != ERROR_SUCCESS) {
    char msg[128];
    sprintf_s(msg, "FwpmFilterAdd0 (block) failed: error %lu", err);
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t handleId = g_nextFilterId++;
  g_wfpFilters[handleId] = wfpFilterId;
  return Napi::Number::New(env, handleId);
}

// ---------------------------------------------------------------------------
// WfpAddAllowFilter
// JS: addAllowFilter(engineHandleId, sidString, remoteIp, remotePort) → filterHandleId
//
// Adds a high-weight permit filter that allows outbound connections from the
// AppContainer SID to a specific ip:port. Evaluated before the block filter.
// ---------------------------------------------------------------------------

Napi::Value WfpAddAllowFilter(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 4 ||
      !info[0].IsNumber() || !info[1].IsString() ||
      !info[2].IsString() || !info[3].IsNumber()) {
    Napi::TypeError::New(env, "addAllowFilter(engineHandleId, sidString, remoteIp, remotePort)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t engineId = info[0].As<Napi::Number>().Uint32Value();
  auto it = g_wfpEngines.find(engineId);
  if (it == g_wfpEngines.end()) {
    Napi::Error::New(env, "Invalid engine handle ID").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  HANDLE hEngine = it->second;

  std::wstring sidStr   = utf8ToWide_wfp(info[1].As<Napi::String>().Utf8Value());
  std::string  remoteIp = info[2].As<Napi::String>().Utf8Value();
  uint32_t     port     = info[3].As<Napi::Number>().Uint32Value();

  PSID pSid = nullptr;
  if (!ConvertStringSidToSidW(sidStr.c_str(), &pSid)) {
    char msg[128];
    sprintf_s(msg, "ConvertStringSidToSidW failed: error %lu", GetLastError());
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  UINT32 ipHostOrder = 0;
  if (!parseIpv4(remoteIp, &ipHostOrder)) {
    LocalFree(pSid);
    Napi::Error::New(env, "Invalid IPv4 address").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Three conditions: AppContainer SID + remote IP + remote port.
  FWPM_FILTER_CONDITION0 conds[3] = {};

  // Condition 0: match AppContainer SID.
  conds[0].fieldKey              = FWPM_CONDITION_ALE_PACKAGE_ID;
  conds[0].matchType             = FWP_MATCH_EQUAL;
  conds[0].conditionValue.type   = FWP_SID;
  conds[0].conditionValue.sid    = reinterpret_cast<SID*>(pSid);

  // Condition 1: match remote IPv4 address (host byte order).
  conds[1].fieldKey              = FWPM_CONDITION_IP_REMOTE_ADDRESS;
  conds[1].matchType             = FWP_MATCH_EQUAL;
  conds[1].conditionValue.type   = FWP_UINT32;
  conds[1].conditionValue.uint32 = ipHostOrder;

  // Condition 2: match remote port (host byte order).
  conds[2].fieldKey              = FWPM_CONDITION_IP_REMOTE_PORT;
  conds[2].matchType             = FWP_MATCH_EQUAL;
  conds[2].conditionValue.type   = FWP_UINT16;
  conds[2].conditionValue.uint16 = static_cast<UINT16>(port);

  // Permit filter with high weight — evaluated first, overrides the block filter.
  FWPM_FILTER0 filter        = {};
  filter.layerKey            = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  filter.action.type         = FWP_ACTION_PERMIT;
  filter.numFilterConditions = 3;
  filter.filterCondition     = conds;
  filter.weight.type         = FWP_UINT8;
  filter.weight.uint8        = 15;  // higher weight → evaluated before block filter

  UINT64 wfpFilterId = 0;
  DWORD err = FwpmFilterAdd0(hEngine, &filter, NULL, &wfpFilterId);
  LocalFree(pSid);

  if (err != ERROR_SUCCESS) {
    char msg[128];
    sprintf_s(msg, "FwpmFilterAdd0 (allow) failed: error %lu", err);
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t handleId = g_nextFilterId++;
  g_wfpFilters[handleId] = wfpFilterId;
  return Napi::Number::New(env, handleId);
}

// ---------------------------------------------------------------------------
// WfpRemoveFilter
// JS: removeFilter(engineHandleId, filterHandleId) → void
// ---------------------------------------------------------------------------

Napi::Value WfpRemoveFilter(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) {
    Napi::TypeError::New(env, "removeFilter(engineHandleId, filterHandleId)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t engineId  = info[0].As<Napi::Number>().Uint32Value();
  uint32_t filterId  = info[1].As<Napi::Number>().Uint32Value();

  auto engIt = g_wfpEngines.find(engineId);
  if (engIt == g_wfpEngines.end()) {
    Napi::Error::New(env, "Invalid engine handle ID").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  auto filIt = g_wfpFilters.find(filterId);
  if (filIt == g_wfpFilters.end()) {
    Napi::Error::New(env, "Invalid filter handle ID").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  HANDLE hEngine     = engIt->second;
  UINT64 wfpFilterId = filIt->second;

  DWORD err = FwpmFilterDeleteById0(hEngine, wfpFilterId);
  g_wfpFilters.erase(filIt);

  if (err != ERROR_SUCCESS) {
    char msg[128];
    sprintf_s(msg, "FwpmFilterDeleteById0 failed: error %lu", err);
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  return env.Undefined();
}

// ---------------------------------------------------------------------------
// WfpCloseEngine
// JS: closeFilterEngine(engineHandleId) → void
// ---------------------------------------------------------------------------

Napi::Value WfpCloseEngine(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "closeFilterEngine(engineHandleId)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t engineId = info[0].As<Napi::Number>().Uint32Value();
  auto it = g_wfpEngines.find(engineId);
  if (it == g_wfpEngines.end()) return env.Undefined();

  FwpmEngineClose0(it->second);
  g_wfpEngines.erase(it);
  return env.Undefined();
}

// ---------------------------------------------------------------------------
// RegisterWfpExports — called from appcontainer.cc Init()
// ---------------------------------------------------------------------------

void RegisterWfpExports(Napi::Env env, Napi::Object exports) {
  exports.Set("openFilterEngine",       Napi::Function::New<WfpOpenEngine>(env,    "openFilterEngine"));
  exports.Set("addBlockOutboundFilter", Napi::Function::New<WfpAddBlockFilter>(env, "addBlockOutboundFilter"));
  exports.Set("addAllowFilter",         Napi::Function::New<WfpAddAllowFilter>(env, "addAllowFilter"));
  exports.Set("removeFilter",           Napi::Function::New<WfpRemoveFilter>(env,  "removeFilter"));
  exports.Set("closeFilterEngine",      Napi::Function::New<WfpCloseEngine>(env,   "closeFilterEngine"));
}