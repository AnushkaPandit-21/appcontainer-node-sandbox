/**
 * appcontainer.cc
 *
 * Native Node-API addon for Windows AppContainer sandboxing.
 * Built with node-gyp; links against userenv.lib, Advapi32.lib, Fwpuclnt.lib.
 *
 * Build:
 *   npm run build:native        (from package root on Windows)
 *   node-gyp configure build    (manual)
 */

#include "appcontainer.h"
#include "wfp_rules.h"
#include <map>
#include <vector>
#include <string>

// ---------------------------------------------------------------------------
// Handle stores
// ---------------------------------------------------------------------------

struct AppContainerContext {
  PSID sid = nullptr;                          // Freed with FreeSid()
  std::wstring profileName;
  std::vector<SID_AND_ATTRIBUTES> capSids;     // Each .Sid freed with LocalFree()
};

static std::map<uint32_t, AppContainerContext> g_handles;
static uint32_t g_nextHandleId = 1;

// Process HANDLE store: maps uint32_t → Win32 HANDLE
static std::map<uint32_t, HANDLE> g_processes;
static uint32_t g_nextProcessId = 1;

// WFP state: tracks the WFP engine and installed filter IDs per sandbox handle.
struct WfpState {
  HANDLE engineHandle = nullptr;
  std::vector<UINT64> filterIds;
};
static std::map<uint32_t, WfpState> g_wfpStates;

static uint32_t storeContext(AppContainerContext&& ctx) {
  uint32_t id = g_nextHandleId++;
  g_handles[id] = std::move(ctx);
  return id;
}

static AppContainerContext* getContext(uint32_t id) {
  auto it = g_handles.find(id);
  return it != g_handles.end() ? &it->second : nullptr;
}

static void removeContext(uint32_t id) {
  g_handles.erase(id);
}

// ---------------------------------------------------------------------------
// String conversion helpers
// ---------------------------------------------------------------------------

static std::wstring utf8ToWide(const std::string& utf8) {
  if (utf8.empty()) return {};
  int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
  std::wstring result(len - 1, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], len);
  return result;
}

static std::string wideToUtf8(const std::wstring& wide) {
  if (wide.empty()) return {};
  int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
  std::string result(len - 1, '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], len, nullptr, nullptr);
  return result;
}

// ---------------------------------------------------------------------------
// Helper: map a capability name to a well-known SID and allocate it.
// Caller must LocalFree() the returned SID.
// ---------------------------------------------------------------------------

static bool getCapabilitySid(const std::string& name, PSID* ppSid) {
  WELL_KNOWN_SID_TYPE sidType;
  if      (name == "internetClient"             || name == "InternetClient")
    sidType = WinCapabilityInternetClientSid;
  else if (name == "internetClientServer"       || name == "InternetClientServer")
    sidType = WinCapabilityInternetClientServerSid;
  else if (name == "privateNetworkClientServer" || name == "PrivateNetworkClientServer")
    sidType = WinCapabilityPrivateNetworkClientServerSid;
  else
    return false;

  DWORD sidSize = SECURITY_MAX_SID_SIZE;
  PSID pSid = LocalAlloc(LPTR, sidSize);
  if (!pSid) return false;

  if (!CreateWellKnownSid(sidType, NULL, pSid, &sidSize)) {
    LocalFree(pSid);
    return false;
  }

  *ppSid = pSid;
  return true;
}

// ---------------------------------------------------------------------------
// CreateProfile
// JS: createProfile(profileName, displayName, capabilities[]) → {handleId, sid}
// ---------------------------------------------------------------------------

Napi::Value CreateProfile(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 3 || !info[0].IsString() || !info[1].IsString() || !info[2].IsArray()) {
    Napi::TypeError::New(env, "createProfile(profileName, displayName, capabilities[])").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  std::wstring profileName = utf8ToWide(info[0].As<Napi::String>().Utf8Value());
  std::wstring displayName = utf8ToWide(info[1].As<Napi::String>().Utf8Value());
  Napi::Array  capArray    = info[2].As<Napi::Array>();

  AppContainerContext ctx;
  ctx.profileName = profileName;

  // Build capability SID array from the capability name strings.
  for (uint32_t i = 0; i < capArray.Length(); i++) {
    std::string capName = capArray.Get(i).As<Napi::String>().Utf8Value();
    PSID capSid = nullptr;
    if (getCapabilitySid(capName, &capSid)) {
      SID_AND_ATTRIBUTES sa = {};
      sa.Sid        = capSid;
      sa.Attributes = SE_GROUP_ENABLED;
      ctx.capSids.push_back(sa);
    }
  }

  // Create the AppContainer profile.
  // If a profile with this name already exists (e.g. from a crashed session),
  // ERROR_ALREADY_EXISTS is returned — recover by deriving the SID directly.
  HRESULT hr = CreateAppContainerProfile(
    profileName.c_str(),
    displayName.c_str(),
    L"Gemini CLI Sandbox",
    ctx.capSids.empty() ? nullptr : ctx.capSids.data(),
    static_cast<DWORD>(ctx.capSids.size()),
    &ctx.sid
  );

  if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
    hr = DeriveAppContainerSidFromAppContainerName(profileName.c_str(), &ctx.sid);
  }

  if (FAILED(hr)) {
    for (auto& sa : ctx.capSids) if (sa.Sid) LocalFree(sa.Sid);
    char msg[128];
    sprintf_s(msg, "CreateAppContainerProfile failed: HRESULT 0x%08X", (unsigned)hr);
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Convert AppContainer SID to its string representation for JS callers.
  LPWSTR pSidStr = nullptr;
  ConvertSidToStringSidW(ctx.sid, &pSidStr);
  std::string sidStr = wideToUtf8(pSidStr);
  LocalFree(pSidStr);

  uint32_t handleId = storeContext(std::move(ctx));

  Napi::Object result = Napi::Object::New(env);
  result.Set("handleId", Napi::Number::New(env, handleId));
  result.Set("sid",      Napi::String::New(env, sidStr));
  return result;
}

// ---------------------------------------------------------------------------
// SetFsAcl
// JS: setFsAcl(handleId, path, permission, recursive) → void
//
// Grants the AppContainer SID access to a filesystem path by merging a new
// EXPLICIT_ACCESS entry into the path's existing DACL via SetNamedSecurityInfo.
// ---------------------------------------------------------------------------

Napi::Value SetFsAcl(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 4) {
    Napi::TypeError::New(env, "setFsAcl(handleId, path, permission, recursive)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t    handleId   = info[0].As<Napi::Number>().Uint32Value();
  std::wstring fsPath    = utf8ToWide(info[1].As<Napi::String>().Utf8Value());
  std::string  permission = info[2].As<Napi::String>().Utf8Value();
  bool         recursive  = info[3].As<Napi::Boolean>().Value();

  AppContainerContext* ctx = getContext(handleId);
  if (!ctx) {
    Napi::Error::New(env, "Invalid handle ID").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  DWORD accessMask;
  if      (permission == "read")      accessMask = GENERIC_READ | GENERIC_EXECUTE;
  else if (permission == "write")     accessMask = GENERIC_WRITE;
  else                                accessMask = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;

  DWORD inheritFlags = recursive
    ? (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
    : NO_INHERITANCE;

  EXPLICIT_ACCESS ea        = {};
  ea.grfAccessPermissions   = accessMask;
  ea.grfAccessMode          = GRANT_ACCESS;
  ea.grfInheritance         = inheritFlags;
  ea.Trustee.TrusteeForm    = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType    = TRUSTEE_IS_WELL_KNOWN_GROUP;
  ea.Trustee.ptstrName      = reinterpret_cast<LPWSTR>(ctx->sid);

  // Read the current DACL on the target path.
  PACL pOldDacl = nullptr;
  PSECURITY_DESCRIPTOR pSd = nullptr;
  GetNamedSecurityInfoW(
    fsPath.c_str(), SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION,
    NULL, NULL, &pOldDacl, NULL, &pSd
  );

  // Merge our entry into the existing DACL.
  PACL pNewDacl = nullptr;
  DWORD err = SetEntriesInAcl(1, &ea, pOldDacl, &pNewDacl);
  if (pSd) LocalFree(pSd);

  if (err != ERROR_SUCCESS) {
    char msg[64]; sprintf_s(msg, "SetEntriesInAcl failed: %lu", err);
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Apply the updated DACL.
  err = SetNamedSecurityInfoW(
    const_cast<LPWSTR>(fsPath.c_str()), SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION,
    NULL, NULL, pNewDacl, NULL
  );
  LocalFree(pNewDacl);

  if (err != ERROR_SUCCESS) {
    char msg[64]; sprintf_s(msg, "SetNamedSecurityInfo failed: %lu", err);
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  return env.Undefined();
}

// ---------------------------------------------------------------------------
// InstallWfpFilters
// JS: installWfpFilters(handleId, rules[]) → wfpHandleId
//
// Opens a WFP engine, installs a block-all outbound filter for the
// AppContainer SID, then adds high-weight allow filters for each rule.
// Requires administrator privileges (WFP engine open will fail otherwise).
// ---------------------------------------------------------------------------

Napi::Value InstallWfpFilters(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsArray()) {
    Napi::TypeError::New(env, "installWfpFilters(handleId, rules[])").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t    handleId = info[0].As<Napi::Number>().Uint32Value();
  Napi::Array rules    = info[1].As<Napi::Array>();

  AppContainerContext* ctx = getContext(handleId);
  if (!ctx) {
    Napi::Error::New(env, "Invalid handle ID").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Open the WFP engine (requires administrator privileges).
  HANDLE hEngine = nullptr;
  DWORD err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &hEngine);
  if (err != ERROR_SUCCESS) {
    char msg[128];
    if (err == ERROR_ACCESS_DENIED) {
      sprintf_s(msg, "WFP requires administrator privileges (error %lu)", err);
    } else {
      sprintf_s(msg, "FwpmEngineOpen0 failed: error %lu", err);
    }
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  WfpState state;
  state.engineHandle = hEngine;

  // ── Block-all outbound filter ──
  // Low weight (1) so that the allow filters below (weight 15) take precedence.
  FWPM_FILTER_CONDITION0 blockCond = {};
  blockCond.fieldKey            = FWPM_CONDITION_ALE_PACKAGE_ID;
  blockCond.matchType           = FWP_MATCH_EQUAL;
  blockCond.conditionValue.type = FWP_SID;
  blockCond.conditionValue.sid  = reinterpret_cast<SID*>(ctx->sid);

  FWPM_FILTER0 blockFilter        = {};
  blockFilter.layerKey             = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  blockFilter.action.type          = FWP_ACTION_BLOCK;
  blockFilter.numFilterConditions  = 1;
  blockFilter.filterCondition      = &blockCond;
  blockFilter.weight.type          = FWP_UINT8;
  blockFilter.weight.uint8         = 1;

  UINT64 blockFilterId = 0;
  err = FwpmFilterAdd0(hEngine, &blockFilter, NULL, &blockFilterId);
  if (err != ERROR_SUCCESS) {
    FwpmEngineClose0(hEngine);
    char msg[128];
    sprintf_s(msg, "FwpmFilterAdd0 (block) failed: error %lu", err);
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }
  state.filterIds.push_back(blockFilterId);

  // ── Allow filters for each rule ──
  // High weight (15) so they override the block-all filter.
  for (uint32_t i = 0; i < rules.Length(); i++) {
    Napi::Object rule = rules.Get(i).As<Napi::Object>();
    std::string remoteIp = rule.Get("remoteIp").As<Napi::String>().Utf8Value();
    uint32_t remotePort  = rule.Get("remotePort").As<Napi::Number>().Uint32Value();

    // Parse IPv4 address to host byte order for WFP.
    unsigned a, b, c, d;
    if (sscanf_s(remoteIp.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
        a > 255 || b > 255 || c > 255 || d > 255) {
      continue; // skip invalid addresses
    }
    UINT32 ipHostOrder = (a << 24) | (b << 16) | (c << 8) | d;

    FWPM_FILTER_CONDITION0 allowConds[3] = {};

    allowConds[0].fieldKey              = FWPM_CONDITION_ALE_PACKAGE_ID;
    allowConds[0].matchType             = FWP_MATCH_EQUAL;
    allowConds[0].conditionValue.type   = FWP_SID;
    allowConds[0].conditionValue.sid    = reinterpret_cast<SID*>(ctx->sid);

    allowConds[1].fieldKey              = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    allowConds[1].matchType             = FWP_MATCH_EQUAL;
    allowConds[1].conditionValue.type   = FWP_UINT32;
    allowConds[1].conditionValue.uint32 = ipHostOrder;

    allowConds[2].fieldKey              = FWPM_CONDITION_IP_REMOTE_PORT;
    allowConds[2].matchType             = FWP_MATCH_EQUAL;
    allowConds[2].conditionValue.type   = FWP_UINT16;
    allowConds[2].conditionValue.uint16 = static_cast<UINT16>(remotePort);

    FWPM_FILTER0 allowFilter        = {};
    allowFilter.layerKey            = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    allowFilter.action.type         = FWP_ACTION_PERMIT;
    allowFilter.numFilterConditions = 3;
    allowFilter.filterCondition     = allowConds;
    allowFilter.weight.type         = FWP_UINT8;
    allowFilter.weight.uint8        = 15;

    UINT64 allowFilterId = 0;
    err = FwpmFilterAdd0(hEngine, &allowFilter, NULL, &allowFilterId);
    if (err == ERROR_SUCCESS) {
      state.filterIds.push_back(allowFilterId);
    }
  }

  g_wfpStates[handleId] = std::move(state);
  return Napi::Number::New(env, handleId);
}

// ---------------------------------------------------------------------------
// RemoveWfpFilters
// JS: removeWfpFilters(handleId) → void
//
// Removes all WFP filters installed by InstallWfpFilters and closes the
// WFP engine. Best-effort — errors are ignored since this is cleanup.
// ---------------------------------------------------------------------------

Napi::Value RemoveWfpFilters(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "removeWfpFilters(handleId)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t handleId = info[0].As<Napi::Number>().Uint32Value();
  auto it = g_wfpStates.find(handleId);
  if (it == g_wfpStates.end()) return env.Undefined();

  WfpState& state = it->second;

  // Remove all installed filters (block + allows).
  for (UINT64 filterId : state.filterIds) {
    FwpmFilterDeleteById0(state.engineHandle, filterId);
  }

  // Close the WFP engine.
  if (state.engineHandle) {
    FwpmEngineClose0(state.engineHandle);
  }

  g_wfpStates.erase(it);
  return env.Undefined();
}

// ---------------------------------------------------------------------------
// SpawnInContainer
// JS: spawnInContainer(handleId, executable, args[], env[], cwd, inheritStdio)
//       → processHandleId
//
// Spawns a process inside the AppContainer using CreateProcessW with
// PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES.
// ---------------------------------------------------------------------------

Napi::Value SpawnInContainer(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 6) {
    Napi::TypeError::New(env, "spawnInContainer(handleId, executable, args[], env[], cwd, inheritStdio)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t     handleId     = info[0].As<Napi::Number>().Uint32Value();
  std::wstring exe          = utf8ToWide(info[1].As<Napi::String>().Utf8Value());
  Napi::Array  args         = info[2].As<Napi::Array>();
  Napi::Array  envArr       = info[3].As<Napi::Array>();
  std::wstring cwd          = utf8ToWide(info[4].As<Napi::String>().Utf8Value());
  bool         inheritStdio = info[5].As<Napi::Boolean>().Value();

  AppContainerContext* ctx = getContext(handleId);
  if (!ctx) {
    Napi::Error::New(env, "Invalid handle ID").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Build the command line: "executable" arg1 arg2 ...
  // CreateProcessW requires a mutable wchar_t buffer.
  std::wstring cmdLine = L"\"" + exe + L"\"";
  for (uint32_t i = 0; i < args.Length(); i++) {
    cmdLine += L" " + utf8ToWide(args.Get(i).As<Napi::String>().Utf8Value());
  }
  std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
  cmdBuf.push_back(L'\0');

  // Build the environment block: KEY=VALUE\0KEY=VALUE\0\0
  // If no env vars supplied, pass NULL so the child inherits the parent's environment.
  std::vector<wchar_t> envBlock;
  bool useCustomEnv = (envArr.Length() > 0);
  if (useCustomEnv) {
    for (uint32_t i = 0; i < envArr.Length(); i++) {
      std::wstring pair = utf8ToWide(envArr.Get(i).As<Napi::String>().Utf8Value());
      envBlock.insert(envBlock.end(), pair.begin(), pair.end());
      envBlock.push_back(L'\0');
    }
    envBlock.push_back(L'\0'); // double-null terminator
  }

  // ── Step 1: Size the PROC_THREAD_ATTRIBUTE_LIST ──
  SIZE_T attrListSize = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);

  LPPROC_THREAD_ATTRIBUTE_LIST attrList =
    reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
      HeapAlloc(GetProcessHeap(), 0, attrListSize)
    );
  if (!attrList) {
    Napi::Error::New(env, "HeapAlloc failed for attribute list").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
    HeapFree(GetProcessHeap(), 0, attrList);
    Napi::Error::New(env, "InitializeProcThreadAttributeList failed").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // ── Step 2: Attach SECURITY_CAPABILITIES ──
  // This is what places the process inside the AppContainer token.
  SECURITY_CAPABILITIES sc    = {};
  sc.AppContainerSid           = ctx->sid;
  sc.Capabilities              = ctx->capSids.empty() ? nullptr : ctx->capSids.data();
  sc.CapabilityCount           = static_cast<DWORD>(ctx->capSids.size());
  sc.Reserved                  = 0;

  if (!UpdateProcThreadAttribute(
        attrList, 0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &sc, sizeof(SECURITY_CAPABILITIES),
        NULL, NULL)) {
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    Napi::Error::New(env, "UpdateProcThreadAttribute failed").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // ── Step 3: STARTUPINFOEXW ──
  STARTUPINFOEXW siex = {};
  siex.StartupInfo.cb = sizeof(siex);
  siex.lpAttributeList = attrList;

  if (inheritStdio) {
    HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    SetHandleInformation(hIn,  HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(hOut, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(hErr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    siex.StartupInfo.hStdInput  = hIn;
    siex.StartupInfo.hStdOutput = hOut;
    siex.StartupInfo.hStdError  = hErr;
    siex.StartupInfo.dwFlags    = STARTF_USESTDHANDLES;
  }

  // ── Step 4: CreateProcessW ──
  PROCESS_INFORMATION pi = {};
  DWORD createFlags = EXTENDED_STARTUPINFO_PRESENT;
  if (useCustomEnv) createFlags |= CREATE_UNICODE_ENVIRONMENT;

  BOOL ok = CreateProcessW(
    NULL,                                              // lpApplicationName (use cmdLine)
    cmdBuf.data(),                                     // lpCommandLine (mutable!)
    NULL, NULL,                                        // process/thread sec attrs
    inheritStdio ? TRUE : FALSE,                       // bInheritHandles
    createFlags,
    useCustomEnv ? reinterpret_cast<LPVOID>(envBlock.data()) : NULL,
    cwd.empty() ? NULL : cwd.c_str(),                  // lpCurrentDirectory
    reinterpret_cast<LPSTARTUPINFOW>(&siex),           // lpStartupInfo
    &pi                                                // lpProcessInformation
  );

  DeleteProcThreadAttributeList(attrList);
  HeapFree(GetProcessHeap(), 0, attrList);

  if (!ok) {
    DWORD err = GetLastError();
    char msg[128]; sprintf_s(msg, "CreateProcessW failed: error %lu", err);
    Napi::Error::New(env, msg).ThrowAsJavaScriptException();
    return env.Undefined();
  }

  CloseHandle(pi.hThread); // We only need hProcess

  uint32_t processId = g_nextProcessId++;
  g_processes[processId] = pi.hProcess;

  return Napi::Number::New(env, processId);
}

// ---------------------------------------------------------------------------
// WaitForProcess
// JS: waitForProcess(processHandleId) → exitCode
// ---------------------------------------------------------------------------

Napi::Value WaitForProcess(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1) {
    Napi::TypeError::New(env, "waitForProcess(processHandleId)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t processId = info[0].As<Napi::Number>().Uint32Value();
  auto it = g_processes.find(processId);
  if (it == g_processes.end()) {
    Napi::Error::New(env, "Invalid process handle ID").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  HANDLE hProcess = it->second;
  WaitForSingleObject(hProcess, INFINITE);

  DWORD exitCode = 0;
  GetExitCodeProcess(hProcess, &exitCode);
  CloseHandle(hProcess);
  g_processes.erase(it);

  return Napi::Number::New(env, exitCode);
}

// ---------------------------------------------------------------------------
// TerminateContainerProcess
// JS: terminateProcess(processHandleId, exitCode) → void
// Renamed from TerminateProcess to avoid conflict with Win32 TerminateProcess().
// ---------------------------------------------------------------------------

Napi::Value TerminateContainerProcess(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2) {
    Napi::TypeError::New(env, "terminateProcess(processHandleId, exitCode)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t processId = info[0].As<Napi::Number>().Uint32Value();
  uint32_t exitCode  = info[1].As<Napi::Number>().Uint32Value();

  auto it = g_processes.find(processId);
  if (it != g_processes.end()) {
    ::TerminateProcess(it->second, exitCode);
  }

  return env.Undefined();
}

// ---------------------------------------------------------------------------
// DeleteProfile
// JS: deleteProfile(handleId) → void
//
// Deletes the AppContainer profile and frees all associated SIDs.
// ---------------------------------------------------------------------------

Napi::Value DeleteProfile(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1) {
    Napi::TypeError::New(env, "deleteProfile(handleId)").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  uint32_t handleId = info[0].As<Napi::Number>().Uint32Value();
  AppContainerContext* ctx = getContext(handleId);
  if (!ctx) return env.Undefined();

  // Best-effort delete — profile may have already been removed.
  DeleteAppContainerProfile(ctx->profileName.c_str());

  // Free the AppContainer SID (allocated by CreateAppContainerProfile /
  // DeriveAppContainerSidFromAppContainerName — must use FreeSid).
  if (ctx->sid) {
    FreeSid(ctx->sid);
    ctx->sid = nullptr;
  }

  // Free capability SIDs (allocated by us via LocalAlloc in getCapabilitySid).
  for (auto& sa : ctx->capSids) {
    if (sa.Sid) LocalFree(sa.Sid);
  }
  ctx->capSids.clear();

  removeContext(handleId);
  return env.Undefined();
}

// ---------------------------------------------------------------------------
// Module init
// ---------------------------------------------------------------------------

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  // AppContainer core functions
  exports.Set("createProfile",     Napi::Function::New<CreateProfile>(env, "createProfile"));
  exports.Set("setFsAcl",          Napi::Function::New<SetFsAcl>(env, "setFsAcl"));
  exports.Set("installWfpFilters", Napi::Function::New<InstallWfpFilters>(env, "installWfpFilters"));
  exports.Set("removeWfpFilters",  Napi::Function::New<RemoveWfpFilters>(env, "removeWfpFilters"));
  exports.Set("spawnInContainer",  Napi::Function::New<SpawnInContainer>(env, "spawnInContainer"));
  exports.Set("waitForProcess",    Napi::Function::New<WaitForProcess>(env, "waitForProcess"));
  exports.Set("terminateProcess",  Napi::Function::New<TerminateContainerProcess>(env, "terminateProcess"));
  exports.Set("deleteProfile",     Napi::Function::New<DeleteProfile>(env, "deleteProfile"));

  // Granular WFP functions (from wfp_rules.cc) — for testing and direct use.
  RegisterWfpExports(env, exports);

  return exports;
}

NODE_API_MODULE(appcontainer, Init)
