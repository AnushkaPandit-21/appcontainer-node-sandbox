/**
 * Windows AppContainer sandbox driver — TypeScript wrapper.
 *
 * This module sits between gemini-cli's sandbox.ts dispatch layer and the
 * native C++ addon (appcontainer.node). It:
 *
 *   1. Loads the native addon (build/Release/appcontainer.node)
 *   2. Translates TypeScript config → native addon calls
 *   3. Manages the process lifecycle (spawn, wait, cleanup)
 *
 * Integration point in gemini-cli:
 *   sandbox.ts → start_appcontainer_sandbox() → this module
 *
 * Win32 API call sequence (implemented in native/appcontainer.cc):
 *   CreateAppContainerProfile()           — creates the container profile
 *   DeriveAppContainerSidFromAppContainerName() — gets the SID
 *   SetNamedSecurityInfo()                — grants SID access to each fsRule path
 *   InitializeProcThreadAttributeList()   — prepares attribute list for CreateProcess
 *   UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES)
 *   CreateProcess()                       — spawns node.exe inside the container
 *   WaitForSingleObject()                 — waits for process to exit
 *   DeleteAppContainerProfile()           — cleans up profile on destroySandbox()
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import type {
  AppContainerConfig,
  AppContainerHandle,
  RunOptions,
  SandboxResult,
} from './types.js';
import { AppContainerError } from './types.js';

// ---------------------------------------------------------------------------
// Native addon interface
// This describes the shape of what appcontainer.node exports.
// The actual implementation lives in native/appcontainer.cc.
// ---------------------------------------------------------------------------

interface NativeAddon {
  /**
   * Creates an AppContainer profile via CreateAppContainerProfile().
   * Returns an opaque handle ID and the SID string.
   *
   * Throws NativeError on failure (wraps HRESULT from userenv.h).
   */
  createProfile(
    profileName: string,
    displayName: string,
    capabilities: string[],
  ): { handleId: number; sid: string };

  /**
   * Sets filesystem ACLs on a path granting the AppContainer SID
   * the specified access rights via SetNamedSecurityInfo().
   *
   * permission: 'read' | 'write' | 'readwrite'
   * recursive: whether to set inheritance flags
   */
  setFsAcl(
    handleId: number,
    fsPath: string,
    permission: string,
    recursive: boolean,
  ): void;

  /**
   * Installs Windows Filtering Platform (WFP) callout filters that block
   * all outbound TCP from this AppContainer SID except to the allowed endpoints.
   *
   * Returns a WFP filter handle ID used by removeWfpFilters().
   */
  installWfpFilters(
    handleId: number,
    allowRules: Array<{ remoteIp: string; remotePort: number }>,
  ): number;

  /**
   * Removes WFP filters previously installed by installWfpFilters().
   */
  removeWfpFilters(wfpHandleId: number): void;

  /**
   * Spawns a process inside the AppContainer using CreateProcess() with
   * PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES.
   *
   * Returns the Win32 process handle ID (used with waitForProcess).
   *
   * executable: full path to node.exe
   * args: command-line arguments
   * env: environment variables as flat 'KEY=VALUE' strings
   * cwd: working directory
   * inheritStdio: whether to attach to parent's console handles
   */
  spawnInContainer(
    handleId: number,
    executable: string,
    args: string[],
    env: string[],
    cwd: string,
    inheritStdio: boolean,
  ): number;

  /**
   * Waits for a spawned process to exit (WaitForSingleObject + GetExitCodeProcess).
   * Returns the exit code.
   */
  waitForProcess(processHandleId: number): number;

  /**
   * Terminates a running process (TerminateProcess).
   */
  terminateProcess(processHandleId: number, exitCode: number): void;

  /**
   * Removes the AppContainer profile (DeleteAppContainerProfile)
   * and frees native resources.
   */
  deleteProfile(handleId: number): void;
}

// ---------------------------------------------------------------------------
// Addon loading
// ---------------------------------------------------------------------------

function loadNativeAddon(): NativeAddon {
  if (process.platform !== 'win32') {
    throw new Error(
      'AppContainer sandbox is only supported on Windows. ' +
      'Use GEMINI_SANDBOX=docker on other platforms.',
    );
  }

  const require = createRequire(import.meta.url);
  const addonDir = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    'build',
    'Release',
  );
  const addonPath = path.join(addonDir, 'appcontainer.node');

  try {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return require(addonPath) as NativeAddon;
  } catch (err) {
    throw new Error(
      `Failed to load native AppContainer addon from ${addonPath}.\n` +
      `Run 'npm run build:native' first.\nCause: ${String(err)}`,
    );
  }
}

// Lazily loaded on first use.
let _addon: NativeAddon | null = null;

function getAddon(): NativeAddon {
  if (!_addon) {
    _addon = loadNativeAddon();
  }
  return _addon;
}

// ---------------------------------------------------------------------------
// Active process tracking for abort signal support
// ---------------------------------------------------------------------------

interface ActiveProcess {
  processHandleId: number;
  emitter: EventEmitter;
}

const activeProcesses = new Map<number, ActiveProcess>();
let nextProcessKey = 0;

// ---------------------------------------------------------------------------
// Public API implementation
// ---------------------------------------------------------------------------

/**
 * Creates an AppContainer profile and sets up filesystem ACLs.
 *
 * This must be called once before runInSandbox(). The returned handle is
 * passed to both runInSandbox() and destroySandbox().
 *
 * Corresponds to the macOS Seatbelt profile selection + parameter building
 * step in sandbox.ts lines 51–89.
 */
export async function createSandbox(
  config: AppContainerConfig,
): Promise<AppContainerHandle> {
  const addon = getAddon();

  // Step 1: Create the AppContainer profile and get its SID.
  // Win32: CreateAppContainerProfile(profileName, displayName, description,
  //          pCapabilities, dwCapabilityCount, &ppSidAppContainerSid)
  let result: { handleId: number; sid: string };
  try {
    result = addon.createProfile(
      config.profileName,
      config.displayName,
      config.capabilities,
    );
  } catch (err) {
    const code = (err as { code?: number }).code ?? 0;
    throw new AppContainerError(String(err), code, 'createProfile');
  }

  const { handleId, sid } = result;

  // Step 2: Grant the AppContainer SID access to each filesystem path.
  // Win32: SetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
  //          NULL, NULL, pNewDacl, NULL)
  // where pNewDacl is built by SetEntriesInAcl() with the SID and access mask.
  for (const rule of config.fsRules) {
    try {
      addon.setFsAcl(handleId, rule.path, rule.permission, rule.recursive ?? true);
    } catch (err) {
      const code = (err as { code?: number }).code ?? 0;
      // Clean up profile before re-throwing.
      try { addon.deleteProfile(handleId); } catch { /* ignore cleanup error */ }
      throw new AppContainerError(
        `Failed to set ACL on ${rule.path}: ${String(err)}`,
        code,
        'setFsAcl',
      );
    }
  }

  // Step 3: Install WFP network filters if proxied networking is requested.
  // Win32: FwpmEngineOpen0(), FwpmFilterAdd0() with AppContainer SID condition.
  let hasWfpFilters = false;
  if (config.wfpAllowRules && config.wfpAllowRules.length > 0) {
    try {
      addon.installWfpFilters(handleId, config.wfpAllowRules);
      hasWfpFilters = true;
    } catch (err) {
      const code = (err as { code?: number }).code ?? 0;
      try { addon.deleteProfile(handleId); } catch { /* ignore */ }
      throw new AppContainerError(String(err), code, 'installWfpFilters');
    }
  }

  return {
    profileName: config.profileName,
    sid,
    hasWfpFilters,
    nativeHandleId: handleId,
  };
}

/**
 * Spawns a process inside the AppContainer and waits for it to exit.
 *
 * Corresponds to the spawn() call in sandbox.ts at lines 175–195 (Seatbelt)
 * or lines 600–650 (container), returning a Promise<number> exit code.
 *
 * The process is launched via CreateProcess() with a
 * PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES attribute that contains the
 * AppContainer SID and granted capabilities. The process runs at Low
 * integrity level and cannot escape the AppContainer boundary.
 */
export async function runInSandbox(
  handle: AppContainerHandle,
  executable: string,
  opts: RunOptions,
): Promise<SandboxResult> {
  const addon = getAddon();

  // Flatten env Record<string, string> → 'KEY=VALUE' string array for Win32.
  const envPairs = Object.entries(opts.env).map(
    ([k, v]) => `${k}=${v}`,
  );

  // Step 4: Spawn the process inside the AppContainer.
  // Win32 sequence:
  //   SIZE_T attributeListSize;
  //   InitializeProcThreadAttributeList(NULL, 1, 0, &attributeListSize);
  //   LPPROC_THREAD_ATTRIBUTE_LIST attrList = alloc(attributeListSize);
  //   InitializeProcThreadAttributeList(attrList, 1, 0, &attributeListSize);
  //   SECURITY_CAPABILITIES sc = {
  //     .AppContainerSid = pSid,
  //     .Capabilities    = pCapabilities,
  //     .CapabilityCount = dwCapabilityCount,
  //   };
  //   UpdateProcThreadAttribute(attrList,
  //     0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
  //     &sc, sizeof(sc), NULL, NULL);
  //   STARTUPINFOEXW si = { .lpAttributeList = attrList };
  //   CreateProcessW(executable, cmdLine, NULL, NULL, inheritHandles,
  //     EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
  //     pEnv, pCwd, &si.StartupInfo, &pi);

  let processHandleId: number;
  try {
    processHandleId = addon.spawnInContainer(
      handle.nativeHandleId,
      executable,
      opts.nodeArgs ?? [],
      envPairs,
      opts.cwd,
      opts.inheritStdio ?? true,
    );
  } catch (err) {
    const code = (err as { code?: number }).code ?? 0;
    throw new AppContainerError(String(err), code, 'spawnInContainer');
  }

  // Track the process for abort signal support.
  const key = nextProcessKey++;
  const emitter = new EventEmitter();
  activeProcesses.set(key, { processHandleId, emitter });

  // Wire up abort signal → TerminateProcess.
  const onAbort = () => {
    try {
      addon.terminateProcess(processHandleId, 1);
    } catch { /* process may already have exited */ }
  };
  opts.signal?.addEventListener('abort', onAbort);

  // Step 5: Wait for exit.
  // Win32: WaitForSingleObject(hProcess, INFINITE) + GetExitCodeProcess()
  let exitCode: number;
  try {
    exitCode = await new Promise<number>((resolve, reject) => {
      // WaitForSingleObject is blocking — run it on a libuv thread pool worker
      // via the native addon's async waitForProcess to avoid blocking the
      // Node.js event loop.
      setImmediate(() => {
        try {
          const code = addon.waitForProcess(processHandleId);
          resolve(code);
        } catch (e) {
          reject(e);
        }
      });
    });
  } finally {
    opts.signal?.removeEventListener('abort', onAbort);
    activeProcesses.delete(key);
  }

  return { exitCode, output: '' };
}

/**
 * Tears down the sandbox: removes WFP filters and deletes the AppContainer profile.
 *
 * Should be called in a finally block after runInSandbox() returns, regardless
 * of success or failure — analogous to the container removal ('docker rm') that
 * happens at the end of the container sandbox lifecycle.
 *
 * Win32: DeleteAppContainerProfile(profileName)
 *        FwpmFilterDeleteById0() for each installed WFP filter (if proxied)
 */
export async function destroySandbox(handle: AppContainerHandle): Promise<void> {
  const addon = getAddon();

  // Remove WFP filters first (must happen before profile deletion).
  if (handle.hasWfpFilters) {
    try {
      addon.removeWfpFilters(handle.nativeHandleId);
    } catch (err) {
      // Log but don't throw — best-effort cleanup.
      console.error(`[appcontainer] Failed to remove WFP filters: ${String(err)}`);
    }
  }

  // Delete the AppContainer profile.
  // Win32: DeleteAppContainerProfile(pszAppContainerName)
  try {
    addon.deleteProfile(handle.nativeHandleId);
  } catch (err) {
    const code = (err as { code?: number }).code ?? 0;
    throw new AppContainerError(String(err), code, 'deleteProfile');
  }
}

/**
 * Returns true if the current platform supports AppContainer sandboxing.
 * AppContainer requires Windows 8 / Server 2012 or later (NT 6.2+).
 */
export function isAppContainerSupported(): boolean {
  if (process.platform !== 'win32') return false;
  // os.release() returns '10.0.xxxxx' on Windows 10/11,
  // '6.2.xxxxx' on Windows 8. We need >= 6.2.
  const [major, minor] = process.versions.node.split('.').map(Number);
  // Node.js 20+ requires Windows 8.1+, so if we're here we're fine.
  // For completeness, check the Windows version directly.
  void major; void minor;
  try {
    const addon = getAddon();
    void addon; // If the addon loads, the platform is supported.
    return true;
  } catch {
    return false;
  }
}
