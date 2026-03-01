/**
 * TypeScript types for the Windows AppContainer sandbox driver.
 *
 * These types mirror the surface area that sandbox.ts in gemini-cli expects,
 * adapted for the AppContainer Win32 security model.
 *
 * Win32 references:
 *   CreateAppContainerProfile  — userenv.h
 *   InitializeProcThreadAttributeList — processthreadsapi.h
 *   SECURITY_CAPABILITIES      — winnt.h
 *   Windows Filtering Platform — fwpuclnt.lib
 */

// ---------------------------------------------------------------------------
// AppContainer Capability SIDs
// These map directly to the well-known capability SIDs in Windows.
// A SID (Security Identifier) granted here allows the sandboxed process to
// access that resource. Granting NO capabilities means maximum isolation.
// See: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
// ---------------------------------------------------------------------------

export enum AppContainerCapability {
  /**
   * Allows outbound internet connections (TCP/UDP to remote hosts).
   * Win32: WinCapabilityInternetClientSid
   * Grant this for 'open' network profiles; deny for 'proxied' profiles.
   */
  InternetClient = 'internetClient',

  /**
   * Allows inbound connections from the internet.
   * Win32: WinCapabilityInternetClientServerSid
   * Almost always denied for Gemini CLI sandboxing.
   */
  InternetClientServer = 'internetClientServer',

  /**
   * Allows access to devices on the local network (mDNS, UPNP, etc.).
   * Win32: WinCapabilityPrivateNetworkClientServerSid
   */
  PrivateNetworkClientServer = 'privateNetworkClientServer',

  /**
   * Allows reading from the Pictures library.
   * Not needed for Gemini CLI; shown here for completeness.
   */
  PicturesLibrary = 'picturesLibrary',
}

// ---------------------------------------------------------------------------
// Filesystem access rule — maps a host path to a set of permissions
// granted to the AppContainer SID via SetNamedSecurityInfo/SetEntriesInAcl.
// ---------------------------------------------------------------------------

export type FsPermission = 'read' | 'write' | 'readwrite';

export interface FsAccessRule {
  /**
   * Absolute Windows path on the host (e.g. C:\Users\foo\project).
   * The native addon will call SetNamedSecurityInfo to grant this path
   * to the AppContainer SID.
   */
  path: string;
  permission: FsPermission;
  /**
   * If true, the permission applies to all subdirectories (OBJECT_INHERIT_ACE
   * + CONTAINER_INHERIT_ACE flags). Default: true.
   */
  recursive?: boolean;
}

// ---------------------------------------------------------------------------
// Network filter rule — enforced via Windows Filtering Platform (WFP).
// Used for 'proxied' sandbox profiles where outbound traffic is restricted
// to a single proxy endpoint (localhost:8877).
// ---------------------------------------------------------------------------

export interface WfpAllowRule {
  /** Destination IP address (IPv4 or IPv6). '127.0.0.1' for proxy. */
  remoteIp: string;
  /** Destination TCP port. */
  remotePort: number;
  /** Human-readable name for this filter rule. */
  description: string;
}

// ---------------------------------------------------------------------------
// Main sandbox configuration — passed to createSandbox().
// Mirrors the parameters that sandbox.ts builds before launching sandbox-exec
// on macOS, adapted for the AppContainer security model.
// ---------------------------------------------------------------------------

export interface AppContainerConfig {
  /**
   * Unique profile name for this AppContainer instance.
   * Passed to CreateAppContainerProfile(). Must be unique per user per machine.
   * Gemini CLI should use: `gemini-cli-<session-uuid>`
   */
  profileName: string;

  /**
   * Human-readable display name shown in Windows security dialogs.
   */
  displayName: string;

  /**
   * Filesystem access rules. The native addon will set ACLs on each path
   * granting the AppContainer SID the specified permissions.
   *
   * Minimum required for Gemini CLI:
   *   - TARGET_DIR  → readwrite
   *   - TMP_DIR     → readwrite
   *   - Node.js installation dir → read
   *   - INCLUDE_DIRs → readwrite (extra workspace dirs)
   */
  fsRules: FsAccessRule[];

  /**
   * Capability SIDs to grant. An empty array provides maximum isolation
   * (no internet access, no local network, no device access).
   * For 'open' profile: [AppContainerCapability.InternetClient]
   * For 'proxied' profile: [] (network filtered by WFP instead)
   */
  capabilities: AppContainerCapability[];

  /**
   * WFP allow-rules for proxied networking.
   * Only used when capabilities is empty and a proxy command is set.
   * The addon installs a WFP filter that blocks all outbound TCP except
   * matching these rules.
   */
  wfpAllowRules?: WfpAllowRule[];
}

// ---------------------------------------------------------------------------
// Opaque handle returned by createSandbox(), consumed by runInSandbox()
// and destroySandbox().
// The handle wraps the AppContainer SID and profile name so the caller
// never needs to hold raw Win32 memory.
// ---------------------------------------------------------------------------

export interface AppContainerHandle {
  /**
   * The profile name passed to CreateAppContainerProfile().
   * Used by DeleteAppContainerProfile() in destroySandbox().
   */
  readonly profileName: string;

  /**
   * The AppContainer SID as a string (e.g. "S-1-15-2-...").
   * The native addon holds the actual PSID internally; this is for logging.
   */
  readonly sid: string;

  /**
   * Whether WFP filters were installed for this handle.
   * If true, destroySandbox() must remove the WFP filters.
   */
  readonly hasWfpFilters: boolean;

  /**
   * Opaque internal handle ID used by the native addon to look up the
   * SECURITY_CAPABILITIES struct. Not meaningful to TypeScript callers.
   */
  readonly nativeHandleId: number;
}

// ---------------------------------------------------------------------------
// Options for runInSandbox().
// Mirrors the arguments sandbox.ts passes when spawning the sandboxed process.
// ---------------------------------------------------------------------------

export interface RunOptions {
  /**
   * Working directory for the sandboxed process.
   * Must be within a path covered by an fsRule with at least 'read' permission.
   */
  cwd: string;

  /**
   * Environment variables to set in the sandboxed process.
   * Sensitive keys (API keys, etc.) should be passed here, not inherited from
   * the parent, so they are scoped to the sandboxed process.
   */
  env: Record<string, string>;

  /**
   * Arguments to pass to node (the process launched inside the container).
   * Corresponds to nodeArgs in sandbox.ts's start_sandbox().
   */
  nodeArgs?: string[];

  /**
   * Whether to attach stdio of the sandbox to the parent's stdio.
   * Default: true (interactive). Set false for non-interactive/test runs.
   */
  inheritStdio?: boolean;

  /**
   * AbortSignal to terminate the sandboxed process.
   */
  signal?: AbortSignal;
}

// ---------------------------------------------------------------------------
// Result returned by runInSandbox().
// ---------------------------------------------------------------------------

export interface SandboxResult {
  /** Process exit code. 0 = success. */
  exitCode: number;

  /**
   * Combined stdout + stderr if inheritStdio was false.
   * Empty string if inheritStdio was true (output went directly to terminal).
   */
  output: string;
}

// ---------------------------------------------------------------------------
// Error thrown when AppContainer operations fail.
// Wraps the Win32 HRESULT or GetLastError() code returned by the native addon.
// ---------------------------------------------------------------------------

export class AppContainerError extends Error {
  constructor(
    message: string,
    public readonly win32Code: number,
    public readonly operation: string,
  ) {
    super(`AppContainer ${operation} failed (Win32 0x${win32Code.toString(16).toUpperCase().padStart(8, '0')}): ${message}`);
    this.name = 'AppContainerError';
  }
}
