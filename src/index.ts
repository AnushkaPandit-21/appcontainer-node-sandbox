/**
 * Public API for the Windows AppContainer sandbox driver.
 *
 * Usage in gemini-cli's sandbox.ts dispatch layer:
 *
 *   import {
 *     createSandbox,
 *     runInSandbox,
 *     destroySandbox,
 *     buildConfig,
 *     isAppContainerSupported,
 *   } from '@google/gemini-cli-windows-sandbox';
 *
 *   // In start_appcontainer_sandbox():
 *   const config = buildConfig(cliConfig, sandboxConfig);
 *   const handle = await createSandbox(config);
 *   try {
 *     const result = await runInSandbox(handle, nodeExecutable, {
 *       cwd: process.cwd(),
 *       env: buildSandboxEnv(cliConfig),
 *       nodeArgs,
 *       inheritStdio: true,
 *       signal: abortController.signal,
 *     });
 *     return result.exitCode;
 *   } finally {
 *     await destroySandbox(handle);
 *   }
 */

export {
  createSandbox,
  runInSandbox,
  destroySandbox,
  isAppContainerSupported,
} from './sandbox-windows.js';

export type {
  AppContainerConfig,
  AppContainerHandle,
  AppContainerCapability,
  FsAccessRule,
  FsPermission,
  WfpAllowRule,
  RunOptions,
  SandboxResult,
} from './types.js';

export { AppContainerError } from './types.js';

// ---------------------------------------------------------------------------
// Config builder helper
// Constructs an AppContainerConfig from the same inputs that sandbox.ts
// collects before launching: cwd, tmpdir, homedir, include-dirs, profile name.
// This is the TypeScript equivalent of building the -D args for sandbox-exec.
// ---------------------------------------------------------------------------

import os from 'node:os';
import path from 'node:path';
import type { AppContainerConfig, FsAccessRule, WfpAllowRule } from './types.js';
import { AppContainerCapability } from './types.js';

export interface BuildConfigOptions {
  /** The project working directory (TARGET_DIR equivalent). */
  targetDir: string;

  /** The system temp directory (TMP_DIR equivalent). */
  tmpDir?: string;

  /** Path to the Node.js executable that will be sandboxed. */
  nodeExecutablePath: string;

  /**
   * Profile: 'open' (outbound internet allowed) or 'proxied' (WFP restricted).
   * Mirrors the macOS Seatbelt *-open vs *-proxied profile distinction.
   */
  networkProfile: 'open' | 'proxied';

  /** Extra writable directories (INCLUDE_DIR_0..4 equivalent). */
  includeDirs?: string[];

  /**
   * If networkProfile is 'proxied', the proxy endpoint to allow.
   * Default: { remoteIp: '127.0.0.1', remotePort: 8877 }
   */
  proxyEndpoint?: { remoteIp: string; remotePort: number };

  /**
   * Unique session identifier appended to the profile name.
   * Default: random hex string.
   */
  sessionId?: string;
}

/**
 * Builds an AppContainerConfig from high-level sandbox options.
 *
 * This mirrors the parameter assembly in sandbox.ts (lines 57–89 for Seatbelt,
 * lines 340–450 for container) adapted for AppContainer's ACL/capability model.
 */
export function buildConfig(opts: BuildConfigOptions): AppContainerConfig {
  const sessionId = opts.sessionId ?? Math.random().toString(16).slice(2, 10);
  const profileName = `gemini-cli-${sessionId}`;
  const tmpDir = opts.tmpDir ?? os.tmpdir();
  const homeDir = os.homedir();

  // Build filesystem rules — mirrors the Seatbelt profile parameters.
  // 'permissive-open' / 'restrictive-open' / 'strict-open' equivalent:
  //   We always restrict writes; reads depend on profile strictness.
  const fsRules: FsAccessRule[] = [
    // Target project dir: read + write (all profiles)
    { path: opts.targetDir, permission: 'readwrite', recursive: true },

    // Temp dir: read + write (all profiles)
    { path: tmpDir, permission: 'readwrite', recursive: true },

    // ~/.gemini: read + write (settings, keys)
    { path: path.join(homeDir, '.gemini'), permission: 'readwrite', recursive: true },

    // ~/.npm / ~/.cache: write allowed (Seatbelt allows this too)
    { path: path.join(homeDir, '.npm'), permission: 'readwrite', recursive: true },
    { path: path.join(homeDir, '.cache'), permission: 'readwrite', recursive: true },

    // Node.js installation: read only (needed to exec node.exe and load modules)
    {
      path: path.dirname(opts.nodeExecutablePath),
      permission: 'read',
      recursive: true,
    },
  ];

  // Add extra include directories (INCLUDE_DIR_0..4 equivalent)
  for (const dir of opts.includeDirs ?? []) {
    fsRules.push({ path: dir, permission: 'readwrite', recursive: true });
  }

  // Network configuration
  const capabilities: AppContainerCapability[] =
    opts.networkProfile === 'open'
      ? [AppContainerCapability.InternetClient]
      : []; // 'proxied': no capabilities — WFP handles allow-list

  const wfpAllowRules: WfpAllowRule[] | undefined =
    opts.networkProfile === 'proxied'
      ? [
          opts.proxyEndpoint ?? {
            remoteIp: '127.0.0.1',
            remotePort: 8877,
            description: 'Gemini CLI sandbox proxy',
          },
          // Always allow debugger port inbound (mirrors Seatbelt profiles)
          {
            remoteIp: '127.0.0.1',
            remotePort: 9229,
            description: 'Node.js inspector',
          },
        ]
      : undefined;

  return {
    profileName,
    displayName: `Gemini CLI Sandbox (${sessionId})`,
    fsRules,
    capabilities,
    wfpAllowRules,
  };
}
