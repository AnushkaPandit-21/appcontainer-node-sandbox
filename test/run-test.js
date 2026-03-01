'use strict';

/**
 * AppContainer sandbox integration test.
 *
 * Tests two core isolation properties:
 *   1. Write to C:\Windows\ is BLOCKED (AppContainer has no ACL there).
 *   2. Write to a directory we explicitly granted via setFsAcl SUCCEEDS.
 *
 * Run after: npm run build:native
 *   node test/run-test.js
 */

const path = require('path');
const fs   = require('fs');
const os   = require('os');

// ---------------------------------------------------------------------------
// Load native addon
// ---------------------------------------------------------------------------

const addonPath = path.resolve(__dirname, '..', 'build', 'Release', 'appcontainer.node');
let addon;
try {
  addon = require(addonPath);
} catch (err) {
  console.error('ERROR: Failed to load appcontainer.node');
  console.error('       Run "npm run build:native" first.\n');
  console.error(err.message);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

const testDir     = path.join(os.tmpdir(), `ac-test-${Date.now()}`);
const profileName = `gemini-cli-test-${Date.now()}`;
let handleId;

fs.mkdirSync(testDir, { recursive: true });

function pass(label) { console.log(`  PASS  ${label}`); }
function fail(label) { console.log(`  FAIL  ${label}`); }

// ---------------------------------------------------------------------------
// Cleanup helper (always called, even on early exit)
// ---------------------------------------------------------------------------

function cleanup() {
  console.log('\n[cleanup]');
  if (handleId !== undefined) {
    try {
      addon.deleteProfile(handleId);
      console.log('  AppContainer profile deleted');
    } catch (e) {
      console.error('  deleteProfile error:', e.message);
    }
  }
  try {
    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('  Test directory removed');
  } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// Main test
// ---------------------------------------------------------------------------

(function main() {
  let passCount = 0;
  let failCount = 0;

  console.log('=== AppContainer Sandbox Integration Test ===\n');
  console.log(`  Profile : ${profileName}`);
  console.log(`  Test dir: ${testDir}\n`);

  // ── Step 1: Create the AppContainer profile ──────────────────────────────
  console.log('[1] Creating AppContainer profile...');
  let profileResult;
  try {
    profileResult = addon.createProfile(profileName, 'Gemini CLI Sandbox Test', []);
    handleId = profileResult.handleId;
    console.log(`    handleId = ${handleId}`);
    console.log(`    SID      = ${profileResult.sid}\n`);
  } catch (err) {
    console.error('  ERROR:', err.message);
    cleanup();
    process.exit(1);
  }

  // ── Step 2: Grant AppContainer access to testDir ─────────────────────────
  console.log('[2] Granting read+write ACL on test directory...');
  try {
    addon.setFsAcl(handleId, testDir, 'readwrite', true);
    console.log('    ACL applied\n');
  } catch (err) {
    console.error('  ERROR:', err.message);
    cleanup();
    process.exit(1);
  }

  // ── Test A: Write to C:\Windows\ — SHOULD BE BLOCKED ────────────────────
  const protectedFile = 'C:\\Windows\\ac_isolation_test_delete_me.txt';
  console.log('[3] Test A — write to C:\\Windows\\ (isolation should BLOCK this)...');
  try {
    const pid = addon.spawnInContainer(
      handleId,
      'C:\\Windows\\System32\\cmd.exe',
      ['/c', `echo isolation_test > "${protectedFile}" 2>nul`],
      [],      // env: inherit parent environment
      'C:\\',  // cwd
      true     // inheritStdio
    );
    const exitCode = addon.waitForProcess(pid);
    const written = fs.existsSync(protectedFile);
    if (written) {
      // Clean up the stray file before failing
      try { fs.unlinkSync(protectedFile); } catch { /* ignore */ }
    }
    console.log(`    cmd.exe exit code : ${exitCode}`);
    console.log(`    File exists       : ${written}`);
    if (!written) {
      pass('AppContainer blocked write to C:\\Windows\\');
      passCount++;
    } else {
      fail('Write to C:\\Windows\\ was NOT blocked — isolation is not working!');
      failCount++;
    }
  } catch (err) {
    console.error('  ERROR running test A:', err.message);
    failCount++;
  }

  // ── Test B: Write to ACL-granted testDir — SHOULD SUCCEED ───────────────
  const allowedFile = path.join(testDir, 'hello.txt');
  console.log('\n[4] Test B — write to ACL-granted test dir (should SUCCEED)...');
  try {
    const pid = addon.spawnInContainer(
      handleId,
      'C:\\Windows\\System32\\cmd.exe',
      ['/c', `echo hello_sandbox > "${allowedFile}"`],
      [],
      testDir,
      true
    );
    const exitCode = addon.waitForProcess(pid);
    const written = fs.existsSync(allowedFile);
    console.log(`    cmd.exe exit code : ${exitCode}`);
    console.log(`    File exists       : ${written}`);
    if (written) {
      pass('AppContainer wrote successfully to ACL-granted directory');
      passCount++;
    } else {
      fail('Write to ACL-granted directory was blocked — ACL not applied?');
      failCount++;
    }
  } catch (err) {
    console.error('  ERROR running test B:', err.message);
    failCount++;
  }

  // ── Summary ──────────────────────────────────────────────────────────────
  cleanup();

  console.log('\n=== Results ===');
  console.log(`  Passed: ${passCount}`);
  console.log(`  Failed: ${failCount}`);
  console.log('');

  process.exit(failCount === 0 ? 0 : 1);
})();
