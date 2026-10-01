'use strict';
/**
 * Code-signature inspection for release artifacts.
 *
 * Two separate concerns live here:
 *
 *  1. A cert-free structural check. An Authenticode signature is embedded in
 *     the PE certificate table, so whether an installer carries one at all can
 *     be determined by parsing the file on any operating system, with no
 *     signing identity and no Windows tooling. That makes "we shipped an
 *     unsigned installer" detectable in ordinary CI instead of only on a
 *     Windows release machine.
 *
 *  2. Pure interpreters for the platform verifiers (signtool, codesign, spctl).
 *     Running those tools needs the real OS; deciding what their output means
 *     does not. Keeping the decision separate means the policy is unit-tested
 *     deterministically, and an unrecognised output is never read as success.
 *
 * Nothing here treats "could not check" as "passed".
 */
const {openSync, readSync, closeSync, statSync} = require('node:fs');
const {spawnSync} = require('node:child_process');

const WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002;

function readBuffer(fd, length, position) {
  const buffer = Buffer.alloc(length);
  const read = readSync(fd, buffer, 0, length, position);
  if (read !== length) throw new Error('PE_TRUNCATED');
  return buffer;
}

/**
 * Report whether a PE image carries an embedded Authenticode certificate.
 *
 * Returns {signed:boolean, ...} on a parsable PE, or {parsed:false, reason} when
 * the file is not a PE at all. A caller must not read {parsed:false} as signed.
 */
function inspectPortableExecutable(path) {
  let fd;
  try {
    fd = openSync(path, 'r');
    const size = statSync(path).size;
    if (size < 0x40) return {parsed: false, reason: 'PE_TOO_SMALL'};

    const dos = readBuffer(fd, 0x40, 0);
    if (dos.toString('ascii', 0, 2) !== 'MZ') return {parsed: false, reason: 'PE_NO_MZ'};
    const peOffset = dos.readUInt32LE(0x3c);
    if (peOffset <= 0 || peOffset + 24 > size) return {parsed: false, reason: 'PE_BAD_HEADER_OFFSET'};

    const coff = readBuffer(fd, 24, peOffset);
    if (coff.toString('ascii', 0, 4) !== 'PE\0\0') return {parsed: false, reason: 'PE_NO_SIGNATURE'};
    const optionalHeaderSize = coff.readUInt16LE(20);
    if (optionalHeaderSize === 0) return {parsed: false, reason: 'PE_NO_OPTIONAL_HEADER'};

    const optionalOffset = peOffset + 24;
    const magic = readBuffer(fd, 2, optionalOffset).readUInt16LE(0);
    let directoryCountOffset;
    let directoryTableOffset;
    if (magic === 0x10b) {            // PE32
      directoryCountOffset = optionalOffset + 92;
      directoryTableOffset = optionalOffset + 96;
    } else if (magic === 0x20b) {     // PE32+
      directoryCountOffset = optionalOffset + 108;
      directoryTableOffset = optionalOffset + 112;
    } else {
      return {parsed: false, reason: 'PE_UNKNOWN_OPTIONAL_MAGIC'};
    }

    const directoryCount = readBuffer(fd, 4, directoryCountOffset).readUInt32LE(0);
    // Index 4 is IMAGE_DIRECTORY_ENTRY_SECURITY.
    if (directoryCount <= 4) return {parsed: true, signed: false, reason: 'NO_SECURITY_DIRECTORY'};

    const entry = readBuffer(fd, 8, directoryTableOffset + 4 * 8);
    // For the security directory this field is a file offset, not an RVA.
    const certificateOffset = entry.readUInt32LE(0);
    const certificateSize = entry.readUInt32LE(4);
    if (certificateOffset === 0 || certificateSize === 0) {
      return {parsed: true, signed: false, reason: 'EMPTY_SECURITY_DIRECTORY'};
    }
    if (certificateOffset + 8 > size) return {parsed: true, signed: false, reason: 'SECURITY_DIRECTORY_OUT_OF_BOUNDS'};

    const header = readBuffer(fd, 8, certificateOffset);
    const declaredLength = header.readUInt32LE(0);
    const revision = header.readUInt16LE(4);
    const certificateType = header.readUInt16LE(6);
    if (declaredLength < 8 || certificateOffset + declaredLength > size) {
      return {parsed: true, signed: false, reason: 'CERTIFICATE_LENGTH_INVALID'};
    }
    if (certificateType !== WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
      return {parsed: true, signed: false, reason: 'CERTIFICATE_TYPE_UNEXPECTED', certificateType};
    }
    return {
      parsed: true,
      signed: true,
      certificateOffset,
      certificateSize,
      declaredLength,
      revision,
      certificateType
    };
  } catch (error) {
    return {parsed: false, reason: error && error.message === 'PE_TRUNCATED' ? 'PE_TRUNCATED' : 'PE_UNREADABLE'};
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Interpret `signtool verify /pa` output.
 *
 * Exit status alone is not enough: signtool reports some failures on stdout, so
 * both are considered and anything unrecognised is a failure.
 */
function interpretSigntoolOutput({status, stdout = '', stderr = ''}) {
  const text = `${stdout}\n${stderr}`;
  if (/No signature found/i.test(text)) return {ok: false, reason: 'UNSIGNED'};
  if (/is not timestamped/i.test(text) && status !== 0) return {ok: false, reason: 'NOT_TIMESTAMPED'};
  if (/A certificate chain processed, but terminated/i.test(text)) return {ok: false, reason: 'CHAIN_UNTRUSTED'};
  if (/SignTool Error/i.test(text)) return {ok: false, reason: 'SIGNTOOL_ERROR'};
  if (status === 0 && /Successfully verified/i.test(text)) return {ok: true, reason: 'VERIFIED'};
  return {ok: false, reason: 'UNRECOGNISED_OUTPUT'};
}

/** Interpret `codesign --verify --deep --strict --verbose=2` output. */
function interpretCodesignOutput({status, stdout = '', stderr = ''}) {
  const text = `${stdout}\n${stderr}`;
  if (/code object is not signed at all/i.test(text)) return {ok: false, reason: 'UNSIGNED'};
  if (/invalid signature|failed to satisfy|a sealed resource is missing or invalid|invalid Info\.plist/i.test(text)) {
    return {ok: false, reason: 'SIGNATURE_INVALID'};
  }
  if (status !== 0) return {ok: false, reason: 'CODESIGN_FAILED'};
  if (/: valid on disk/i.test(text) && /satisfies its Designated Requirement/i.test(text)) {
    return {ok: true, reason: 'VERIFIED'};
  }
  return {ok: false, reason: 'UNRECOGNISED_OUTPUT'};
}

/** Interpret `spctl --assess --type execute --verbose` output. */
function interpretSpctlOutput({status, stdout = '', stderr = ''}) {
  const text = `${stdout}\n${stderr}`;
  if (/rejected/i.test(text)) {
    if (/source=Unnotarized/i.test(text)) return {ok: false, reason: 'NOT_NOTARIZED'};
    return {ok: false, reason: 'GATEKEEPER_REJECTED'};
  }
  if (status === 0 && /accepted/i.test(text)) {
    if (/source=Notarized Developer ID/i.test(text)) return {ok: true, reason: 'NOTARIZED_DEVELOPER_ID'};
    if (/source=Developer ID/i.test(text)) return {ok: true, reason: 'DEVELOPER_ID_NOT_NOTARIZED'};
    return {ok: true, reason: 'ACCEPTED_OTHER_SOURCE'};
  }
  return {ok: false, reason: 'UNRECOGNISED_OUTPUT'};
}


/**
 * Extract the certificate that actually signed the file.
 *
 * signtool /v prints the signing chain from root to leaf, indenting each level,
 * and then prints the TIMESTAMP chain under its own heading. The signer is the
 * last certificate of the signing chain — the leaf. Everything else in the
 * output (the file path, the root and intermediate CAs, the timestamp
 * authority) names some other party, so searching the whole text for a name
 * answers a different question than "who signed this".
 *
 * Returns {ok:true, signer:{issuedTo, issuedBy, sha1}} or a reason. A file with
 * several signatures whose signers disagree is ambiguous, not a match: which
 * one is "the publisher" is not for this code to decide.
 */
function parseAuthenticodeSigner(text) {
  const lines = String(text).split(/\r?\n/);
  // Headings that end a chain. "Timestamp Verified by" starts a different chain
  // whose certificates must never be read as the signer.
  const ENDS_CHAIN = /^\s*(The signature is timestamped|Timestamp Verified by|Successfully verified|Signature Index|Number of |File is signed)/i;

  const signers = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (!/^\s*Signing Certificate Chain:/i.test(lines[i])) continue;
    let leaf = null;
    for (let j = i + 1; j < lines.length; j += 1) {
      if (ENDS_CHAIN.test(lines[j])) break;
      const issuedTo = /^\s*Issued to:\s*(.+?)\s*$/.exec(lines[j]);
      if (issuedTo) { leaf = {issuedTo: issuedTo[1], issuedBy: '', sha1: ''}; continue; }
      if (!leaf) continue;
      const issuedBy = /^\s*Issued by:\s*(.+?)\s*$/.exec(lines[j]);
      if (issuedBy) { leaf.issuedBy = issuedBy[1]; continue; }
      const sha1 = /^\s*SHA1 hash:\s*([0-9a-fA-F ]+?)\s*$/.exec(lines[j]);
      if (sha1) leaf.sha1 = sha1[1];
    }
    if (leaf) signers.push(leaf);
  }

  if (signers.length === 0) return {ok: false, reason: 'SIGNER_NOT_FOUND'};
  const distinct = new Set(signers.map(s => `${s.issuedTo}\u0000${s.sha1.replace(/\s+/g, '').toLowerCase()}`));
  if (distinct.size > 1) return {ok: false, reason: 'SIGNER_AMBIGUOUS'};
  return {ok: true, signer: signers[0]};
}

/** A thumbprint's formatting is not part of its identity. */
const normaliseThumbprint = value => String(value).replace(/[\s:]/g, '').toLowerCase();

/**
 * Real Authenticode trust verification.
 *
 * inspectPortableExecutable only says whether a certificate table is present.
 * It performs no cryptography, checks no digest over the image and validates no
 * chain, so it can never be the thing that approves a release. This runs the
 * operating system's verifier and reports its ACTUAL exit status.
 *
 * `exec` is injectable so the decision logic is testable without Windows. A
 * verifier that could not run returns ran:false and never ok:true.
 */
async function verifyAuthenticodeTrust({
  file, expectedPublisher = null, expectedThumbprint = null, exec = defaultSigntoolExec
} = {}) {
  let outcome;
  try {
    outcome = await exec(file);
  } catch (error) {
    const missing = error && (error.code === 'ENOENT' || /ENOENT|not recognized|not found/i.test(String(error.message ?? '')));
    return {ok: false, ran: false, reason: missing ? 'SIGNTOOL_UNAVAILABLE' : 'SIGNTOOL_EXEC_FAILED'};
  }
  if (!outcome || typeof outcome.status !== 'number') {
    return {ok: false, ran: false, reason: 'SIGNTOOL_NO_STATUS'};
  }
  const interpreted = interpretSigntoolOutput(outcome);
  const result = {...interpreted, ran: true, status: outcome.status};
  if (!result.ok) return result;

  // Who signed it is a separate question from whether the signature is valid,
  // and it is answered from the signing certificate rather than from the text
  // of the report. A substring search over the whole output would accept a file
  // signed by someone else whose build path merely contained the expected name.
  const text = `${outcome.stdout ?? ''}\n${outcome.stderr ?? ''}`;
  const parsed = parseAuthenticodeSigner(text);
  if (expectedPublisher || expectedThumbprint) {
    if (!parsed.ok) return {...result, ok: false, reason: parsed.reason};
    if (expectedPublisher && parsed.signer.issuedTo !== String(expectedPublisher).trim()) {
      return {...result, ok: false, reason: 'PUBLISHER_MISMATCH', signer: parsed.signer};
    }
    // Pinning the certificate itself survives a renamed subject and is the
    // stronger check; see distribution/desktop/README.md for how it is rotated.
    if (expectedThumbprint
      && normaliseThumbprint(parsed.signer.sha1) !== normaliseThumbprint(expectedThumbprint)) {
      return {...result, ok: false, reason: 'SIGNER_THUMBPRINT_MISMATCH', signer: parsed.signer};
    }
  }
  return parsed.ok ? {...result, signer: parsed.signer} : result;
}

function defaultSigntoolExec(file) {
  const outcome = spawnSync('signtool', ['verify', '/pa', '/v', file], {encoding: 'utf8'});
  if (outcome.error) throw outcome.error;
  return {status: outcome.status, stdout: outcome.stdout, stderr: outcome.stderr};
}

/**
 * Run a macOS verifier and keep its real exit status.
 *
 * Passing recorded text with an assumed status:0 into the interpreters, as the
 * previous workflow did, cannot distinguish "the tool said this and succeeded"
 * from "the tool never ran".
 */
function runMacVerifier(command, args) {
  const outcome = spawnSync(command, args, {encoding: 'utf8'});
  if (outcome.error) {
    const missing = outcome.error.code === 'ENOENT';
    return {ran: false, status: null, stdout: '', stderr: String(outcome.error.message ?? ''),
      reason: missing ? `${command.toUpperCase()}_UNAVAILABLE` : `${command.toUpperCase()}_EXEC_FAILED`};
  }
  return {ran: true, status: outcome.status, stdout: outcome.stdout ?? '', stderr: outcome.stderr ?? ''};
}

/**
 * Interpret `codesign --display --verbose=4` output.
 *
 * `codesign --verify` proves the bundle's seal is intact; it does not say WHO
 * signed it. An intact signature from an unknown identity is not release trust,
 * so the signing authority and team identifier are checked separately here
 * against values the caller supplied from trusted configuration.
 */
function interpretCodesignIdentity({status, stdout = '', stderr = ''}, {expectedTeamId = null} = {}) {
  const text = `${stdout}\n${stderr}`;
  if (/code object is not signed at all/i.test(text)) return {ok: false, reason: 'UNSIGNED'};
  if (status !== 0) return {ok: false, reason: 'CODESIGN_DISPLAY_FAILED'};
  const authority = /^Authority=(.+)$/m.exec(text);
  if (!authority || !/^Developer ID Application:/.test(authority[1].trim())) {
    return {ok: false, reason: 'NOT_DEVELOPER_ID_APPLICATION'};
  }
  const team = /^TeamIdentifier=(.+)$/m.exec(text);
  const teamId = team ? team[1].trim() : '';
  if (!teamId || teamId === 'not set') return {ok: false, reason: 'TEAM_IDENTIFIER_ABSENT'};
  // An expected team id that is never compared is not a check. When the caller
  // supplies one it must match exactly.
  if (expectedTeamId && teamId !== expectedTeamId) return {ok: false, reason: 'TEAM_IDENTIFIER_MISMATCH', teamId};
  return {ok: true, reason: 'IDENTITY_VERIFIED', teamId};
}

/**
 * Hardened Runtime, read from the same `codesign --display --verbose=4` output.
 *
 * It is reported separately from the signing identity because they fail for
 * different reasons: a correctly signed build with Hardened Runtime disabled
 * cannot be notarized, and saying only "codesign passed" would hide that.
 * codesign prints the CS_RUNTIME flag as `flags=0x10000(runtime)`.
 */
function interpretHardenedRuntime({status, stdout = '', stderr = ''}) {
  const text = `${stdout}\n${stderr}`;
  if (status !== 0) return {ok: false, reason: 'CODESIGN_DISPLAY_FAILED'};
  const flags = /^CodeDirectory\b.*?\bflags=(0x[0-9a-fA-F]+)/m.exec(text) || /\bflags=(0x[0-9a-fA-F]+)/.exec(text);
  if (!flags) return {ok: false, reason: 'CODE_DIRECTORY_FLAGS_ABSENT'};
  // CS_RUNTIME = 0x10000.
  const enabled = (Number.parseInt(flags[1], 16) & 0x10000) !== 0;
  return enabled
    ? {ok: true, reason: 'HARDENED_RUNTIME_ENABLED', flags: flags[1]}
    : {ok: false, reason: 'HARDENED_RUNTIME_DISABLED', flags: flags[1]};
}

/**
 * Interpret `xcrun stapler validate` output.
 *
 * Notarization and stapling are different things: a notarized artifact whose
 * ticket was never stapled still shows a Gatekeeper prompt for a user who is
 * offline. spctl cannot distinguish the two on a machine that can reach Apple,
 * so the ticket is checked on its own.
 */
function interpretStaplerOutput({status, stdout = '', stderr = ''}) {
  const text = `${stdout}\n${stderr}`;
  if (/does not have a ticket stapled|not have a ticket|Error 65/i.test(text)) {
    return {ok: false, reason: 'TICKET_NOT_STAPLED'};
  }
  if (/The validate action failed/i.test(text)) return {ok: false, reason: 'STAPLE_VALIDATION_FAILED'};
  if (status === 0 && /The validate action worked/i.test(text)) return {ok: true, reason: 'TICKET_STAPLED'};
  return {ok: false, reason: 'UNRECOGNISED_OUTPUT'};
}

/**
 * The COMPLETE spctl argv, target included.
 *
 * This returns the whole command line rather than just its options, and the
 * name says so, because the previous split invited exactly the bug it caused:
 * one caller appended the file and the other did not, so the macOS report ran
 * spctl with options and nothing to assess. Ownership of the target lives here
 * now, so it is passed once, by construction, at every call site.
 *
 * The assessment type depends on what the artifact is. Assessing a disk image
 * as an installer package asks Gatekeeper the wrong question, and a wrong
 * question does not produce a trustworthy answer.
 */
function spctlArgvFor(file) {
  const lower = String(file).toLowerCase();
  if (lower.endsWith('.app')) return ['--assess', '--type', 'execute', '--verbose', file];
  if (lower.endsWith('.pkg') || lower.endsWith('.mpkg')) return ['--assess', '--type', 'install', '--verbose', file];
  return ['--assess', '--type', 'open', '--context', 'context:primary-signature', '--verbose', file];
}

/** Apply an interpreter to a run result, refusing anything that did not run. */
function interpretRun(run, interpret) {
  if (!run || run.ran !== true) {
    return {ok: false, ran: false, reason: run && run.reason ? run.reason : 'VERIFIER_DID_NOT_RUN'};
  }
  if (typeof run.status !== 'number') return {ok: false, ran: true, reason: 'VERIFIER_NO_STATUS'};
  return {...interpret(run), ran: true, status: run.status};
}

/**
 * Apply the release policy to an inspection result.
 *
 * `requireSigned` comes from the caller's release mode. When signing is
 * required, anything other than a positively verified signature fails; an
 * unavailable verifier is a failure too, never a pass.
 */
function applySigningPolicy(result, {requireSigned}) {
  if (!requireSigned) return {ok: true, enforced: false, detail: result};
  if (!result || result.ok !== true) {
    return {ok: false, enforced: true, reason: result && result.reason ? result.reason : 'VERIFICATION_UNAVAILABLE', detail: result};
  }
  return {ok: true, enforced: true, detail: result};
}

module.exports = {
  inspectPortableExecutable,
  verifyAuthenticodeTrust,
  parseAuthenticodeSigner,
  runMacVerifier,
  interpretRun,
  interpretSigntoolOutput,
  interpretCodesignOutput,
  interpretCodesignIdentity,
  interpretHardenedRuntime,
  interpretStaplerOutput,
  interpretSpctlOutput,
  spctlArgvFor,
  applySigningPolicy,
  WIN_CERT_TYPE_PKCS_SIGNED_DATA
};
