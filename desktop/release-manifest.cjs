'use strict';
/**
 * Release-manifest trust boundary.
 *
 * The desktop shell fetches its update manifest over the network, so the
 * manifest is attacker-reachable input. Nothing in it may be believed until a
 * detached Ed25519 signature over a canonical byte string verifies against a
 * public key pinned inside the application bundle.
 *
 * Every check here fails closed: any doubt returns a rejection reason and the
 * caller must act as if there were no update information at all. There is
 * deliberately no bypass switch, and no "warn but continue" path.
 *
 * This file is shared by the Electron main process, the release tooling under
 * scripts/, and the test suites, so all three agree byte-for-byte on what is
 * signed. It is CommonJS because the Electron main process is.
 */
const {createHash, createPublicKey, verify: cryptoVerify, timingSafeEqual} = require('node:crypto');
const {createReadStream, statSync} = require('node:fs');

/**
 * Domain separation. Signatures produced for this context can never be replayed
 * as a signature for some other structure that happens to canonicalize the same.
 */
const SIGNING_CONTEXT = 'incheon-academy-union-os/release-manifest/v1\n';
const SIGNATURE_ALGORITHM = 'ed25519';
const SUPPORTED_SCHEMA = 2;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const VERSION_PATTERN = /^\d+(\.\d+){0,3}$/;
const KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;

/**
 * Public keys that exist only so the signing path can be exercised. They are
 * derived from a published seed, so anyone can sign with them. They are listed
 * here by VALUE rather than by label: a release must not become approvable by
 * editing an `environment` field next to a key everybody can reproduce.
 */
const DEVELOPMENT_PUBLIC_KEYS = Object.freeze([
  '_CVyQ-v3SRImFLiUr1-URtQ_9SkpyDmJkGFfYhkgRw0'
]);

/**
 * Canonical JSON.
 *
 * A signature over "the manifest" is meaningless unless signer and verifier
 * agree on the exact bytes. Key order, whitespace and float formatting all vary
 * between serializers, so the signed form is defined here rather than inherited
 * from whatever JSON.stringify happens to do at the call site:
 *
 *  - object keys are emitted in ascending UTF-16 code-unit order
 *  - no insignificant whitespace
 *  - arrays keep their order (order is meaningful and therefore signed)
 *  - only JSON types are allowed; undefined, functions and symbols are rejected
 *  - numbers must be finite integers, so no float formatting ambiguity exists
 *  - the result is encoded UTF-8
 */
function canonicalize(value, path = '$') {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`CANONICAL_NUMBER_NOT_FINITE at ${path}`);
    if (!Number.isInteger(value)) throw new Error(`CANONICAL_NUMBER_NOT_INTEGER at ${path}`);
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => canonicalize(item, `${path}[${index}]`)).join(',')}]`;
  }
  if (typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      throw new Error(`CANONICAL_UNSUPPORTED_OBJECT at ${path}`);
    }
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      const child = value[key];
      if (child === undefined) throw new Error(`CANONICAL_UNDEFINED at ${path}.${key}`);
      parts.push(`${JSON.stringify(key)}:${canonicalize(child, `${path}.${key}`)}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new Error(`CANONICAL_UNSUPPORTED_TYPE at ${path}`);
}

/** The exact bytes a release signature covers. */
function signingBytes(payload) {
  return Buffer.from(SIGNING_CONTEXT + canonicalize(payload), 'utf8');
}

function publicKeyFrom(base64url) {
  return createPublicKey({key: {kty: 'OKP', crv: 'Ed25519', x: base64url}, format: 'jwk'});
}

/** Compare dotted numeric versions. Returns -1, 0 or 1. */
function compareVersions(left, right) {
  const a = String(left).split('.').map(part => Number.parseInt(part, 10) || 0);
  const b = String(right).split('.').map(part => Number.parseInt(part, 10) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

const reject = reason => ({ok: false, reason});

/** Structural validation of the signed payload before anything is believed. */
function validatePayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return reject('PAYLOAD_INVALID');
  if (payload.schemaVersion !== SUPPORTED_SCHEMA) return reject('PAYLOAD_SCHEMA_UNSUPPORTED');
  if (typeof payload.productId !== 'string' || !payload.productId) return reject('PAYLOAD_PRODUCT_ID_INVALID');
  if (typeof payload.releaseId !== 'string' || !/^[A-Za-z0-9._:@-]{1,128}$/.test(payload.releaseId)) {
    return reject('PAYLOAD_RELEASE_ID_INVALID');
  }
  if (typeof payload.version !== 'string' || !VERSION_PATTERN.test(payload.version)) {
    return reject('PAYLOAD_VERSION_INVALID');
  }
  // A monotonic revision separates a legitimate re-publish of the same version
  // from a replayed or swapped one. Without it the only way to correct a
  // release would be indistinguishable from an attack.
  if (!Number.isInteger(payload.revision) || payload.revision < 1) return reject('PAYLOAD_REVISION_INVALID');
  if (payload.expiresAt !== undefined) {
    const expiresAt = Date.parse(payload.expiresAt);
    if (typeof payload.expiresAt !== 'string' || !Number.isFinite(expiresAt)) return reject('PAYLOAD_EXPIRES_AT_INVALID');
  }
  if (typeof payload.minimumSupportedVersion !== 'string' || !VERSION_PATTERN.test(payload.minimumSupportedVersion)) {
    return reject('PAYLOAD_MINIMUM_VERSION_INVALID');
  }
  if (compareVersions(payload.minimumSupportedVersion, payload.version) > 0) {
    return reject('PAYLOAD_MINIMUM_VERSION_ABOVE_RELEASE');
  }
  const publishedAt = Date.parse(payload.publishedAt);
  if (typeof payload.publishedAt !== 'string' || !Number.isFinite(publishedAt)) {
    return reject('PAYLOAD_PUBLISHED_AT_INVALID');
  }
  if (!Array.isArray(payload.artifacts) || payload.artifacts.length === 0) return reject('PAYLOAD_ARTIFACTS_INVALID');
  const seen = new Set();
  for (const artifact of payload.artifacts) {
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) return reject('ARTIFACT_INVALID');
    const {platform, channel, arch, url, sha256, sizeBytes} = artifact;
    for (const [field, value] of [['platform', platform], ['channel', channel], ['arch', arch]]) {
      if (typeof value !== 'string' || !/^[a-z0-9_-]{1,32}$/.test(value)) return reject(`ARTIFACT_${field.toUpperCase()}_INVALID`);
    }
    const key = `${platform}/${channel}/${arch}`;
    if (seen.has(key)) return reject('ARTIFACT_DUPLICATE');
    seen.add(key);
    if (typeof sha256 !== 'string' || !SHA256_PATTERN.test(sha256)) return reject('ARTIFACT_SHA256_INVALID');
    if (!Number.isInteger(sizeBytes) || sizeBytes <= 0) return reject('ARTIFACT_SIZE_INVALID');
    if (typeof url !== 'string') return reject('ARTIFACT_URL_INVALID');
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return reject('ARTIFACT_URL_INVALID');
    }
    // Installers may only ever be fetched over TLS, and a URL carrying
    // credentials is never a legitimate release location.
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) return reject('ARTIFACT_URL_NOT_HTTPS');
  }
  return {ok: true};
}

/**
 * Verify a fetched manifest.
 *
 * `trustedKeys` is the pinned key set shipped inside the application bundle.
 * Nothing outside that set can produce an acceptable manifest, and a manifest
 * naming a keyId that is not pinned is rejected rather than looked up anywhere.
 */
function verifyManifest(manifest, options = {}) {
  const {trustedKeys, expectedProductId, requireProductionKey = false} = options;
  if (!Array.isArray(trustedKeys) || trustedKeys.length === 0) return reject('NO_TRUSTED_KEYS');
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return reject('MANIFEST_INVALID');

  const signature = manifest.signature;
  if (!signature || typeof signature !== 'object' || Array.isArray(signature)) return reject('SIGNATURE_MISSING');
  if (signature.algorithm !== SIGNATURE_ALGORITHM) return reject('SIGNATURE_ALGORITHM_UNSUPPORTED');
  if (typeof signature.keyId !== 'string' || !KEY_ID_PATTERN.test(signature.keyId)) return reject('SIGNATURE_KEY_ID_INVALID');
  if (typeof signature.value !== 'string' || signature.value.length === 0) return reject('SIGNATURE_VALUE_INVALID');

  const key = trustedKeys.find(candidate => candidate && candidate.keyId === signature.keyId);
  if (!key) return reject('SIGNATURE_KEY_NOT_TRUSTED');
  if (key.algorithm !== SIGNATURE_ALGORITHM) return reject('SIGNATURE_ALGORITHM_UNSUPPORTED');
  if (requireProductionKey) {
    if (key.environment !== 'production') return reject('KEY_NOT_PRODUCTION');
    // Checked after the label so a mislabelled development key is still caught.
    if (DEVELOPMENT_PUBLIC_KEYS.includes(key.publicKey)) return reject('KEY_IS_DEVELOPMENT_KEY');
  }

  const payload = manifest.signed;
  let bytes;
  try {
    bytes = signingBytes(payload);
  } catch {
    return reject('PAYLOAD_NOT_CANONICALIZABLE');
  }

  let signatureBytes;
  try {
    signatureBytes = Buffer.from(signature.value, 'base64');
    // Ed25519 signatures are exactly 64 bytes; base64 silently tolerates junk,
    // so the round trip is checked rather than assumed.
    if (signatureBytes.length !== 64) return reject('SIGNATURE_VALUE_INVALID');
  } catch {
    return reject('SIGNATURE_VALUE_INVALID');
  }

  let publicKey;
  try {
    publicKey = publicKeyFrom(key.publicKey);
  } catch {
    return reject('TRUSTED_KEY_INVALID');
  }

  let verified = false;
  try {
    verified = cryptoVerify(null, bytes, publicKey, signatureBytes);
  } catch {
    return reject('SIGNATURE_INVALID');
  }
  if (!verified) return reject('SIGNATURE_INVALID');

  const structure = validatePayload(payload);
  if (!structure.ok) return structure;

  if (expectedProductId && payload.productId !== expectedProductId) return reject('PRODUCT_ID_MISMATCH');

  return {ok: true, release: payload, keyId: key.keyId, environment: key.environment ?? 'unknown'};
}

/**
 * Decide whether a verified release may be offered to this installation.
 *
 * Separated from signature verification so replay and downgrade handling is
 * explicit and independently testable. `lastAccepted` is the highest release
 * this installation has already seen, persisted by the caller.
 */
function evaluateRelease(release, options = {}) {
  const {
    currentVersion, lastAccepted, now = Date.now(),
    clockSkewMs = 24 * 60 * 60 * 1000,
    maxAgeMs = null
  } = options;
  if (typeof currentVersion !== 'string' || !VERSION_PATTERN.test(currentVersion)) return reject('CURRENT_VERSION_INVALID');

  const publishedAt = Date.parse(release.publishedAt);
  if (publishedAt > now + clockSkewMs) return reject('PUBLISHED_AT_IN_FUTURE');

  // Freshness. A signature never expires on its own, so a manifest that is
  // simply old is still perfectly valid cryptographically. An explicit signed
  // expiry, or a caller-supplied maximum age, is what bounds that.
  if (release.expiresAt !== undefined) {
    const expiresAt = Date.parse(release.expiresAt);
    // An expiry that cannot be read is not an absent expiry.
    if (!Number.isFinite(expiresAt) || expiresAt < now) return reject('MANIFEST_EXPIRED');
  }
  if (Number.isFinite(maxAgeMs) && maxAgeMs !== null && now - publishedAt > maxAgeMs) return reject('MANIFEST_STALE');

  if (lastAccepted && typeof lastAccepted === 'object') {
    const seenAt = Date.parse(lastAccepted.publishedAt);
    if (Number.isFinite(seenAt) && publishedAt < seenAt) return reject('REPLAYED_OLDER_MANIFEST');

    const knownVersion = typeof lastAccepted.version === 'string' && VERSION_PATTERN.test(lastAccepted.version);
    if (knownVersion && compareVersions(release.version, lastAccepted.version) < 0) return reject('VERSION_ROLLED_BACK');

    // Same version: the only legitimate way its contents may differ from what
    // was accepted before is a strictly higher revision. A different releaseId,
    // a different URL or a different digest at the same revision is a swap,
    // whoever signed it.
    if (knownVersion && compareVersions(release.version, lastAccepted.version) === 0) {
      const seenRevision = Number.isInteger(lastAccepted.revision) ? lastAccepted.revision : 0;
      if (release.revision < seenRevision) return reject('REVISION_ROLLED_BACK');
      if (release.revision === seenRevision
        && typeof lastAccepted.payloadDigest === 'string'
        && lastAccepted.payloadDigest !== payloadDigest(release)) {
        return reject('VERSION_CONTENT_CHANGED');
      }
    }
  }

  const supported = compareVersions(currentVersion, release.minimumSupportedVersion) >= 0;
  const updateAvailable = compareVersions(release.version, currentVersion) > 0;
  return {ok: true, updateAvailable, supported, release};
}

/** Stable identity of a signed payload, used for replay bookkeeping. */
function payloadDigest(payload) {
  return createHash('sha256').update(signingBytes(payload)).digest('hex');
}

/** What the caller should persist after accepting a manifest. */
function acceptanceRecord(release) {
  return {
    releaseId: release.releaseId,
    version: release.version,
    revision: release.revision,
    publishedAt: release.publishedAt,
    payloadDigest: payloadDigest(release)
  };
}

function selectArtifact(release, {platform, channel, arch}) {
  return release.artifacts.find(artifact => artifact.platform === platform
    && artifact.channel === channel && (!arch || artifact.arch === arch)) ?? null;
}

function sha256File(path) {
  return new Promise((resolve, reject2) => {
    const hash = createHash('sha256');
    const stream = createReadStream(path);
    stream.on('error', reject2);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Verify a downloaded installer against the signed manifest entry.
 *
 * A signature over the manifest only proves the manifest; it says nothing about
 * the bytes actually on disk. Size and digest are both checked, and the digest
 * comparison is constant-time so it cannot be probed byte by byte.
 */
async function verifyArtifactFile(path, artifact) {
  if (!artifact || typeof artifact.sha256 !== 'string' || !SHA256_PATTERN.test(artifact.sha256)) {
    return reject('ARTIFACT_SHA256_INVALID');
  }
  // Size is part of the signed entry, so it is part of the contract here. The
  // previous version documented a size check it did not perform.
  if (!Number.isInteger(artifact.sizeBytes) || artifact.sizeBytes <= 0) return reject('ARTIFACT_SIZE_INVALID');
  let size;
  try {
    size = statSync(path).size;
  } catch {
    return reject('ARTIFACT_FILE_UNREADABLE');
  }
  if (size !== artifact.sizeBytes) return reject('ARTIFACT_SIZE_MISMATCH');
  let actual;
  try {
    actual = await sha256File(path);
  } catch {
    return reject('ARTIFACT_FILE_UNREADABLE');
  }
  const expectedBuffer = Buffer.from(artifact.sha256, 'hex');
  const actualBuffer = Buffer.from(actual, 'hex');
  if (expectedBuffer.length !== actualBuffer.length || !timingSafeEqual(expectedBuffer, actualBuffer)) {
    return reject('ARTIFACT_SHA256_MISMATCH');
  }
  return {ok: true, sha256: actual};
}

module.exports = {
  SIGNING_CONTEXT,
  DEVELOPMENT_PUBLIC_KEYS,
  SIGNATURE_ALGORITHM,
  SUPPORTED_SCHEMA,
  canonicalize,
  signingBytes,
  compareVersions,
  validatePayload,
  verifyManifest,
  evaluateRelease,
  payloadDigest,
  acceptanceRecord,
  selectArtifact,
  sha256File,
  verifyArtifactFile
};
