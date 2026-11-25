import { fingerprintAuthProfileCredential } from "../execution-auth-binding.js";
import { resolveTokenExpiryState } from "./credential-state.js";
import { isOAuthRefreshFence } from "./oauth-refresh-marker.js";
import type { OAuthCredential } from "./types.js";

export type ScopedOAuthDelegationReason =
  | "missing"
  | "unusable"
  | "expired"
  | "fenced"
  | "stale"
  | "key-domain-mismatch"
  | "force-refresh";

export class ScopedOAuthDelegationError extends Error {
  readonly code = "SCOPED_OAUTH_DELEGATION" as const;

  constructor(readonly reason: ScopedOAuthDelegationReason) {
    super(
      "Gateway-owned OAuth delegation is unavailable; refresh the sign-in through its owner or retry. No credential was changed.",
    );
    this.name = "ScopedOAuthDelegationError";
  }
}

/** Trusted scope owner supplies a retained, synchronous, read-only assertion.
 * It must check the exact live Gateway and captured credential generation/fence.
 * No store reader/writer or credential may be returned through this interface.
 */
export type ScopedOAuthAuthorityAssertion = () =>
  | "current"
  | "stale"
  | "fenced"
  | "key-domain-mismatch";

/** Separate from persisted credentials; the access secret is not an enumerable field. */
class ScopedOAuthAccessProjection {
  readonly mode = "oauth" as const;
  readonly #access: string;

  constructor(
    readonly profileId: string,
    readonly provider: string,
    access: string,
    readonly expires: number,
    readonly authFlow: string | undefined,
    readonly accountId: string | undefined,
    readonly authFingerprint: string,
  ) {
    this.#access = access;
    Object.freeze(this);
  }

  get access(): string {
    return this.#access;
  }
}

export type { ScopedOAuthAccessProjection };

const scopeBrand: unique symbol = Symbol("scoped-oauth-delegation");

/** Opaque, process-local runtime capability. Serialization cannot preserve it. */
export type ScopedOAuthDelegation = { readonly [scopeBrand]: true };

type Candidate =
  | { reason: ScopedOAuthDelegationReason; provider: string }
  | {
      projection: ScopedOAuthAccessProjection;
      assertCurrent: ScopedOAuthAuthorityAssertion;
      provider: string;
    };

const scopes = new WeakMap<ScopedOAuthDelegation, ReadonlyMap<string, Candidate>>();

function assertAuthority(assertCurrent: ScopedOAuthAuthorityAssertion): void {
  let status: ReturnType<ScopedOAuthAuthorityAssertion>;
  try {
    status = assertCurrent();
  } catch {
    // Never propagate a store/owner diagnostic, which could contain secrets.
    throw new ScopedOAuthDelegationError("stale");
  }
  switch (status) {
    case "current":
      return;
    case "fenced":
    case "key-domain-mismatch":
      throw new ScopedOAuthDelegationError(status);
    default:
      throw new ScopedOAuthDelegationError("stale");
  }
}

function assertExpiry(expires: number): void {
  const state = resolveTokenExpiryState(expires);
  if (state !== "valid") {
    throw new ScopedOAuthDelegationError(state === "expired" ? "expired" : "unusable");
  }
}

/** Admit canonical OAuth rows in the binding consumer's process/key domain.
 * Rejected rows retain only a non-secret candidate marker and denial reason.
 * The caller must not capture the canonical row or a writable handle in its assertion.
 */
export function createScopedOAuthDelegation(
  candidates: readonly {
    profileId: string;
    provider: string;
    credential?: OAuthCredential & { setup?: unknown };
    assertCurrent: ScopedOAuthAuthorityAssertion;
  }[],
): ScopedOAuthDelegation {
  const entries = new Map<string, Candidate>();
  for (const { profileId, provider, credential, assertCurrent } of candidates) {
    if (entries.has(profileId)) {
      entries.set(profileId, { provider, reason: "unusable" });
      continue;
    }
    try {
      assertAuthority(assertCurrent);
      if (!credential) {
        throw new ScopedOAuthDelegationError("missing");
      }
      if (credential.type !== "oauth" || credential.provider !== provider || credential.setup) {
        throw new ScopedOAuthDelegationError("unusable");
      }
      if (isOAuthRefreshFence(credential)) {
        throw new ScopedOAuthDelegationError("fenced");
      }
      if (typeof credential.access !== "string" || !credential.access.trim()) {
        throw new ScopedOAuthDelegationError("unusable");
      }
      assertExpiry(credential.expires);
      const proof = fingerprintAuthProfileCredential({ profileId, credential });
      if (!proof) {
        throw new ScopedOAuthDelegationError("unusable");
      }
      const projection = new ScopedOAuthAccessProjection(
        profileId,
        provider,
        credential.access,
        credential.expires,
        credential.authFlow,
        credential.accountId,
        proof,
      );
      entries.set(profileId, { provider, projection, assertCurrent });
    } catch (error) {
      entries.set(profileId, {
        provider,
        reason: error instanceof ScopedOAuthDelegationError ? error.reason : "unusable",
      });
    }
  }
  const scope: ScopedOAuthDelegation = Object.freeze({ [scopeBrand]: true as const });
  scopes.set(scope, entries);
  return scope;
}

function readScope(scope: ScopedOAuthDelegation): ReadonlyMap<string, Candidate> {
  const entries = scopes.get(scope);
  if (!entries) {
    throw new ScopedOAuthDelegationError("key-domain-mismatch");
  }
  return entries;
}

/** Check before the ordinary missing-profile branch; rejected candidates still match. */
export function hasScopedOAuthCandidate(scope: ScopedOAuthDelegation, profileId: string): boolean {
  return readScope(scope).has(profileId);
}

function requireCurrentProjection(
  scope: ScopedOAuthDelegation,
  selection: { profileId: string; provider: string; forceRefresh?: boolean },
): ScopedOAuthAccessProjection {
  const candidate = readScope(scope).get(selection.profileId);
  if (!candidate || candidate.provider !== selection.provider) {
    throw new ScopedOAuthDelegationError("missing");
  }
  if ("reason" in candidate) {
    throw new ScopedOAuthDelegationError(candidate.reason);
  }
  // Check the retained authority even on a forced-refresh/auth-error retry.
  assertAuthority(candidate.assertCurrent);
  assertExpiry(candidate.projection.expires);
  if (selection.forceRefresh) {
    throw new ScopedOAuthDelegationError("force-refresh");
  }
  return candidate.projection;
}

/** Call at every credential handoff. An already dispatched request cannot be revoked. */
export function resolveScopedOAuthAccess(
  scope: ScopedOAuthDelegation,
  selection: { profileId: string; provider: string; forceRefresh?: boolean },
): ScopedOAuthAccessProjection {
  return requireCurrentProjection(scope, selection);
}

/** Revalidate at successful-run binding, without a durable OAuth row or ID token. */
export function resolveScopedOAuthBindingProof(
  scope: ScopedOAuthDelegation,
  selection: { profileId: string; provider: string },
): string {
  return requireCurrentProjection(scope, selection).authFingerprint;
}
