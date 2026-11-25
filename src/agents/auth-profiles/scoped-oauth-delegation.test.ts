import { afterEach, describe, expect, it, vi } from "vitest";
import { fingerprintAuthProfileCredential } from "../execution-auth-binding.js";
import { createFailedOAuthRefreshFence, createOAuthRefreshFence } from "./oauth-refresh-marker.js";
import {
  createScopedOAuthDelegation,
  hasScopedOAuthCandidate,
  resolveScopedOAuthAccess,
  resolveScopedOAuthBindingProof,
  ScopedOAuthDelegationError,
  type ScopedOAuthAuthorityAssertion,
  type ScopedOAuthDelegation,
  type ScopedOAuthDelegationReason,
} from "./scoped-oauth-delegation.js";
import type { OAuthCredential } from "./types.js";

const selection = { profileId: "test:delegated", provider: "test-provider" };
const now = 1_800_000_000_000;

function credential(overrides: Partial<OAuthCredential> = {}): OAuthCredential {
  return {
    type: "oauth",
    provider: selection.provider,
    access: "synthetic-access",
    refresh: "synthetic-refresh",
    idToken: "synthetic-id",
    expires: now + 1,
    authFlow: "chatgpt-token-sharing",
    accountId: "test-account",
    ...overrides,
  };
}

function scopeFor(
  row: OAuthCredential | undefined,
  assertCurrent: ScopedOAuthAuthorityAssertion = () => "current",
) {
  vi.spyOn(Date, "now").mockReturnValue(now);
  return createScopedOAuthDelegation([{ ...selection, credential: row, assertCurrent }]);
}

function expectDenial(run: () => unknown, reason: ScopedOAuthDelegationReason) {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(ScopedOAuthDelegationError);
  expect(caught).toMatchObject({ code: "SCOPED_OAUTH_DELEGATION", reason });
}

afterEach(() => vi.restoreAllMocks());

describe("scoped OAuth delegation", () => {
  it("projects only access and routing semantics, with the existing keyed binding proof", () => {
    const row = credential();
    const scope = scopeFor(row);
    const projection = resolveScopedOAuthAccess(scope, selection);
    expect(projection.access).toBe(row.access);
    expect(projection).toMatchObject({
      ...selection,
      mode: "oauth",
      expires: row.expires,
      authFlow: row.authFlow,
      accountId: row.accountId,
    });
    for (const field of ["refresh", "idToken", "authorizationCode", "readCurrentCredential", "type"]) {
      expect(field in projection).toBe(false);
    }
    expect(Object.isFrozen(projection)).toBe(true);
    const serialized = JSON.stringify([scope, projection]);
    for (const material of [row.access, row.refresh, row.idToken]) {
      expect(serialized.includes(material!)).toBe(false);
    }
    expect(resolveScopedOAuthBindingProof(scope, selection)).toBe(
      fingerprintAuthProfileCredential({ profileId: selection.profileId, credential: row }),
    );
    // Projection is independent of later mutation of the caller's canonical object.
    row.access = "synthetic-replacement";
    expect(resolveScopedOAuthAccess(scope, selection).access === row.access).toBe(false);
  });

  it("keeps markers for absent or unusable projections and never falls through", () => {
    for (const [row, reason] of [
      [undefined, "missing"],
      [credential({ access: " " }), "unusable"],
      [credential({ expires: NaN }), "unusable"],
      [credential({ expires: now }), "expired"],
    ] as const) {
      const scope = scopeFor(row);
      expect(hasScopedOAuthCandidate(scope, selection.profileId)).toBe(true);
      expectDenial(() => resolveScopedOAuthAccess(scope, selection), reason);
    }
    const scope = scopeFor(credential());
    expect(hasScopedOAuthCandidate(scope, "ordinary-static")).toBe(false);
    expectDenial(() => resolveScopedOAuthAccess(scope, { ...selection, provider: "other" }), "missing");
  });

  it("rejects both pending and failed durable refresh fences", () => {
    const pending = createOAuthRefreshFence({ profileId: selection.profileId, credential: credential() });
    for (const row of [pending, createFailedOAuthRefreshFence(pending)]) {
      const scope = scopeFor(row);
      expect(hasScopedOAuthCandidate(scope, selection.profileId)).toBe(true);
      expectDenial(() => resolveScopedOAuthAccess(scope, selection), "fenced");
    }
  });

  it.each(["stale", "fenced", "key-domain-mismatch"] as const)(
    "revalidates authority on every handoff and successful binding: %s",
    (denial) => {
      let status: ReturnType<ScopedOAuthAuthorityAssertion> = "current";
      const assertCurrent = vi.fn(() => status);
      const scope = scopeFor(credential(), assertCurrent);
      resolveScopedOAuthAccess(scope, selection);
      expect(assertCurrent).toHaveBeenCalledTimes(2);
      status = denial;
      expectDenial(() => resolveScopedOAuthAccess(scope, selection), denial);
      expectDenial(() => resolveScopedOAuthBindingProof(scope, selection), denial);
      expectDenial(() => resolveScopedOAuthAccess(scope, { ...selection, forceRefresh: true }), denial);
      expect(assertCurrent).toHaveBeenCalledTimes(5);
    },
  );

  it("uses actual expiry, refuses forced refresh and checks authority on retry", () => {
    const assertion = vi.fn(() => "current" as const);
    const scope = scopeFor(credential(), assertion);
    resolveScopedOAuthAccess(scope, selection);
    expectDenial(() => resolveScopedOAuthAccess(scope, { ...selection, forceRefresh: true }), "force-refresh");
    expect(assertion).toHaveBeenCalledTimes(3);
    vi.mocked(Date.now).mockReturnValue(now + 1);
    expectDenial(() => resolveScopedOAuthAccess(scope, selection), "expired");
    expectDenial(() => resolveScopedOAuthBindingProof(scope, selection), "expired");
  });

  it("sanitizes owner exceptions and rejects foreign or serialized capabilities", () => {
    const scope = scopeFor(credential(), () => {
      throw new Error("synthetic-owner-diagnostic");
    });
    expectDenial(() => resolveScopedOAuthAccess(scope, selection), "stale");
    try {
      resolveScopedOAuthAccess(scope, selection);
    } catch (error) {
      expect(String(error)).not.toContain("synthetic-owner-diagnostic");
      expect((error as Error).cause).toBeUndefined();
    }
    const foreign = JSON.parse(JSON.stringify(scopeFor(credential()))) as ScopedOAuthDelegation;
    expectDenial(() => hasScopedOAuthCandidate(foreign, selection.profileId), "key-domain-mismatch");
  });

  it("retains rejected admission and rejects ambiguous duplicate profile IDs", () => {
    let status: ReturnType<ScopedOAuthAuthorityAssertion> = "stale";
    const rejected = scopeFor(credential(), () => status);
    status = "current";
    expectDenial(() => resolveScopedOAuthAccess(rejected, selection), "stale");
    const candidate = { ...selection, credential: credential(), assertCurrent: () => "current" as const };
    const duplicate = createScopedOAuthDelegation([candidate, candidate]);
    expectDenial(() => resolveScopedOAuthAccess(duplicate, selection), "unusable");
  });
});
