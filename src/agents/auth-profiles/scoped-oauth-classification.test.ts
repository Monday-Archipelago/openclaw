import { describe, expect, it } from "vitest";
import { fingerprintAuthProfileCredential } from "../execution-auth-binding.js";
import { createOAuthRefreshFence } from "./oauth-refresh-marker.js";
import { coercePersistedAuthProfileStore } from "./persisted-store.js";
import { recoverScopedOAuthAuthFlow } from "./scoped-oauth-classification.js";
import {
  createScopedOAuthDelegation,
  listScopedOAuthCandidates,
  resolveScopedOAuthAccess,
  resolveScopedOAuthBindingProof,
} from "./scoped-oauth-delegation.js";
import { summarizeScopedOAuthRows } from "./scoped-oauth-diagnostic.js";
import type { OAuthCredential } from "./types.js";

const profileId = "openai:synthetic-migrated";
const selection = { profileId, provider: "openai" };

function row(overrides: Partial<OAuthCredential> = {}): OAuthCredential {
  return {
    type: "oauth",
    provider: "openai",
    access: "synthetic-access",
    refresh: "synthetic-refresh",
    idToken: "synthetic-id",
    expires: Date.now() + 60_000,
    issuer: "https://auth.openai.com",
    tokenEndpoint: "https://auth.openai.com/api/accounts/oauth/token",
    clientId: "synthetic-registered-client",
    accountId: "synthetic-grant-identity",
    grantedScope: "openid resource.invoke chatgpt.tokens.use.direct",
    ...overrides,
  };
}

describe("scoped OAuth migrated-flow classification", () => {
  it.each(["chatgpt.tokens.use.direct", "chatpass.enable.request.direct"])(
    "recovers a missing flow from a recorded sharing grant (%s) without mutating the row",
    (directScope) => {
      const raw = row({ grantedScope: `openid resource.invoke ${directScope}` });
      const canonical = coercePersistedAuthProfileStore({
        version: 1,
        profiles: { [profileId]: raw },
      })!.profiles[profileId];
      if (canonical.type !== "oauth") {
        throw new Error("expected synthetic OAuth row");
      }
      const before = structuredClone(canonical);
      const recoveredAuthFlow = recoverScopedOAuthAuthFlow(canonical);
      expect(recoveredAuthFlow).toBe("chatgpt-token-sharing");
      const scope = createScopedOAuthDelegation([
        { ...selection, credential: canonical, assertCurrent: () => "current" },
      ]);
      expect(listScopedOAuthCandidates(scope)).toEqual([
        { ...selection, authFlow: "chatgpt-token-sharing" },
      ]);
      const projection = resolveScopedOAuthAccess(scope, selection);
      expect(projection.authFlow).toBe("chatgpt-token-sharing");
      expect(projection.accountId).toBeUndefined();
      expect(projection.access === canonical.access).toBe(true);
      expect("refresh" in projection).toBe(false);
      expect("idToken" in projection).toBe(false);
      expect(resolveScopedOAuthBindingProof(scope, selection)).toBe(
        fingerprintAuthProfileCredential({ profileId, credential: canonical }),
      );
      expect(canonical).toEqual(before);
      expect(canonical.authFlow).toBeUndefined();
      expect(() => resolveScopedOAuthAccess(scope, { ...selection, forceRefresh: true })).toThrow(
        expect.objectContaining({ reason: "force-refresh" }),
      );
      expect(summarizeScopedOAuthRows({ [profileId]: canonical })).toMatchObject({
        openAiMissingFlowRows: 1,
        matchingFlowRows: 0,
        recoveredFlowRows: 1,
      });
    },
  );

  it.each<Partial<OAuthCredential>>([
    { provider: "another-provider" },
    { authFlow: "chatgpt-identity" },
    { authFlow: "native" },
    { grantedScope: undefined, authorizationScope: "resource.invoke chatgpt.tokens.use.direct" },
    { grantedScope: "openid resource.invoke" },
    { grantedScope: "openid chatgpt.tokens.use.direct" },
    { issuer: undefined },
    { tokenEndpoint: "https://example.invalid/token" },
    { clientId: "dynamic_agent_client" },
    { accountId: undefined },
    { issuer: undefined, clientId: undefined, tokenEndpoint: undefined, grantedScope: undefined },
  ])("does not infer sharing from an unrelated or incomplete row %#", (overrides) => {
    expect(recoverScopedOAuthAuthFlow(row(overrides))).toBeUndefined();
  });

  it("retains fail-closed fencing and expiry for recovered candidates", () => {
    for (const [credential, reason] of [
      [createOAuthRefreshFence({ profileId, credential: row() }), "fenced"],
      [row({ expires: Date.now() - 1 }), "expired"],
    ] as const) {
      const recoveredAuthFlow = recoverScopedOAuthAuthFlow(credential);
      expect(recoveredAuthFlow).toBe("chatgpt-token-sharing");
      const scope = createScopedOAuthDelegation([
        { ...selection, credential, assertCurrent: () => "current" },
      ]);
      expect(listScopedOAuthCandidates(scope)).toHaveLength(1);
      expect(() => resolveScopedOAuthAccess(scope, selection)).toThrow(
        expect.objectContaining({ reason }),
      );
    }
  });
});
