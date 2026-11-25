import { describe, expect, it, vi } from "vitest";
import { authProfileRuntimeMode } from "../../auth-profiles/runtime-scope.js";
import {
  closeScopedOAuthDelegation,
  createScopedOAuthDelegation,
  resolveScopedOAuthBindingProof,
} from "../../auth-profiles/scoped-oauth-delegation.js";
import type { OAuthCredential } from "../../auth-profiles/types.js";
import { reportEmbeddedRunSuccessfulAuthBinding } from "./auth-profile-success.js";

describe("delegated successful-run binding", () => {
  it("uses the same-process proof only for the actual resolved credential", () => {
    const selection = { profileId: "openai:delegated", provider: "openai" };
    const credential: OAuthCredential = {
      type: "oauth",
      provider: "openai",
      access: "synthetic-access",
      refresh: "synthetic-refresh",
      expires: Date.now() + 60_000,
      authFlow: "chatgpt-token-sharing",
    };
    let current = true;
    const scope = createScopedOAuthDelegation([{
      ...selection,
      credential,
      assertCurrent: () => current ? "current" : "stale",
    }]);
    const proof = resolveScopedOAuthBindingProof(scope, selection);
    const onSuccessfulAuthBinding = vi.fn();
    const input: Parameters<typeof reportEmbeddedRunSuccessfulAuthBinding>[0] = {
      ...selection,
      profileStore: { version: 1, profiles: {} },
      apiKeyInfo: {
        profileId: selection.profileId,
        mode: "oauth",
        authFlow: credential.authFlow,
        source: "profile:openai:delegated",
        apiKey: credential.access,
      },
      attempt: {} as Parameters<typeof reportEmbeddedRunSuccessfulAuthBinding>[0]["attempt"],
      modelId: "synthetic-model",
      modelApi: "openai-responses",
      agentHarnessId: "synthetic-harness",
      pluginHarnessOwnsTransport: false,
      pluginHarnessOwnsAuthBootstrap: false,
      onSuccessfulAuthBinding,
    };
    try {
      authProfileRuntimeMode.run({
        kind: "agent-dir", agentDir: "/synthetic", env: {}, oauthDelegation: scope,
      }, () => {
        reportEmbeddedRunSuccessfulAuthBinding(input);
        expect(onSuccessfulAuthBinding).toHaveBeenCalledWith(expect.objectContaining({
          authProfileId: selection.profileId,
          authFingerprint: proof,
        }));
        expect(() => reportEmbeddedRunSuccessfulAuthBinding({
          ...input, apiKeyInfo: { ...input.apiKeyInfo!, apiKey: "wrong" },
        })).toThrow(expect.objectContaining({ reason: "key-domain-mismatch" }));
        reportEmbeddedRunSuccessfulAuthBinding({
          ...input, apiKeyInfo: null, pluginHarnessOwnsTransport: true,
          attempt: { ...input.attempt, authBindingFingerprint: proof },
        });
        expect(onSuccessfulAuthBinding).toHaveBeenCalledTimes(2);
        current = false;
        expect(() => reportEmbeddedRunSuccessfulAuthBinding(input)).toThrow(
          expect.objectContaining({ reason: "stale" }),
        );
        expect(onSuccessfulAuthBinding).toHaveBeenCalledTimes(2);
      });
    } finally {
      closeScopedOAuthDelegation(scope);
    }
  });
});
